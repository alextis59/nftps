const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');

const { TcpStream } = require('./tcpStream.js');
const {
  CIPHER_SPECS,
  TLS_VERSION_1_2,
  SUPPORTED_CIPHER_SUITES,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
} = require('./constants.js');
const {
  computeFinishedVerifyData,
  deriveMasterSecret,
  deriveKeyBlock,
  buildPreMasterSecret,
  encryptPreMasterSecret,
} = require('./cryptoPrimitives.js');
const {
  buildClientHello,
  parseServerHello,
  parseCertificate,
  buildClientKeyExchange,
  buildClientCertificate,
  buildCertificateVerify,
  buildFinished,
  parseFinishedHandshake,
  parseCertificateRequest,
} = require('./handshakeMessages.js');
const {
  verifyServerCertificateChain,
  extractLegacyPublicServerCert,
  ensureClientAuthMaterial,
} = require('./certificates.js');
const {
  parseConnectionOptions,
  ensureServerName,
  ensureSocketConnected,
  ensureHostAndPort,
  defaultVerboseLogger,
  formatVerboseBuffer,
} = require('./options.js');
const { makeCipherStateFromKeyBlock } = require('./cipherState.js');
const { TlsRecordLayer } = require('./tlsRecordLayer.js');

class TlsClient {
  constructor(
    socket,
    hostname,
    {
      clientCertChain = [],
      clientPrivateKey,
      caCertificates,
      rejectUnauthorized = true,
      checkServerIdentity = tls.checkServerIdentity,
      cipherSuites,
      compressionMethods,
      extensions,
      minVersion = 'TLSv1.2',
      maxVersion = 'TLSv1.2',
      minVersionCode = TLS_VERSION_1_2,
      maxVersionCode = TLS_VERSION_1_2,
      verbose = false,
      log = defaultVerboseLogger,
    } = {},
  ) {
    this.socket = socket;
    this.hostname = hostname;
    this.clientCertChain = clientCertChain;
    this.clientPrivateKey = clientPrivateKey;
    this.caCertificates = caCertificates;
    this.rejectUnauthorized = rejectUnauthorized;
    this.checkServerIdentity = checkServerIdentity;
    this.cipherSuites = Array.isArray(cipherSuites) && cipherSuites.length > 0 ? [...cipherSuites] : [...SUPPORTED_CIPHER_SUITES];
    this.compressionMethods = Array.isArray(compressionMethods) ? [...compressionMethods] : [...DEFAULT_COMPRESSION_METHODS];
    this.extensions = extensions || {
      serverName: true,
      signatureAlgorithms: DEFAULT_SIGNATURE_ALGORITHMS.map(({ hash, signature }) => ({ hash, signature })),
      extra: [],
    };
    this.minVersion = minVersion;
    this.maxVersion = maxVersion;
    this.minVersionCode = minVersionCode;
    this.maxVersionCode = maxVersionCode;
    this.verbose = Boolean(verbose);
    this.log = typeof log === 'function' ? log : defaultVerboseLogger;
    this.authorized = false;
    this.authorizationError = null;

    this.tcp = new TcpStream(socket);
    this.recordLayer = new TlsRecordLayer(this.tcp);
    this.handshakeTranscript = [];
    this.handshakeBuffers = {
      plain: Buffer.alloc(0),
      encrypted: Buffer.alloc(0),
    };
    this.selectedCipherSuite = null;
    this.cipherSpec = null;
  }

  #verboseLog(message) {
    if (!this.verbose) {
      return;
    }

    this.log(`[tls-client:${this.hostname}] ${message}`);
  }

  static async connect({
    host,
    port,
    servername = host,
    clientCert,
    clientKey,
    ca,
    rejectUnauthorized = true,
    checkServerIdentity,
    cipherSuites,
    ciphers,
    minVersion,
    maxVersion,
    compressionMethods,
    extensions,
    verbose = false,
    log,
  }) {
    ensureHostAndPort(host, port);
    ensureServerName(servername);

    const options = parseConnectionOptions({
      servername,
      clientCert,
      clientKey,
      ca,
      rejectUnauthorized,
      checkServerIdentity,
      cipherSuites,
      ciphers,
      minVersion,
      maxVersion,
      compressionMethods,
      extensions,
    });
    ensureClientAuthMaterial(options.clientCertChain, options.clientPrivateKey);

    const socket = net.connect({ host, port });
    await once(socket, 'connect');
    const client = new TlsClient(socket, servername, {
      ...options,
      verbose,
      log,
    });
    try {
      await client.doHandshake();
      return client;
    } catch (err) {
      await client.close({ destroySocket: true, sendCloseNotify: false, detach: true }).catch(() => {});
      throw err;
    }
  }

  static async fromExistingSocket(
    socket,
    {
      servername = 'localhost',
      clientCert,
      clientKey,
      ca,
      rejectUnauthorized = true,
      checkServerIdentity,
      cipherSuites,
      ciphers,
      minVersion,
      maxVersion,
      compressionMethods,
      extensions,
      verbose = false,
      log,
    } = {},
  ) {
    ensureSocketConnected(socket);
    ensureServerName(servername);

    const options = parseConnectionOptions({
      servername,
      clientCert,
      clientKey,
      ca,
      rejectUnauthorized,
      checkServerIdentity,
      cipherSuites,
      ciphers,
      minVersion,
      maxVersion,
      compressionMethods,
      extensions,
    });
    ensureClientAuthMaterial(options.clientCertChain, options.clientPrivateKey);

    const client = new TlsClient(socket, servername, {
      ...options,
      verbose,
      log,
    });
    try {
      await client.doHandshake();
      return client;
    } catch (err) {
      await client.close({ destroySocket: true, sendCloseNotify: false, detach: true }).catch(() => {});
      throw err;
    }
  }

  async doHandshake() {
    this.#verboseLog('starting TLS 1.2 handshake');
    const { clientRandom, handshake: ch } = buildClientHello(
      this.hostname,
      this.cipherSuites,
      this.compressionMethods,
      this.extensions,
    );
    this.clientRandom = clientRandom;
    this.handshakeTranscript.push(ch);

    await this.recordLayer.writePlainRecord(0x16, ch);
    this.#verboseLog('sent ClientHello');

    let serverCertPem;
    let sawServerHello = false;
    let sawServerCert = false;
    let certRequest = null;
    let expectedServerHandshake = 'server_hello';

    while (true) {
      const msg = await this.readHandshakeMessage(false);

      if (msg.type === 0x02) {
        if (expectedServerHandshake !== 'server_hello') {
          throw new Error('Unexpected ServerHello ordering in handshake');
        }

        this.handshakeTranscript.push(msg.raw);
        const serverHello = parseServerHello(msg.body);
        this.serverRandom = serverHello.random;
        this.selectedCipherSuite = serverHello.cipherSuite;
        sawServerHello = true;
        expectedServerHandshake = 'certificate';
        this.#verboseLog(
          `received ServerHello version=0x${serverHello.version.toString(16)} cipher=0x${serverHello.cipherSuite.toString(16)}`,
        );

        if (serverHello.version < this.minVersionCode || serverHello.version > this.maxVersionCode) {
          throw new Error(
            `Server selected TLS version 0x${serverHello.version.toString(16)} outside configured range ${this.minVersion}-${this.maxVersion}`,
          );
        }
        if (serverHello.version !== TLS_VERSION_1_2) {
          throw new Error(`Unsupported TLS version 0x${serverHello.version.toString(16)}`);
        }
        if (!CIPHER_SPECS[serverHello.cipherSuite]) {
          throw new Error(`Server selected unsupported cipher suite 0x${serverHello.cipherSuite.toString(16)}`);
        }
        if (!this.cipherSuites.includes(serverHello.cipherSuite)) {
          throw new Error(`Server selected a cipher suite not offered by client: 0x${serverHello.cipherSuite.toString(16)}`);
        }
        if (serverHello.compression !== 0x00) {
          throw new Error('Server selected non-null compression');
        }
        continue;
      }

      if (msg.type === 0x0b) {
        if (expectedServerHandshake !== 'certificate') {
          throw new Error('Unexpected Certificate ordering in handshake');
        }

        this.handshakeTranscript.push(msg.raw);
        const chain = parseCertificate(msg.body);
        this.serverCertChain = chain;
        serverCertPem = extractLegacyPublicServerCert(chain);
        sawServerCert = true;
        expectedServerHandshake = 'certificate_request_or_done';
        this.#verboseLog(`received server certificate chain entries=${chain.length}`);
        continue;
      }

      if (msg.type === 0x0d) {
        if (expectedServerHandshake !== 'certificate_request_or_done' || certRequest) {
          throw new Error('Unexpected CertificateRequest ordering in handshake');
        }

        this.handshakeTranscript.push(msg.raw);
        certRequest = parseCertificateRequest(msg.body);
        expectedServerHandshake = 'server_hello_done';
        this.#verboseLog('server requested client certificate');
        continue;
      }

      if (msg.type === 0x0e) {
        if (expectedServerHandshake !== 'certificate_request_or_done' && expectedServerHandshake !== 'server_hello_done') {
          throw new Error('Unexpected ServerHelloDone ordering in handshake');
        }
        if (msg.body.length !== 0) {
          throw new Error('ServerHelloDone must have an empty body');
        }

        this.handshakeTranscript.push(msg.raw);
        break;
      }

      throw new Error(`Unexpected handshake message type 0x${msg.type.toString(16)}`);
    }

    if (!sawServerHello || !sawServerCert || !serverCertPem) {
      throw new Error('Incomplete server handshake messages');
    }

    if (this.rejectUnauthorized) {
      try {
        verifyServerCertificateChain({
          chainDer: this.serverCertChain,
          hostname: this.hostname,
          caCertificates: this.caCertificates,
          checkServerIdentity: this.checkServerIdentity,
        });
        this.authorized = true;
        this.authorizationError = null;
        this.#verboseLog('server certificate verification passed');
      } catch (err) {
        this.authorized = false;
        this.authorizationError = err;
        this.#verboseLog(`server certificate verification failed: ${err.message}`);
        throw err;
      }
    }

    this.preMasterSecret = buildPreMasterSecret();
    const encPms = encryptPreMasterSecret(this.preMasterSecret, serverCertPem);
    const ckx = buildClientKeyExchange(encPms);
    this.#verboseLog('prepared ClientKeyExchange');

    let sentClientCert = false;
    if (certRequest) {
      const supportsRsaCert = certRequest.certTypes.includes(1);
      const supportsRsaSha256 = certRequest.signatureAlgorithms.some(
        (alg) => alg.hash === 0x04 && alg.signature === 0x01,
      );

      if (!supportsRsaCert || !supportsRsaSha256) {
        throw new Error('Server CertificateRequest does not support RSA with SHA256');
      }

      if (this.clientCertChain.length === 0 || !this.clientPrivateKey) {
        throw new Error('Server requested client certificate but none configured');
      }

      const clientCertMsg = buildClientCertificate(this.clientCertChain);
      this.handshakeTranscript.push(clientCertMsg);
      await this.recordLayer.writePlainRecord(0x16, clientCertMsg);
      sentClientCert = true;
      this.#verboseLog(`sent client certificate chain entries=${this.clientCertChain.length}`);
    }

    this.handshakeTranscript.push(ckx);
    await this.recordLayer.writePlainRecord(0x16, ckx);
    this.#verboseLog('sent ClientKeyExchange');

    this.masterSecret = deriveMasterSecret(this.preMasterSecret, this.clientRandom, this.serverRandom);
    this.cipherSpec = CIPHER_SPECS[this.selectedCipherSuite];
    const keyLength = Number.isInteger(this.cipherSpec.keyLength) ? this.cipherSpec.keyLength : 16;
    const ivLength = Number.isInteger(this.cipherSpec.ivLength) ? this.cipherSpec.ivLength : 16;
    const keyBlockLength = this.cipherSpec.macKeyLength * 2 + keyLength * 2 + ivLength * 2;
    const keyBlock = deriveKeyBlock(this.masterSecret, this.serverRandom, this.clientRandom, keyBlockLength);
    const cipherState = makeCipherStateFromKeyBlock(keyBlock, this.cipherSpec);
    this.recordLayer.installCipher(cipherState);
    this.#verboseLog(
      `installed cipher suite=0x${this.selectedCipherSuite.toString(16)} cipher=${cipherState.cipherAlgorithm} mac=${this.cipherSpec.macAlgorithm}`,
    );

    if (sentClientCert) {
      const certVerify = buildCertificateVerify(this.clientPrivateKey, this.handshakeTranscript);
      this.handshakeTranscript.push(certVerify);
      await this.recordLayer.writePlainRecord(0x16, certVerify);
      this.#verboseLog('sent CertificateVerify');
    }
    await this.recordLayer.sendChangeCipherSpec();
    this.#verboseLog('sent ChangeCipherSpec');

    const transcriptBuf = Buffer.concat(this.handshakeTranscript);
    const finished = buildFinished(this.masterSecret, transcriptBuf, true);
    await this.recordLayer.writeEncryptedRecord(0x16, finished);
    this.handshakeTranscript.push(finished);
    this.#verboseLog('sent Finished');

    const ccs = await this.recordLayer.readPlainRecord();
    if (ccs.type === 0x15) {
      throw new Error(`TLS alert from server: ${ccs.fragment.toString('hex')}`);
    }
    if (ccs.type !== 0x14) {
      throw new Error(`Expected ChangeCipherSpec from server, got record type ${ccs.type}`);
    }
    if (ccs.fragment.length !== 1 || ccs.fragment.readUInt8(0) !== 0x01) {
      throw new Error('Malformed ChangeCipherSpec from server');
    }
    this.#verboseLog('received ChangeCipherSpec from server');

    const srvFinishedRecord = await this.readHandshakeMessage(true);
    if (srvFinishedRecord.type !== 0x14) {
      throw new Error('Expected Finished from server');
    }
    const srvFinished = parseFinishedHandshake(srvFinishedRecord.raw);

    const transcriptForServer = Buffer.concat(this.handshakeTranscript);
    const expected = computeFinishedVerifyData(this.masterSecret, transcriptForServer, 'server finished');
    if (!srvFinished.verifyData.equals(expected)) {
      throw new Error('Server Finished verify_data mismatch');
    }
    this.#verboseLog('received and verified server Finished');

    this.recordLayer.state = 'ENCRYPTED';
    this.#verboseLog('TLS handshake completed successfully');
  }

  async readHandshakeMessage(encrypted = false) {
    const which = encrypted ? 'encrypted' : 'plain';
    let buffer = this.handshakeBuffers[which];

    while (buffer.length < 4) {
      const { type, fragment } = encrypted
        ? await this.recordLayer.readEncryptedRecord()
        : await this.recordLayer.readPlainRecord();

      if (type !== 0x16) {
        throw new Error(`Expected Handshake record, got type ${type}`);
      }

      buffer = Buffer.concat([buffer, fragment]);
      this.handshakeBuffers[which] = buffer;
    }

    const messageLength = buffer.readUIntBE(1, 3);
    const totalLength = 4 + messageLength;

    while (buffer.length < totalLength) {
      const { type, fragment } = encrypted
        ? await this.recordLayer.readEncryptedRecord()
        : await this.recordLayer.readPlainRecord();

      if (type !== 0x16) {
        throw new Error(`Expected Handshake record, got type ${type}`);
      }

      buffer = Buffer.concat([buffer, fragment]);
      this.handshakeBuffers[which] = buffer;
    }

    const raw = buffer.subarray(0, totalLength);
    this.handshakeBuffers[which] = buffer.subarray(totalLength);

    return {
      type: raw.readUInt8(0),
      body: raw.subarray(4),
      raw,
    };
  }

  async sendApplicationData(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    this.#verboseLog(`sent application data (${buf.length} bytes): ${formatVerboseBuffer(buf)}`);
    await this.recordLayer.writeEncryptedRecord(0x17, buf);
  }

  async readApplicationData() {
    const { type, fragment } = await this.recordLayer.readEncryptedRecord();
    if (type !== 0x17) {
      throw new Error(`Expected ApplicationData, got record type ${type}`);
    }
    this.#verboseLog(`received application data (${fragment.length} bytes): ${formatVerboseBuffer(fragment)}`);
    return fragment;
  }

  async shutdownToPlain({ waitForPeer = true, timeoutMs = 5000 } = {}) {
    if (this.recordLayer.state === 'CLOSED') {
      this.tcp.detach();
      return this.socket;
    }

    if (this.recordLayer.state !== 'PLAIN') {
      await this.recordLayer.sendAlertCloseNotify();
      if (waitForPeer) {
        await this.#waitForPeerCloseNotify(timeoutMs);
      }
    }

    this.recordLayer.state = 'CLOSED';
    this.tcp.detach();
    return this.socket;
  }

  async #waitForPeerCloseNotify(timeoutMs) {
    while (true) {
      const record = await this.#withTimeout(
        this.recordLayer.readEncryptedRecord(),
        timeoutMs,
        'Timed out waiting for peer close_notify alert',
      );

      if (record.type !== 0x15) {
        continue;
      }

      if (record.fragment.length < 2) {
        throw new Error('Received malformed TLS alert while waiting for close_notify');
      }

      const level = record.fragment.readUInt8(0);
      const description = record.fragment.readUInt8(1);

      if (description === 0x00) {
        return;
      }

      if (level === 0x02) {
        throw new Error(`Received fatal TLS alert 0x${description.toString(16)} during shutdown`);
      }
    }
  }

  async #withTimeout(promise, timeoutMs, message) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('timeoutMs must be a positive number');
    }

    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(message)), timeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async close({ destroySocket = true, sendCloseNotify = true, detach = true } = {}) {
    try {
      if (sendCloseNotify && this.recordLayer.state !== 'CLOSED') {
        await this.recordLayer.sendAlertCloseNotify();
      }
    } finally {
      this.recordLayer.state = 'CLOSED';
      if (detach) {
        this.tcp.detach();
      }
      if (destroySocket) {
        this.socket.destroy();
      }
    }
  }
}

module.exports = {
  TlsClient,
};
