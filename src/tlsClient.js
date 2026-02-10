const net = require('node:net');
const crypto = require('node:crypto');
const tls = require('node:tls');
const { once } = require('node:events');

/**
 * Minimal buffered TCP helper used by the TLS record layer to read exact byte
 * counts off a socket.
 */
class TcpStream {
  #buffer = Buffer.alloc(0);
  #onData;
  /**
   * @param {net.Socket} socket
   */
  constructor(socket) {
    this.socket = socket;
    this.#onData = (chunk) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
    };
    socket.on('data', this.#onData);
  }

  /**
   * Read exactly `n` bytes from the underlying socket, buffering as needed.
   * @param {number} n
   * @returns {Promise<Buffer>}
   */
  async readExactly(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw new TypeError('readExactly requires a non-negative integer length');
    }

    if (n === 0) {
      return Buffer.alloc(0);
    }

    while (this.#buffer.length < n) {
      await new Promise((resolve, reject) => {
        const cleanup = () => {
          this.socket.off('error', onError);
          this.socket.off('end', onClose);
          this.socket.off('close', onClose);
          this.socket.off('data', onData);
        };
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const onClose = () => {
          cleanup();
          reject(new Error('Socket closed while waiting for TLS record bytes'));
        };
        const onData = () => {
          cleanup();
          resolve();
        };

        this.socket.once('error', onError);
        this.socket.once('end', onClose);
        this.socket.once('close', onClose);
        this.socket.once('data', onData);
      });
    }

    const out = this.#buffer.subarray(0, n);
    this.#buffer = this.#buffer.subarray(n);
    return out;
  }

  /**
   * Write a buffer to the underlying socket.
   * @param {Buffer} buf
   */
  async write(buf) {
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('TcpStream.write expects a Buffer');
    }

    await new Promise((resolve, reject) => {
      this.socket.write(buf, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  detach() {
    if (this.#onData) {
      this.socket.off('data', this.#onData);
      this.#onData = null;
    }
  }
}

const TLS_VERSION_1_2 = 0x0303;
const TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
const TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c;

const CIPHER_SPECS = {
  [TLS_RSA_WITH_AES_128_CBC_SHA]: {
    macAlgorithm: 'sha1',
    macKeyLength: 20,
    macLength: 20,
  },
  [TLS_RSA_WITH_AES_128_CBC_SHA256]: {
    macAlgorithm: 'sha256',
    macKeyLength: 32,
    macLength: 32,
  },
};

/**
 * @typedef {"PLAIN" | "ENCRYPTING" | "ENCRYPTED" | "CLOSED"} TlsState
 */

/**
 * @typedef {Object} CipherState
 * @property {Buffer} clientWriteMacKey
 * @property {Buffer} serverWriteMacKey
 * @property {Buffer} clientWriteKey
 * @property {Buffer} serverWriteKey
 * @property {Buffer} clientWriteIV
 * @property {Buffer} serverWriteIV
 * @property {bigint} clientSeqNum
 * @property {bigint} serverSeqNum
 */

function incSeq(num) {
  return BigInt(num) + 1n;
}

function tls12Prf(secret, label, seed, length) {
  const labelBytes = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBytes, seed]);

  function pHash(secretBytes, seedBytes, outLen) {
    let A = seedBytes;
    let out = Buffer.alloc(0);

    while (out.length < outLen) {
      A = crypto.createHmac('sha256', secretBytes).update(A).digest();
      const chunk = crypto
        .createHmac('sha256', secretBytes)
        .update(A)
        .update(seedBytes)
        .digest();
      out = Buffer.concat([out, chunk]);
    }

    return out.subarray(0, outLen);
  }

  return pHash(secret, fullSeed, length);
}

function computeFinishedVerifyData(masterSecret, handshakeTranscript, label) {
  const hash = crypto.createHash('sha256').update(handshakeTranscript).digest();
  return tls12Prf(masterSecret, label, hash, 12);
}

function deriveMasterSecret(preMasterSecret, clientRandom, serverRandom) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  return tls12Prf(preMasterSecret, 'master secret', seed, 48);
}

function deriveKeyBlock(masterSecret, serverRandom, clientRandom, length) {
  const seed = Buffer.concat([serverRandom, clientRandom]);
  return tls12Prf(masterSecret, 'key expansion', seed, length);
}

function buildClientHello(hostname) {
  const clientRandom = Buffer.alloc(32);
  clientRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  crypto.randomBytes(28).copy(clientRandom, 4);

  const sessionId = Buffer.from([0x00]);

  const offeredCipherSuites = [TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA];
  const cipherSuites = Buffer.alloc(2 + offeredCipherSuites.length * 2);
  cipherSuites.writeUInt16BE(offeredCipherSuites.length * 2, 0);
  for (let i = 0; i < offeredCipherSuites.length; i += 1) {
    cipherSuites.writeUInt16BE(offeredCipherSuites[i], 2 + i * 2);
  }

  const compressionMethods = Buffer.from([0x01, 0x00]);

  const hostBuf = Buffer.from(hostname, 'ascii');
  const serverNameListLen = 1 + 2 + hostBuf.length;
  const sniData = Buffer.alloc(2 + serverNameListLen);
  sniData.writeUInt16BE(serverNameListLen, 0);
  sniData.writeUInt8(0x00, 2);
  sniData.writeUInt16BE(hostBuf.length, 3);
  hostBuf.copy(sniData, 5);

  // signature_algorithms (TLS 1.2)
  // Keep the list short: rsa_pkcs1_sha256 and rsa_pkcs1_sha1.
  const sigAlgsData = Buffer.alloc(2 + 4);
  sigAlgsData.writeUInt16BE(4, 0);
  sigAlgsData.writeUInt8(0x04, 2);
  sigAlgsData.writeUInt8(0x01, 3);
  sigAlgsData.writeUInt8(0x02, 4);
  sigAlgsData.writeUInt8(0x01, 5);

  const extBlocks = [buildExtension(0x0000, sniData), buildExtension(0x000d, sigAlgsData)];
  const extPayload = Buffer.concat(extBlocks);
  const extensions = Buffer.alloc(2 + extPayload.length);
  extensions.writeUInt16BE(extPayload.length, 0);
  extPayload.copy(extensions, 2);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    clientRandom,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions,
  ]);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x01, 0);
  header.writeUIntBE(body.length, 1, 3);

  const handshake = Buffer.concat([header, body]);

  return { clientRandom, handshake };
}

function buildExtension(type, data) {
  const ext = Buffer.alloc(4 + data.length);
  ext.writeUInt16BE(type, 0);
  ext.writeUInt16BE(data.length, 2);
  data.copy(ext, 4);
  return ext;
}

function parseServerHello(body) {
  let offset = 0;

  const version = body.readUInt16BE(offset);
  offset += 2;

  const random = body.subarray(offset, offset + 32);
  if (random.length !== 32) {
    throw new Error('Invalid ServerHello.random length');
  }
  offset += 32;

  const sessionIdLen = body.readUInt8(offset);
  offset += 1;
  const sessionId = body.subarray(offset, offset + sessionIdLen);
  offset += sessionIdLen;

  const cipherSuite = body.readUInt16BE(offset);
  offset += 2;
  const compression = body.readUInt8(offset);
  offset += 1;

  const extensions = new Map();
  if (offset < body.length) {
    const extensionsLen = body.readUInt16BE(offset);
    offset += 2;
    const end = offset + extensionsLen;
    if (end > body.length) {
      throw new Error('Invalid ServerHello.extensions length');
    }

    while (offset + 4 <= end) {
      const extType = body.readUInt16BE(offset);
      offset += 2;
      const extLen = body.readUInt16BE(offset);
      offset += 2;
      const extData = body.subarray(offset, offset + extLen);
      offset += extLen;
      extensions.set(extType, extData);
    }
  }

  return { version, random, sessionId, cipherSuite, compression, extensions };
}

function parseCertificate(body) {
  if (body.length < 3) {
    throw new Error('Certificate message too short');
  }

  let offset = 0;
  const totalLen = body.readUIntBE(offset, 3);
  offset += 3;
  const end = offset + totalLen;
  if (end > body.length) {
    throw new Error('Invalid total certificate length');
  }

  const certs = [];
  while (offset + 3 <= end) {
    const certLen = body.readUIntBE(offset, 3);
    offset += 3;
    const cert = body.subarray(offset, offset + certLen);
    offset += certLen;
    certs.push(cert);
  }

  if (certs.length === 0) {
    throw new Error('Empty certificate chain');
  }

  return certs;
}

function derToPem(der, label) {
  const base64 = der.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function pemToDer(pem, label) {
  const text = Buffer.isBuffer(pem) ? pem.toString('utf8') : String(pem);
  const sanitized = text
    .replace(`-----BEGIN ${label}-----`, '')
    .replace(`-----END ${label}-----`, '')
    .replace(/\s+/g, '');
  return Buffer.from(sanitized, 'base64');
}

function parsePemCertificateChain(certPem) {
  if (certPem === undefined) return [];

  const matches = extractCertificatePemBlocks(certPem, 'clientCert');
  return matches.map((block) => pemToDer(block, 'CERTIFICATE'));
}

function extractCertificatePemBlocks(value, fieldName) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value)) {
    throw new TypeError(`${fieldName} must be a string or Buffer`);
  }

  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!matches || matches.length === 0) {
    throw new Error(`${fieldName} must contain at least one CERTIFICATE block`);
  }

  return matches;
}

function parseCaCertificates(ca) {
  if (ca === undefined) {
    return undefined;
  }

  const entries = Array.isArray(ca) ? ca : [ca];
  const certs = [];
  for (const entry of entries) {
    const certBlocks = extractCertificatePemBlocks(entry, 'ca');
    for (const block of certBlocks) {
      certs.push(new crypto.X509Certificate(block));
    }
  }
  return certs;
}

let cachedDefaultCaCertificates;
function getDefaultCaCertificates() {
  if (!cachedDefaultCaCertificates) {
    cachedDefaultCaCertificates = tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem));
  }
  return cachedDefaultCaCertificates;
}

function assertCertificateTimeValid(cert, context) {
  const now = new Date();
  if (now < cert.validFromDate || now > cert.validToDate) {
    throw new Error(
      `${context} certificate is not valid at ${now.toISOString()} (${cert.validFromDate.toISOString()} - ${cert.validToDate.toISOString()})`,
    );
  }
}

function isSignedBy(certificate, issuer) {
  try {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function normalizeServerIdentityResult(hostname, leaf, checkServerIdentity) {
  if (!hostname) {
    return;
  }

  const legacyCert = leaf.toLegacyObject();
  legacyCert.raw = leaf.raw;
  const maybeError = checkServerIdentity(hostname, legacyCert);
  if (maybeError instanceof Error) {
    throw maybeError;
  }
}

function verifyServerCertificateChain({
  chainDer,
  hostname,
  caCertificates,
  checkServerIdentity = tls.checkServerIdentity,
}) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Server did not present a certificate chain');
  }

  const presented = chainDer.map((der) => new crypto.X509Certificate(der));
  const leaf = presented[0];
  normalizeServerIdentityResult(hostname, leaf, checkServerIdentity);

  const trustStore = caCertificates === undefined ? getDefaultCaCertificates() : caCertificates;
  if (!Array.isArray(trustStore) || trustStore.length === 0) {
    throw new Error('No trusted CA certificates available for server validation');
  }

  const trustedFingerprints = new Set(trustStore.map((cert) => cert.fingerprint256));
  const visited = new Set();
  let current = leaf;

  while (true) {
    assertCertificateTimeValid(current, 'Server');
    if (trustedFingerprints.has(current.fingerprint256)) {
      return;
    }

    visited.add(current.fingerprint256);

    const issuerFromPresented = presented.find(
      (candidate) =>
        candidate.ca === true &&
        !visited.has(candidate.fingerprint256) &&
        candidate.fingerprint256 !== current.fingerprint256 &&
        isSignedBy(current, candidate),
    );

    if (issuerFromPresented) {
      current = issuerFromPresented;
      continue;
    }

    const issuerFromTrustStore = trustStore.find((candidate) => isSignedBy(current, candidate));
    if (issuerFromTrustStore) {
      assertCertificateTimeValid(issuerFromTrustStore, 'Trusted CA');
      return;
    }

    throw new Error('Server certificate chain is not signed by a trusted CA');
  }
}

function validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity }) {
  if (typeof rejectUnauthorized !== 'boolean') {
    throw new TypeError('rejectUnauthorized must be a boolean');
  }

  if (checkServerIdentity !== undefined && typeof checkServerIdentity !== 'function') {
    throw new TypeError('checkServerIdentity must be a function');
  }
}

function parseConnectionOptions({
  servername,
  clientCert,
  clientKey,
  ca,
  rejectUnauthorized = true,
  checkServerIdentity,
}) {
  validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity });

  return {
    servername,
    clientCertChain: parsePemCertificateChain(clientCert),
    clientPrivateKey: parsePrivateKey(clientKey),
    caCertificates: parseCaCertificates(ca),
    rejectUnauthorized,
    checkServerIdentity: checkServerIdentity || tls.checkServerIdentity,
  };
}

function parseServerCertificate(serverCertDer) {
  if (!Buffer.isBuffer(serverCertDer)) {
    throw new TypeError('server certificate must be a Buffer');
  }
  return derToPem(serverCertDer, 'CERTIFICATE');
}

function ensureClientCertificateMatchesKey(clientCertChain, clientPrivateKey) {
  if (clientCertChain.length === 0 || !clientPrivateKey) {
    return;
  }

  const leafCert = new crypto.X509Certificate(derToPem(clientCertChain[0], 'CERTIFICATE'));
  const key = crypto.createPrivateKey(clientPrivateKey);
  if (!leafCert.checkPrivateKey(key)) {
    throw new Error('clientCert and clientKey do not match');
  }
}

function ensureClientAuthMaterial(clientCertChain, clientPrivateKey) {
  if (clientCertChain.length > 0 && !clientPrivateKey) {
    throw new Error('clientKey is required when clientCert is provided');
  }
  if (clientPrivateKey && clientCertChain.length === 0) {
    throw new Error('clientCert is required when clientKey is provided');
  }
  ensureClientCertificateMatchesKey(clientCertChain, clientPrivateKey);
}

function ensureServerName(servername) {
  if (typeof servername !== 'string' || servername.length === 0) {
    throw new TypeError('servername must be a non-empty string');
  }
}

function ensureSocketConnected(socket) {
  if (!socket || typeof socket.write !== 'function') {
    throw new TypeError('fromExistingSocket requires an active socket');
  }
}

function defaultVerboseLogger(message) {
  console.log(message);
}

function ensureHostAndPort(host, port) {
  if (typeof host !== 'string' || host.length === 0) {
    throw new TypeError('host must be a non-empty string');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('port must be an integer between 1 and 65535');
  }
}

function extractLegacyPublicServerCert(chainDer) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Server certificate chain is empty');
  }

  return parseServerCertificate(chainDer[0]);
}

function parsePrivateKey(keyPem) {
  if (keyPem === undefined) return undefined;
  if (typeof keyPem !== 'string' && !Buffer.isBuffer(keyPem)) {
    throw new TypeError('clientKey must be a string or Buffer');
  }
  return Buffer.isBuffer(keyPem) ? keyPem.toString('utf8') : keyPem;
}

function buildPreMasterSecret() {
  const pms = Buffer.alloc(48);
  pms.writeUInt16BE(TLS_VERSION_1_2, 0);
  crypto.randomBytes(46).copy(pms, 2);
  return pms;
}

function encryptPreMasterSecret(preMasterSecret, serverCertPem) {
  const publicKey = crypto.createPublicKey(serverCertPem);
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    preMasterSecret,
  );
}

function buildClientKeyExchange(encryptedPms) {
  const body = Buffer.alloc(2 + encryptedPms.length);
  body.writeUInt16BE(encryptedPms.length, 0);
  encryptedPms.copy(body, 2);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x10, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildClientCertificate(chainDer) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Client certificate chain cannot be empty when building Certificate message');
  }

  const certEntries = chainDer.map((cert) => {
    if (!Buffer.isBuffer(cert)) {
      throw new TypeError('Certificate entries must be Buffers');
    }
    const len = Buffer.alloc(3);
    len.writeUIntBE(cert.length, 0, 3);
    return Buffer.concat([len, cert]);
  });

  const concatenated = Buffer.concat(certEntries);
  const bodyLen = Buffer.alloc(3);
  bodyLen.writeUIntBE(concatenated.length, 0, 3);
  const body = Buffer.concat([bodyLen, concatenated]);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x0b, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildCertificateVerify(privateKeyPem, handshakeTranscript) {
  if (!privateKeyPem) {
    throw new Error('Private key required to build CertificateVerify');
  }

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(Buffer.concat(handshakeTranscript));
  const signature = signer.sign(privateKeyPem);

  const body = Buffer.alloc(4 + signature.length);
  body.writeUInt8(0x04, 0); // sha256
  body.writeUInt8(0x01, 1); // rsa
  body.writeUInt16BE(signature.length, 2);
  signature.copy(body, 4);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x0f, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildFinished(masterSecret, handshakeTranscript, forClient) {
  const label = forClient ? 'client finished' : 'server finished';
  const verifyData = computeFinishedVerifyData(masterSecret, handshakeTranscript, label);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x14, 0);
  header.writeUIntBE(verifyData.length, 1, 3);

  return Buffer.concat([header, verifyData]);
}

function parseFinishedHandshake(fragment) {
  if (fragment.length < 4) {
    throw new Error('Finished handshake too short');
  }

  const msgType = fragment.readUInt8(0);
  if (msgType !== 0x14) {
    throw new Error(`Unexpected handshake type ${msgType} in Finished message`);
  }

  const length = fragment.readUIntBE(1, 3);
  const body = fragment.subarray(4, 4 + length);
  if (body.length !== length) {
    throw new Error('Incomplete Finished verify_data');
  }

  return { verifyData: body };
}

function parseCertificateRequest(body) {
  let offset = 0;

  if (body.length < 1) {
    throw new Error('CertificateRequest too short');
  }

  const certTypesLen = body.readUInt8(offset);
  offset += 1;
  const certTypes = [...body.subarray(offset, offset + certTypesLen)];
  offset += certTypesLen;

  if (offset + 2 > body.length) {
    throw new Error('CertificateRequest missing signature_algorithms length');
  }

  const sigAlgosLen = body.readUInt16BE(offset);
  offset += 2;
  const sigAlgosEnd = offset + sigAlgosLen;
  if (sigAlgosEnd > body.length) {
    throw new Error('Invalid signature_algorithms length in CertificateRequest');
  }

  const signatureAlgorithms = [];
  while (offset + 1 < sigAlgosEnd) {
    const hash = body.readUInt8(offset);
    const signature = body.readUInt8(offset + 1);
    signatureAlgorithms.push({ hash, signature });
    offset += 2;
  }

  if (offset !== sigAlgosEnd) {
    throw new Error('Trailing bytes in CertificateRequest signature_algorithms');
  }

  if (offset + 2 > body.length) {
    throw new Error('CertificateRequest missing distinguished_names length');
  }

  const namesLen = body.readUInt16BE(offset);
  offset += 2;
  const namesEnd = offset + namesLen;
  if (namesEnd > body.length) {
    throw new Error('Invalid distinguished_names length in CertificateRequest');
  }

  // Skip distinguished names; we don't need them for the test scenarios
  offset = namesEnd;

  return { certTypes, signatureAlgorithms };
}

/**
 * Slice the TLS key block into MAC keys, encryption keys, and IVs.
 * @param {Buffer} keyBlock
 * @returns {CipherState}
 */
function makeCipherStateFromKeyBlock(keyBlock, cipherSpec = CIPHER_SPECS[TLS_RSA_WITH_AES_128_CBC_SHA]) {
  if (!Buffer.isBuffer(keyBlock)) {
    throw new TypeError('keyBlock must be a Buffer');
  }
  if (!cipherSpec || typeof cipherSpec !== 'object') {
    throw new TypeError('cipherSpec must be an object');
  }

  const { macKeyLength, macAlgorithm, macLength } = cipherSpec;
  if (!Number.isInteger(macKeyLength) || macKeyLength <= 0) {
    throw new TypeError('cipherSpec.macKeyLength must be a positive integer');
  }
  if (typeof macAlgorithm !== 'string' || macAlgorithm.length === 0) {
    throw new TypeError('cipherSpec.macAlgorithm must be a non-empty string');
  }
  if (!Number.isInteger(macLength) || macLength <= 0) {
    throw new TypeError('cipherSpec.macLength must be a positive integer');
  }

  const REQUIRED = macKeyLength * 2 + 16 + 16 + 16 + 16;
  if (keyBlock.length < REQUIRED) {
    throw new Error(`keyBlock must be at least ${REQUIRED} bytes`);
  }

  let offset = 0;
  const clientWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const serverWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const clientWriteKey = keyBlock.subarray(offset, (offset += 16));
  const serverWriteKey = keyBlock.subarray(offset, (offset += 16));
  const clientWriteIV = keyBlock.subarray(offset, (offset += 16));
  const serverWriteIV = keyBlock.subarray(offset, (offset += 16));

  return {
    clientWriteMacKey,
    serverWriteMacKey,
    clientWriteKey,
    serverWriteKey,
    clientWriteIV,
    serverWriteIV,
    macAlgorithm,
    macLength,
    clientSeqNum: 0n,
    serverSeqNum: 0n,
  };
}

class TlsRecordLayer {
  state = 'PLAIN';
  version = TLS_VERSION_1_2;

  /**
   * @param {TcpStream} tcp
   */
  constructor(tcp) {
    this.tcp = tcp;
    this.cipher = undefined;
  }

  installCipher(cipher) {
    this.cipher = cipher;
  }

  async writePlainRecord(contentType, fragment) {
    if (this.state === 'CLOSED') {
      throw new Error('TLS connection closed');
    }

    if (!Buffer.isBuffer(fragment)) {
      throw new TypeError('TLS record fragment must be a Buffer');
    }

    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(this.version, 1);
    header.writeUInt16BE(fragment.length, 3);

    await this.tcp.write(Buffer.concat([header, fragment]));
  }

  async readPlainRecord() {
    if (this.state === 'CLOSED') {
      throw new Error('TLS connection closed');
    }

    const header = await this.tcp.readExactly(5);
    const type = header.readUInt8(0);
    const ver = header.readUInt16BE(1);
    const length = header.readUInt16BE(3);

    if (ver !== this.version) {
      throw new Error(`Unexpected TLS version in record: 0x${ver.toString(16)}`);
    }

    const fragment = await this.tcp.readExactly(length);
    return { type, fragment };
  }

  async sendChangeCipherSpec() {
    const body = Buffer.from([0x01]);
    await this.writePlainRecord(0x14, body);

    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }
    this.state = 'ENCRYPTING';
  }

  async sendAlertCloseNotify() {
    const alert = Buffer.from([0x01, 0x00]);

    if (this.state === 'PLAIN') {
      await this.writePlainRecord(0x15, alert);
    } else if (this.state === 'ENCRYPTING' || this.state === 'ENCRYPTED') {
      await this.writeEncryptedRecord(0x15, alert);
    }
  }

  async writeEncryptedRecord(contentType, plaintext) {
    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }
    if (this.state !== 'ENCRYPTING' && this.state !== 'ENCRYPTED') {
      throw new Error('Cannot write encrypted record while not in ENCRYPTING/ENCRYPTED state');
    }
    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('TLS record fragment must be a Buffer');
    }

    const c = this.cipher;
    const seqNum = c.clientSeqNum;

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(contentType, 0);
    headerForMac.writeUInt16BE(this.version, 1);
    headerForMac.writeUInt16BE(plaintext.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, plaintext]);
    const mac = crypto.createHmac(c.macAlgorithm, c.clientWriteMacKey).update(macInput).digest();

    let plain = Buffer.concat([plaintext, mac]);
    const blockSize = 16;
    const padLen = blockSize - ((plain.length + 1) % blockSize);
    const pad = Buffer.alloc(padLen + 1, padLen);
    plain = Buffer.concat([plain, pad]);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', c.clientWriteKey, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

    const fragment = Buffer.concat([iv, encrypted]);
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(this.version, 1);
    header.writeUInt16BE(fragment.length, 3);

    await this.tcp.write(Buffer.concat([header, fragment]));

    c.clientSeqNum = incSeq(seqNum);
    this.state = 'ENCRYPTED';
  }

  async readEncryptedRecord() {
    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }

    const header = await this.tcp.readExactly(5);
    const type = header.readUInt8(0);
    const ver = header.readUInt16BE(1);
    const length = header.readUInt16BE(3);

    if (ver !== this.version) {
      throw new Error(`Unexpected TLS version in encrypted record: 0x${ver.toString(16)}`);
    }

    const fragment = await this.tcp.readExactly(length);
    const c = this.cipher;
    const seqNum = c.serverSeqNum;

    if (fragment.length < 16) {
      throw new Error('Encrypted fragment too short (no IV)');
    }

    const iv = fragment.subarray(0, 16);
    const ciphertext = fragment.subarray(16);

    const decipher = crypto.createDecipheriv('aes-128-cbc', c.serverWriteKey, iv);
    decipher.setAutoPadding(false);
    let plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    if (plain.length === 0) {
      throw new Error('Decrypted plaintext empty');
    }

    const padLen = plain[plain.length - 1];
    const totalPadLen = padLen + 1;
    if (totalPadLen > plain.length) {
      throw new Error('Invalid padding length');
    }
    plain = plain.subarray(0, plain.length - totalPadLen);

    if (plain.length < c.macLength) {
      throw new Error('Plaintext too short to contain record MAC');
    }

    const content = plain.subarray(0, plain.length - c.macLength);
    const macRecv = plain.subarray(plain.length - c.macLength);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(type, 0);
    headerForMac.writeUInt16BE(ver, 1);
    headerForMac.writeUInt16BE(content.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, content]);
    const macExpected = crypto.createHmac(c.macAlgorithm, c.serverWriteMacKey).update(macInput).digest();

    if (!crypto.timingSafeEqual(macRecv, macExpected)) {
      throw new Error('TLS MAC verification failed');
    }

    c.serverSeqNum = incSeq(seqNum);
    return { type, fragment: content };
  }
}

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
    const { clientRandom, handshake: ch } = buildClientHello(this.hostname);
    this.clientRandom = clientRandom;
    this.handshakeTranscript.push(ch);

    await this.recordLayer.writePlainRecord(0x16, ch);
    this.#verboseLog('sent ClientHello');

    let serverCertPem;
    let sawServerHello = false;
    let sawServerCert = false;
    let certRequest = null;

    while (true) {
      const msg = await this.readHandshakeMessage(false);

      if (msg.type === 0x02) {
        this.handshakeTranscript.push(msg.raw);
        const serverHello = parseServerHello(msg.body);
        this.serverRandom = serverHello.random;
        this.selectedCipherSuite = serverHello.cipherSuite;
        sawServerHello = true;
        this.#verboseLog(
          `received ServerHello version=0x${serverHello.version.toString(16)} cipher=0x${serverHello.cipherSuite.toString(16)}`,
        );

        if (serverHello.version !== TLS_VERSION_1_2) {
          throw new Error(`Unsupported TLS version 0x${serverHello.version.toString(16)}`);
        }
        if (!CIPHER_SPECS[serverHello.cipherSuite]) {
          throw new Error(`Server selected unsupported cipher suite 0x${serverHello.cipherSuite.toString(16)}`);
        }
        if (serverHello.compression !== 0x00) {
          throw new Error('Server selected non-null compression');
        }
        continue;
      }

      if (msg.type === 0x0b) {
        this.handshakeTranscript.push(msg.raw);
        const chain = parseCertificate(msg.body);
        this.serverCertChain = chain;
        serverCertPem = extractLegacyPublicServerCert(chain);
        sawServerCert = true;
        this.#verboseLog(`received server certificate chain entries=${chain.length}`);
        continue;
      }

      if (msg.type === 0x0d) {
        this.handshakeTranscript.push(msg.raw);
        certRequest = parseCertificateRequest(msg.body);
        this.#verboseLog('server requested client certificate');
        continue;
      }

      if (msg.type === 0x0e) {
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
    const keyBlockLength = this.cipherSpec.macKeyLength * 2 + 16 + 16 + 16 + 16;
    const keyBlock = deriveKeyBlock(this.masterSecret, this.serverRandom, this.clientRandom, keyBlockLength);
    const cipherState = makeCipherStateFromKeyBlock(keyBlock, this.cipherSpec);
    this.recordLayer.installCipher(cipherState);
    this.#verboseLog(`installed cipher suite=0x${this.selectedCipherSuite.toString(16)} mac=${this.cipherSpec.macAlgorithm}`);

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
    await this.recordLayer.writeEncryptedRecord(0x17, buf);
  }

  async readApplicationData() {
    const { type, fragment } = await this.recordLayer.readEncryptedRecord();
    if (type !== 0x17) {
      throw new Error(`Expected ApplicationData, got record type ${type}`);
    }
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
  TcpStream,
  TLS_VERSION_1_2,
  makeCipherStateFromKeyBlock,
  TlsRecordLayer,
  TlsClient,
};
