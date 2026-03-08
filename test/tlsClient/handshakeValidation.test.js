const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const crypto = require('node:crypto');

const { TlsClient, TLS_RSA_WITH_AES_128_CBC_SHA } = require('../../src/index.js');
const {
  deriveMasterSecret,
  deriveKeyBlock,
  computeFinishedVerifyData,
} = require('../../src/tlsClient/cryptoPrimitives.js');
const { loadCertificateFixtures } = require('../../support/testCertFixtures.js');

const TLS_VERSION_1_2 = 0x0303;

class ByteStream {
  #buffer = Buffer.alloc(0);
  #waiters = [];
  #ended = false;
  #error = null;

  constructor(socket) {
    this.socket = socket;
    socket.on('data', (chunk) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.resolve();
      }
    });

    const onEnd = (err) => {
      if (err) {
        this.#error = err;
      }
      this.#ended = true;
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.reject(err || new Error('Socket closed'));
      }
    };

    socket.on('end', () => onEnd());
    socket.on('close', () => onEnd());
    socket.on('error', onEnd);
  }

  async #waitForData() {
    if (this.#error) {
      throw this.#error;
    }
    if (this.#ended) {
      throw new Error('Socket closed');
    }
    await new Promise((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }

  async readExactly(length) {
    while (this.#buffer.length < length) {
      await this.#waitForData();
    }

    const out = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return out;
  }

  async write(buf) {
    await new Promise((resolve, reject) => {
      this.socket.write(buf, (err) => (err ? reject(err) : resolve()));
    });
  }
}

function buildHandshake(type, body) {
  const header = Buffer.alloc(4);
  header.writeUInt8(type, 0);
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

function buildServerHello(
  serverRandom,
  {
    version = TLS_VERSION_1_2,
    cipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA,
    compression = 0x00,
    extra = Buffer.alloc(0),
  } = {},
) {
  const versionBuf = Buffer.alloc(2);
  versionBuf.writeUInt16BE(version, 0);
  const cipherSuiteBuf = Buffer.alloc(2);
  cipherSuiteBuf.writeUInt16BE(cipherSuite, 0);

  return buildHandshake(0x02, Buffer.concat([
    versionBuf,
    serverRandom,
    Buffer.from([0x00]),
    cipherSuiteBuf,
    Buffer.from([compression]),
    extra,
  ]));
}

function pemToDer(pem, label) {
  const text = Buffer.isBuffer(pem) ? pem.toString('utf8') : String(pem);
  const sanitized = text
    .replace(`-----BEGIN ${label}-----`, '')
    .replace(`-----END ${label}-----`, '')
    .replace(/\s+/g, '');
  return Buffer.from(sanitized, 'base64');
}

function firstCertificateDer(certPem) {
  const text = Buffer.isBuffer(certPem) ? certPem.toString('utf8') : String(certPem);
  const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!matches || matches.length === 0) {
    throw new Error('Certificate PEM is missing CERTIFICATE block');
  }
  return pemToDer(matches[0], 'CERTIFICATE');
}

function buildCertificate(certPem, extra = Buffer.alloc(0)) {
  const certDer = firstCertificateDer(certPem);
  const certLen = Buffer.alloc(3);
  certLen.writeUIntBE(certDer.length, 0, 3);
  const certificateList = Buffer.concat([certLen, certDer]);
  const listLen = Buffer.alloc(3);
  listLen.writeUIntBE(certificateList.length, 0, 3);
  return buildHandshake(0x0b, Buffer.concat([listLen, certificateList, extra]));
}

function buildCertificateRequest(extra = Buffer.alloc(0)) {
  return buildHandshake(0x0d, Buffer.concat([
    Buffer.from([0x01, 0x01]),
    Buffer.from([0x00, 0x02, 0x04, 0x01]),
    Buffer.from([0x00, 0x00]),
    extra,
  ]));
}

function parseHandshakeMessages(fragment) {
  const messages = [];
  let offset = 0;

  while (offset + 4 <= fragment.length) {
    const type = fragment.readUInt8(offset);
    const length = fragment.readUIntBE(offset + 1, 3);
    const end = offset + 4 + length;
    if (end > fragment.length) {
      throw new Error('Malformed handshake fragment');
    }
    const raw = fragment.subarray(offset, end);
    messages.push({ type, body: raw.subarray(4), raw });
    offset = end;
  }

  if (offset !== fragment.length) {
    throw new Error('Trailing bytes in handshake fragment');
  }

  return messages;
}

function parseClientHello(body) {
  let offset = 0;
  const version = body.readUInt16BE(offset);
  offset += 2;
  if (version !== TLS_VERSION_1_2) {
    throw new Error(`Unsupported client version 0x${version.toString(16)}`);
  }

  const random = body.subarray(offset, offset + 32);
  offset += 32;

  const sessionIdLen = body.readUInt8(offset);
  offset += 1 + sessionIdLen;

  const cipherSuitesLen = body.readUInt16BE(offset);
  offset += 2;

  let offeredExpectedCipher = false;
  for (let i = 0; i < cipherSuitesLen; i += 2) {
    if (body.readUInt16BE(offset + i) === TLS_RSA_WITH_AES_128_CBC_SHA) {
      offeredExpectedCipher = true;
    }
  }
  if (!offeredExpectedCipher) {
    throw new Error('Client did not offer the expected cipher suite');
  }

  return { random };
}

function parseClientKeyExchange(body) {
  const encryptedLength = body.readUInt16BE(0);
  const encrypted = body.subarray(2, 2 + encryptedLength);
  if (encrypted.length !== encryptedLength) {
    throw new Error('Malformed ClientKeyExchange');
  }
  return encrypted;
}

function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

function bufferToBigInt(buffer) {
  if (buffer.length === 0) {
    return 0n;
  }
  return BigInt(`0x${buffer.toString('hex')}`);
}

function bigIntToBuffer(value, length) {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  const raw = Buffer.from(hex, 'hex');
  if (raw.length > length) {
    throw new Error('Integer does not fit in target buffer');
  }
  if (raw.length === length) {
    return raw;
  }
  const out = Buffer.alloc(length);
  raw.copy(out, length - raw.length);
  return out;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let currentBase = base % modulus;
  let currentExponent = exponent;

  while (currentExponent > 0n) {
    if ((currentExponent & 1n) === 1n) {
      result = (result * currentBase) % modulus;
    }
    currentExponent >>= 1n;
    currentBase = (currentBase * currentBase) % modulus;
  }

  return result;
}

function rsaPkcs1v15PrivateDecrypt(privateKeyPem, ciphertext) {
  const jwk = crypto.createPrivateKey(privateKeyPem).export({ format: 'jwk' });
  const modulus = bufferToBigInt(base64UrlToBuffer(jwk.n));
  const privateExponent = bufferToBigInt(base64UrlToBuffer(jwk.d));
  const modulusLength = base64UrlToBuffer(jwk.n).length;
  const decrypted = bigIntToBuffer(modPow(bufferToBigInt(ciphertext), privateExponent, modulus), modulusLength);

  if (decrypted.length < 11 || decrypted[0] !== 0x00 || decrypted[1] !== 0x02) {
    throw new Error('Invalid PKCS#1 block');
  }

  let separator = -1;
  for (let i = 2; i < decrypted.length; i += 1) {
    if (decrypted[i] === 0x00) {
      separator = i;
      break;
    }
  }
  if (separator < 10) {
    throw new Error('Invalid PKCS#1 padding');
  }

  return decrypted.subarray(separator + 1);
}

function splitKeyBlock(keyBlock) {
  let offset = 0;
  return {
    clientWriteMacKey: keyBlock.subarray(offset, (offset += 20)),
    serverWriteMacKey: keyBlock.subarray(offset, (offset += 20)),
    clientWriteKey: keyBlock.subarray(offset, (offset += 16)),
    serverWriteKey: keyBlock.subarray(offset, (offset += 16)),
    readSeqNum: 0n,
    writeSeqNum: 0n,
  };
}

function encryptForClient(contentType, plaintext, state) {
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(state.writeSeqNum);

  const macHeader = Buffer.alloc(5);
  macHeader.writeUInt8(contentType, 0);
  macHeader.writeUInt16BE(TLS_VERSION_1_2, 1);
  macHeader.writeUInt16BE(plaintext.length, 3);

  const mac = crypto
    .createHmac('sha1', state.serverWriteMacKey)
    .update(Buffer.concat([seqBuf, macHeader, plaintext]))
    .digest();

  let plain = Buffer.concat([plaintext, mac]);
  const padLen = 16 - ((plain.length + 1) % 16);
  plain = Buffer.concat([plain, Buffer.alloc(padLen + 1, padLen)]);

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', state.serverWriteKey, iv);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  state.writeSeqNum += 1n;

  return Buffer.concat([iv, encrypted]);
}

function decryptFromClient(contentType, fragment, state) {
  const iv = fragment.subarray(0, 16);
  const ciphertext = fragment.subarray(16);
  const decipher = crypto.createDecipheriv('aes-128-cbc', state.clientWriteKey, iv);
  decipher.setAutoPadding(false);
  let plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  const padLen = plain[plain.length - 1];
  plain = plain.subarray(0, plain.length - padLen - 1);

  const content = plain.subarray(0, plain.length - 20);
  const macRecv = plain.subarray(plain.length - 20);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(state.readSeqNum);
  const macHeader = Buffer.alloc(5);
  macHeader.writeUInt8(contentType, 0);
  macHeader.writeUInt16BE(TLS_VERSION_1_2, 1);
  macHeader.writeUInt16BE(content.length, 3);

  const macExpected = crypto
    .createHmac('sha1', state.clientWriteMacKey)
    .update(Buffer.concat([seqBuf, macHeader, content]))
    .digest();

  if (!crypto.timingSafeEqual(macRecv, macExpected)) {
    throw new Error('TLS MAC verification failed');
  }

  state.readSeqNum += 1n;
  return content;
}

async function readRecord(stream) {
  const header = await stream.readExactly(5);
  const type = header.readUInt8(0);
  const version = header.readUInt16BE(1);
  const length = header.readUInt16BE(3);
  if (version !== TLS_VERSION_1_2) {
    throw new Error(`Unexpected TLS version 0x${version.toString(16)}`);
  }
  const fragment = await stream.readExactly(length);
  return { type, fragment };
}

async function writeRecord(stream, type, fragment) {
  const header = Buffer.alloc(5);
  header.writeUInt8(type, 0);
  header.writeUInt16BE(TLS_VERSION_1_2, 1);
  header.writeUInt16BE(fragment.length, 3);
  await stream.write(Buffer.concat([header, fragment]));
}

async function createMalformedHandshakeServer(fixtures, options = {}) {
  const {
    serverHelloExtra = Buffer.alloc(0),
    serverHelloVersion = TLS_VERSION_1_2,
    serverCipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA,
    serverCompression = 0x00,
    certificateExtra = Buffer.alloc(0),
    certificateRequestExtra = undefined,
    serverHelloDoneBody = Buffer.alloc(0),
    serverFlight = undefined,
    postFinishedRecordType = 0x14,
    changeCipherSpecFragment = Buffer.from([0x01]),
    serverFinishedType = 0x14,
    serverFinishedBody = undefined,
  } = options;

  const server = net.createServer((socket) => {
    void handleClient(socket, fixtures, {
      serverHelloExtra,
      serverHelloVersion,
      serverCipherSuite,
      serverCompression,
      certificateExtra,
      certificateRequestExtra,
      serverHelloDoneBody,
      serverFlight,
      postFinishedRecordType,
      changeCipherSpecFragment,
      serverFinishedType,
      serverFinishedBody,
    }).catch(() => {
      socket.destroy();
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Unable to determine malformed TLS server address');
  }

  return {
    port: address.port,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function handleClient(socket, fixtures, options) {
  const stream = new ByteStream(socket);
  const transcript = [];

  const clientHelloRecord = await readRecord(stream);
  const clientHello = parseHandshakeMessages(clientHelloRecord.fragment)[0];
  transcript.push(clientHello.raw);
  const { random: clientRandom } = parseClientHello(clientHello.body);

  const serverRandom = Buffer.alloc(32);
  serverRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  crypto.randomBytes(28).copy(serverRandom, 4);

  const serverHello = buildServerHello(serverRandom, {
    version: options.serverHelloVersion,
    cipherSuite: options.serverCipherSuite,
    compression: options.serverCompression,
    extra: options.serverHelloExtra,
  });
  const certificate = buildCertificate(fixtures.serverCert, options.certificateExtra);
  const serverHelloDone = buildHandshake(0x0e, options.serverHelloDoneBody);
  const defaultServerFlight = [serverHello, certificate];
  if (options.certificateRequestExtra !== undefined) {
    defaultServerFlight.push(buildCertificateRequest(options.certificateRequestExtra));
  }
  defaultServerFlight.push(serverHelloDone);
  const serverFlight = options.serverFlight || defaultServerFlight;
  transcript.push(...serverFlight);

  for (const message of serverFlight) {
    await writeRecord(stream, 0x16, message);
  }

  let preMasterSecret;
  while (true) {
    const record = await readRecord(stream);
    if (record.type === 0x16) {
      for (const message of parseHandshakeMessages(record.fragment)) {
        transcript.push(message.raw);
        if (message.type === 0x10) {
          preMasterSecret = rsaPkcs1v15PrivateDecrypt(fixtures.serverKey, parseClientKeyExchange(message.body));
        }
      }
      continue;
    }

    if (record.type === 0x14) {
      break;
    }

    throw new Error(`Unexpected record type ${record.type} before client Finished`);
  }

  const masterSecret = deriveMasterSecret(preMasterSecret, clientRandom, serverRandom);
  const keyBlock = deriveKeyBlock(masterSecret, serverRandom, clientRandom, 104);
  const cipherState = splitKeyBlock(keyBlock);

  const clientFinishedRecord = await readRecord(stream);
  const clientFinishedRaw = decryptFromClient(0x16, clientFinishedRecord.fragment, cipherState);
  const clientFinished = parseHandshakeMessages(clientFinishedRaw)[0];
  const expectedClientVerify = computeFinishedVerifyData(masterSecret, Buffer.concat(transcript), 'client finished');
  if (!clientFinished.body.equals(expectedClientVerify)) {
    throw new Error('Client Finished verify_data mismatch');
  }
  transcript.push(clientFinished.raw);

  await writeRecord(stream, options.postFinishedRecordType, options.changeCipherSpecFragment);
  const serverFinished = buildHandshake(
    options.serverFinishedType,
    options.serverFinishedBody || computeFinishedVerifyData(masterSecret, Buffer.concat(transcript), 'server finished'),
  );
  await writeRecord(stream, 0x16, encryptForClient(0x16, serverFinished, cipherState));
  socket.end();
}

test('custom TLS client rejects non-empty ServerHelloDone', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createMalformedHandshakeServer(fixtures, {
    serverHelloDoneBody: Buffer.from([0x42]),
  });

  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /ServerHelloDone must have an empty body/,
  );
});

test('custom TLS client rejects malformed ChangeCipherSpec payload', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createMalformedHandshakeServer(fixtures, {
    changeCipherSpecFragment: Buffer.from([0x02, 0x99]),
  });

  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Malformed ChangeCipherSpec from server/,
  );
});

test('custom TLS client rejects Certificate messages with trailing bytes', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createMalformedHandshakeServer(fixtures, {
    certificateExtra: Buffer.from([0xaa]),
  });

  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Invalid total certificate length/,
  );
});

test('custom TLS client rejects CertificateRequest messages with trailing bytes', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createMalformedHandshakeServer(fixtures, {
    certificateRequestExtra: Buffer.from([0xaa]),
  });

  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        clientCert: fixtures.clientCert,
        clientKey: fixtures.clientKey,
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Trailing bytes in CertificateRequest/,
  );
});

test('custom TLS client rejects ServerHello messages with trailing bytes', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createMalformedHandshakeServer(fixtures, {
    serverHelloExtra: Buffer.from([0x00, 0x00, 0xde]),
  });

  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Invalid ServerHello\.extensions length/,
  );
});

test('custom TLS client rejects unsupported ServerHello version and selection values', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const servers = await Promise.all([
    createMalformedHandshakeServer(fixtures, {
      serverHelloVersion: 0x0301,
    }),
    createMalformedHandshakeServer(fixtures, {
      serverHelloVersion: 0x0304,
    }),
    createMalformedHandshakeServer(fixtures, {
      serverCipherSuite: 0x9999,
    }),
    createMalformedHandshakeServer(fixtures, {
      serverCipherSuite: 0x0035,
    }),
    createMalformedHandshakeServer(fixtures, {
      serverCompression: 0x01,
    }),
  ]);

  t.after(async () => {
    await Promise.all(servers.map((server) => server.close()));
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[0].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /outside configured range/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[1].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
        maxVersion: 'TLSv1.3',
      }),
    /Unsupported TLS version 0x304/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[2].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Server selected unsupported cipher suite 0x9999/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[3].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Server selected a cipher suite not offered by client: 0x35/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[4].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Server selected non-null compression/,
  );
});

test('custom TLS client rejects invalid server handshake ordering', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const firstServerRandom = Buffer.alloc(32, 0x11);
  const secondServerRandom = Buffer.alloc(32, 0x22);
  const orderingServers = await Promise.all([
    createMalformedHandshakeServer(fixtures, {
      serverFlight: [
        buildServerHello(firstServerRandom),
        buildServerHello(secondServerRandom),
      ],
    }),
    createMalformedHandshakeServer(fixtures, {
      serverFlight: [
        buildServerHello(firstServerRandom),
        buildCertificate(fixtures.serverCert),
        buildCertificate(fixtures.serverCert),
      ],
    }),
    createMalformedHandshakeServer(fixtures, {
      serverFlight: [
        buildServerHello(firstServerRandom),
        buildHandshake(0x0e, Buffer.alloc(0)),
      ],
    }),
    createMalformedHandshakeServer(fixtures, {
      serverFlight: [
        buildServerHello(firstServerRandom),
        buildHandshake(0x0c, Buffer.alloc(0)),
      ],
    }),
  ]);

  t.after(async () => {
    await Promise.all(orderingServers.map((server) => server.close()));
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: orderingServers[0].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Unexpected ServerHello ordering in handshake/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: orderingServers[1].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Unexpected Certificate ordering in handshake/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: orderingServers[2].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Unexpected ServerHelloDone ordering in handshake/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: orderingServers[3].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Unexpected handshake message type 0xc/,
  );
});

test('custom TLS client rejects invalid records after sending Finished', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const servers = await Promise.all([
    createMalformedHandshakeServer(fixtures, {
      postFinishedRecordType: 0x15,
      changeCipherSpecFragment: Buffer.from([0x02, 0x28]),
    }),
    createMalformedHandshakeServer(fixtures, {
      postFinishedRecordType: 0x17,
      changeCipherSpecFragment: Buffer.from('x'),
    }),
    createMalformedHandshakeServer(fixtures, {
      serverFinishedType: 0x0f,
      serverFinishedBody: Buffer.alloc(0),
    }),
    createMalformedHandshakeServer(fixtures, {
      serverFinishedBody: Buffer.alloc(12, 0xaa),
    }),
  ]);

  t.after(async () => {
    await Promise.all(servers.map((server) => server.close()));
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[0].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /TLS alert from server: 0228/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[1].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Expected ChangeCipherSpec from server, got record type 23/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[2].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Expected Finished from server/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: servers[3].port,
        servername: 'localhost',
        ca: [fixtures.caCert],
        cipherSuites: [TLS_RSA_WITH_AES_128_CBC_SHA],
      }),
    /Server Finished verify_data mismatch/,
  );
});
