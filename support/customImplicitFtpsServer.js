const net = require('node:net');
const crypto = require('node:crypto');

const TLS_VERSION_1_2 = 0x0303;
const TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;

class ByteStream {
  #buffer = Buffer.alloc(0);
  #waiters = [];
  #ended = false;
  #error = null;
  #handleData;
  #handleEnd;
  #handleError;

  constructor(socket) {
    this.socket = socket;
    this.#handleData = (chunk) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.resolve();
      }
    };
    this.#handleEnd = () => {
      this.#ended = true;
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.reject(new Error('Socket closed'));
      }
    };
    this.#handleError = (err) => {
      this.#error = err;
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.reject(err);
      }
    };

    socket.on('data', this.#handleData);
    socket.on('end', this.#handleEnd);
    socket.on('close', this.#handleEnd);
    socket.on('error', this.#handleError);
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
    if (!Number.isInteger(length) || length < 0) {
      throw new TypeError('readExactly length must be a non-negative integer');
    }

    while (this.#buffer.length < length) {
      await this.#waitForData();
    }

    const out = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return out;
  }

  async readLine() {
    while (true) {
      const newline = this.#buffer.indexOf(0x0a);
      if (newline !== -1) {
        const line = this.#buffer.subarray(0, newline + 1);
        this.#buffer = this.#buffer.subarray(newline + 1);
        return line.toString('utf8').replace(/\r?\n$/, '');
      }
      await this.#waitForData();
    }
  }

  async write(data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    await new Promise((resolve, reject) => {
      this.socket.write(buffer, (err) => (err ? reject(err) : resolve()));
    });
  }
}

function tls12Prf(secret, label, seed, length) {
  const labelBytes = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBytes, seed]);

  let A = fullSeed;
  let out = Buffer.alloc(0);
  while (out.length < length) {
    A = crypto.createHmac('sha256', secret).update(A).digest();
    const chunk = crypto.createHmac('sha256', secret).update(A).update(fullSeed).digest();
    out = Buffer.concat([out, chunk]);
  }

  return out.subarray(0, length);
}

function deriveMasterSecret(preMasterSecret, clientRandom, serverRandom) {
  return tls12Prf(preMasterSecret, 'master secret', Buffer.concat([clientRandom, serverRandom]), 48);
}

function deriveKeyBlock(masterSecret, serverRandom, clientRandom, length) {
  return tls12Prf(masterSecret, 'key expansion', Buffer.concat([serverRandom, clientRandom]), length);
}

function computeFinishedVerifyData(masterSecret, transcript, label) {
  const hash = crypto.createHash('sha256').update(transcript).digest();
  return tls12Prf(masterSecret, label, hash, 12);
}

function buildHandshake(type, body) {
  const header = Buffer.alloc(4);
  header.writeUInt8(type, 0);
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

function buildServerHello(serverRandom) {
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    serverRandom,
    Buffer.from([0x00]), // session id length
    Buffer.from([0x00, 0x2f]), // TLS_RSA_WITH_AES_128_CBC_SHA
    Buffer.from([0x00]), // compression method null
  ]);
  return buildHandshake(0x02, body);
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
    throw new Error('Certificate PEM is missing CERTIFICATE blocks');
  }
  return pemToDer(matches[0], 'CERTIFICATE');
}

function buildCertificate(certPem) {
  const certDer = firstCertificateDer(certPem);
  const certLen = Buffer.alloc(3);
  certLen.writeUIntBE(certDer.length, 0, 3);
  const certEntry = Buffer.concat([certLen, certDer]);

  const allLen = Buffer.alloc(3);
  allLen.writeUIntBE(certEntry.length, 0, 3);
  return buildHandshake(0x0b, Buffer.concat([allLen, certEntry]));
}

function buildServerHelloDone() {
  return buildHandshake(0x0e, Buffer.alloc(0));
}

function buildFinished(masterSecret, transcript, forClient) {
  const label = forClient ? 'client finished' : 'server finished';
  const verifyData = computeFinishedVerifyData(masterSecret, transcript, label);
  return buildHandshake(0x14, verifyData);
}

function parseHandshakeMessages(fragment) {
  const messages = [];
  let offset = 0;

  while (offset + 4 <= fragment.length) {
    const type = fragment.readUInt8(offset);
    const len = fragment.readUIntBE(offset + 1, 3);
    const end = offset + 4 + len;
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
  let supportsCipher = false;
  for (let i = 0; i < cipherSuitesLen; i += 2) {
    const cs = body.readUInt16BE(offset + i);
    if (cs === TLS_RSA_WITH_AES_128_CBC_SHA) {
      supportsCipher = true;
    }
  }
  if (!supportsCipher) {
    throw new Error('Client does not offer TLS_RSA_WITH_AES_128_CBC_SHA');
  }

  return { random };
}

function parseClientKeyExchange(body) {
  if (body.length < 2) {
    throw new Error('ClientKeyExchange too short');
  }
  const encLen = body.readUInt16BE(0);
  const encrypted = body.subarray(2, 2 + encLen);
  if (encrypted.length !== encLen) {
    throw new Error('Malformed ClientKeyExchange length');
  }
  return encrypted;
}

function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

function bufferToBigInt(buffer) {
  if (buffer.length === 0) return 0n;
  return BigInt(`0x${buffer.toString('hex')}`);
}

function bigIntToBuffer(value, length) {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  const raw = Buffer.from(hex, 'hex');
  if (raw.length > length) {
    throw new Error('Integer does not fit in target buffer length');
  }
  if (raw.length === length) {
    return raw;
  }
  const out = Buffer.alloc(length);
  raw.copy(out, length - raw.length);
  return out;
}

function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = base % modulus;
  let e = exponent;

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % modulus;
    }
    e >>= 1n;
    b = (b * b) % modulus;
  }

  return result;
}

function rsaPkcs1v15PrivateDecrypt(privateKeyPem, ciphertext) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const jwk = key.export({ format: 'jwk' });
  if (!jwk?.n || !jwk?.d) {
    throw new Error('Private key export missing RSA parameters');
  }

  const modulus = bufferToBigInt(base64UrlToBuffer(jwk.n));
  const privateExponent = bufferToBigInt(base64UrlToBuffer(jwk.d));
  const k = base64UrlToBuffer(jwk.n).length;
  if (ciphertext.length !== k) {
    throw new Error('Encrypted pre-master secret has unexpected length');
  }

  const c = bufferToBigInt(ciphertext);
  const m = modPow(c, privateExponent, modulus);
  const em = bigIntToBuffer(m, k);

  // RSAES-PKCS1-v1_5 decoding for block type 0x02
  if (em.length < 11 || em[0] !== 0x00 || em[1] !== 0x02) {
    throw new Error('Invalid PKCS#1 v1.5 block');
  }
  let separator = -1;
  for (let i = 2; i < em.length; i += 1) {
    if (em[i] === 0x00) {
      separator = i;
      break;
    }
  }
  if (separator < 10) {
    throw new Error('Invalid PKCS#1 v1.5 padding length');
  }

  return em.subarray(separator + 1);
}

function parseFinished(rawHandshake) {
  const messages = parseHandshakeMessages(rawHandshake);
  if (messages.length !== 1 || messages[0].type !== 0x14) {
    throw new Error('Expected exactly one Finished handshake message');
  }
  return messages[0];
}

function splitKeyBlock(keyBlock) {
  if (keyBlock.length < 104) {
    throw new Error('key_block too short');
  }

  let offset = 0;
  return {
    clientWriteMacKey: keyBlock.subarray(offset, (offset += 20)),
    serverWriteMacKey: keyBlock.subarray(offset, (offset += 20)),
    clientWriteKey: keyBlock.subarray(offset, (offset += 16)),
    serverWriteKey: keyBlock.subarray(offset, (offset += 16)),
    clientWriteIV: keyBlock.subarray(offset, (offset += 16)),
    serverWriteIV: keyBlock.subarray(offset, (offset += 16)),
    readSeqNum: 0n,
    writeSeqNum: 0n,
  };
}

function nextSeq(seq) {
  return seq + 1n;
}

function encryptForClient(contentType, plaintext, state) {
  const seqNum = state.writeSeqNum;
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqNum);

  const macHeader = Buffer.alloc(5);
  macHeader.writeUInt8(contentType, 0);
  macHeader.writeUInt16BE(TLS_VERSION_1_2, 1);
  macHeader.writeUInt16BE(plaintext.length, 3);

  const mac = crypto
    .createHmac('sha1', state.serverWriteMacKey)
    .update(Buffer.concat([seqBuf, macHeader, plaintext]))
    .digest();

  let plain = Buffer.concat([plaintext, mac]);
  const blockSize = 16;
  const padLen = blockSize - ((plain.length + 1) % blockSize);
  plain = Buffer.concat([plain, Buffer.alloc(padLen + 1, padLen)]);

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', state.serverWriteKey, iv);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

  state.writeSeqNum = nextSeq(seqNum);
  return Buffer.concat([iv, encrypted]);
}

function decryptFromClient(contentType, fragment, state) {
  const seqNum = state.readSeqNum;
  if (fragment.length < 16) {
    throw new Error('Encrypted fragment too short');
  }

  const iv = fragment.subarray(0, 16);
  const ciphertext = fragment.subarray(16);
  if (ciphertext.length % 16 !== 0) {
    throw new Error('Invalid ciphertext length');
  }

  const decipher = crypto.createDecipheriv('aes-128-cbc', state.clientWriteKey, iv);
  decipher.setAutoPadding(false);
  let plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  const padLen = plain[plain.length - 1];
  const totalPadLen = padLen + 1;
  if (totalPadLen > plain.length) {
    throw new Error('Invalid CBC padding');
  }
  for (let i = plain.length - totalPadLen; i < plain.length; i += 1) {
    if (plain[i] !== padLen) {
      throw new Error('Invalid CBC padding bytes');
    }
  }
  plain = plain.subarray(0, plain.length - totalPadLen);

  if (plain.length < 20) {
    throw new Error('Decrypted plaintext too short for HMAC');
  }

  const content = plain.subarray(0, plain.length - 20);
  const macRecv = plain.subarray(plain.length - 20);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqNum);
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

  state.readSeqNum = nextSeq(seqNum);
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

async function completeServerHandshake(stream, { key, cert }) {
  const transcript = [];

  const clientHelloRecord = await readRecord(stream);
  if (clientHelloRecord.type !== 0x16) {
    throw new Error(`Expected ClientHello record, got ${clientHelloRecord.type}`);
  }
  const clientHelloMsgs = parseHandshakeMessages(clientHelloRecord.fragment);
  if (clientHelloMsgs.length !== 1 || clientHelloMsgs[0].type !== 0x01) {
    throw new Error('Expected single ClientHello message');
  }
  transcript.push(clientHelloMsgs[0].raw);
  const { random: clientRandom } = parseClientHello(clientHelloMsgs[0].body);

  const serverRandom = Buffer.alloc(32);
  serverRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  crypto.randomBytes(28).copy(serverRandom, 4);

  const serverHello = buildServerHello(serverRandom);
  const certificate = buildCertificate(cert);
  const serverHelloDone = buildServerHelloDone();
  transcript.push(serverHello, certificate, serverHelloDone);

  await writeRecord(stream, 0x16, serverHello);
  await writeRecord(stream, 0x16, certificate);
  await writeRecord(stream, 0x16, serverHelloDone);

  let preMasterSecret;
  while (true) {
    const record = await readRecord(stream);
    if (record.type === 0x16) {
      const messages = parseHandshakeMessages(record.fragment);
      for (const message of messages) {
        transcript.push(message.raw);
        if (message.type === 0x10) {
          const encrypted = parseClientKeyExchange(message.body);
          preMasterSecret = rsaPkcs1v15PrivateDecrypt(key, encrypted);
          if (preMasterSecret.length !== 48) {
            throw new Error('Invalid pre-master secret length');
          }
        }
      }
      continue;
    }

    if (record.type === 0x14) {
      if (!record.fragment.equals(Buffer.from([0x01]))) {
        throw new Error('Malformed ChangeCipherSpec from client');
      }
      break;
    }

    throw new Error(`Unexpected record type ${record.type} before client Finished`);
  }

  if (!preMasterSecret) {
    throw new Error('Missing ClientKeyExchange message');
  }

  const masterSecret = deriveMasterSecret(preMasterSecret, clientRandom, serverRandom);
  const keyBlock = deriveKeyBlock(masterSecret, serverRandom, clientRandom, 104);
  const cipherState = splitKeyBlock(keyBlock);

  const clientFinishedRecord = await readRecord(stream);
  if (clientFinishedRecord.type !== 0x16) {
    throw new Error(`Expected encrypted Finished handshake, got record ${clientFinishedRecord.type}`);
  }

  const clientFinishedRaw = decryptFromClient(0x16, clientFinishedRecord.fragment, cipherState);
  const clientFinished = parseFinished(clientFinishedRaw);
  const expectedClientVerify = computeFinishedVerifyData(
    masterSecret,
    Buffer.concat(transcript),
    'client finished',
  );
  if (!crypto.timingSafeEqual(clientFinished.body, expectedClientVerify)) {
    throw new Error('Client Finished verify_data mismatch');
  }
  transcript.push(clientFinished.raw);

  await writeRecord(stream, 0x14, Buffer.from([0x01]));
  const serverFinished = buildFinished(masterSecret, Buffer.concat(transcript), false);
  const encryptedServerFinished = encryptForClient(0x16, serverFinished, cipherState);
  await writeRecord(stream, 0x16, encryptedServerFinished);

  return { cipherState };
}

async function sendSecureLine(stream, tlsState, line) {
  const plaintext = Buffer.from(`${line}\r\n`, 'utf8');
  const encrypted = encryptForClient(0x17, plaintext, tlsState.cipherState);
  await writeRecord(stream, 0x17, encrypted);
}

async function readSecureLine(stream, tlsState, bufferState) {
  while (true) {
    const newline = bufferState.buffer.indexOf(0x0a);
    if (newline !== -1) {
      const line = bufferState.buffer.subarray(0, newline + 1);
      bufferState.buffer = bufferState.buffer.subarray(newline + 1);
      return line.toString('utf8').replace(/\r?\n$/, '');
    }

    const record = await readRecord(stream);
    if (record.type !== 0x17) {
      throw new Error(`Expected encrypted ApplicationData, got record ${record.type}`);
    }
    const plaintext = decryptFromClient(0x17, record.fragment, tlsState.cipherState);
    bufferState.buffer = Buffer.concat([bufferState.buffer, plaintext]);
  }
}

async function performTlsShutdown(stream, tlsState, stats) {
  while (true) {
    const record = await readRecord(stream);
    if (record.type !== 0x15) {
      continue;
    }
    const alert = decryptFromClient(0x15, record.fragment, tlsState.cipherState);
    if (alert.length < 2) {
      throw new Error('Malformed alert during TLS shutdown');
    }
    const description = alert.readUInt8(1);
    if (description === 0x00) {
      if (stats) {
        stats.sawClientCloseNotify = true;
      }
      break;
    }
  }

  const closeNotify = Buffer.from([0x01, 0x00]);
  const encryptedCloseNotify = encryptForClient(0x15, closeNotify, tlsState.cipherState);
  await writeRecord(stream, 0x15, encryptedCloseNotify);
  if (stats) {
    stats.sentServerCloseNotify = true;
  }
}

async function handleConnection(socket, credentials, stats) {
  const stream = new ByteStream(socket);
  const tlsState = await completeServerHandshake(stream, credentials);

  let tlsActive = true;
  let loggedIn = false;
  const secureLineBuffer = { buffer: Buffer.alloc(0) };

  const sendLine = async (line) => {
    if (tlsActive) {
      await sendSecureLine(stream, tlsState, line);
    } else {
      await stream.write(`${line}\r\n`);
    }
  };

  await sendLine('220 Custom implicit FTPS server ready');

  while (true) {
    let line;
    try {
      line = tlsActive
        ? await readSecureLine(stream, tlsState, secureLineBuffer)
        : await stream.readLine();
    } catch (err) {
      if (err?.message === 'Socket closed') {
        return;
      }
      throw err;
    }

    const [command, ...rest] = line.trim().split(/\s+/);
    const arg = rest.join(' ');

    switch (command?.toUpperCase()) {
      case 'USER':
        await sendLine('331 User name okay, need password.');
        break;
      case 'PASS':
        loggedIn = true;
        await sendLine('230 User logged in, proceed.');
        break;
      case 'PBSZ':
        await sendLine('200 PBSZ set to 0.');
        break;
      case 'PROT':
        await sendLine(arg.toUpperCase() === 'C' ? '200 Protection level set to Clear.' : '200 Protection level set to Private.');
        break;
      case 'CCC':
        await sendLine('200 Command channel unprotected.');
        await performTlsShutdown(stream, tlsState, stats);
        tlsActive = false;
        break;
      case 'PWD':
        if (!loggedIn) {
          await sendLine('530 Not logged in.');
          break;
        }
        await sendLine('257 "/" is current directory');
        break;
      case 'QUIT':
        await sendLine('221 Service closing control connection.');
        socket.end();
        return;
      default:
        await sendLine('502 Command not implemented');
        break;
    }
  }
}

async function handleExplicitConnection(socket, credentials, stats) {
  const stream = new ByteStream(socket);
  let tlsState = null;
  let tlsActive = false;
  let loggedIn = false;
  const secureLineBuffer = { buffer: Buffer.alloc(0) };

  const sendLine = async (line) => {
    if (tlsActive) {
      await sendSecureLine(stream, tlsState, line);
    } else {
      await stream.write(`${line}\r\n`);
    }
  };

  await sendLine('220 Custom explicit FTPS server ready');

  while (true) {
    let line;
    try {
      line = tlsActive
        ? await readSecureLine(stream, tlsState, secureLineBuffer)
        : await stream.readLine();
    } catch (err) {
      if (err?.message === 'Socket closed') {
        return;
      }
      throw err;
    }

    const [command, ...rest] = line.trim().split(/\s+/);
    const arg = rest.join(' ');

    switch (command?.toUpperCase()) {
      case 'AUTH':
        if (arg.toUpperCase() !== 'TLS') {
          await sendLine('504 AUTH type not supported');
          break;
        }
        if (tlsActive) {
          await sendLine('503 Control channel already secured');
          break;
        }
        await sendLine('234 Proceed with negotiation.');
        tlsState = await completeServerHandshake(stream, credentials);
        tlsActive = true;
        break;
      case 'USER':
        await sendLine('331 User name okay, need password.');
        break;
      case 'PASS':
        loggedIn = true;
        await sendLine('230 User logged in, proceed.');
        break;
      case 'PBSZ':
        await sendLine('200 PBSZ set to 0.');
        break;
      case 'PROT':
        await sendLine(arg.toUpperCase() === 'C' ? '200 Protection level set to Clear.' : '200 Protection level set to Private.');
        break;
      case 'CCC':
        if (!tlsActive || !tlsState) {
          await sendLine('533 Command channel already clear.');
          break;
        }
        await sendLine('200 Command channel unprotected.');
        await performTlsShutdown(stream, tlsState, stats);
        tlsState = null;
        tlsActive = false;
        break;
      case 'PWD':
        if (!loggedIn) {
          await sendLine('530 Not logged in.');
          break;
        }
        await sendLine('257 "/" is current directory');
        break;
      case 'QUIT':
        await sendLine('221 Service closing control connection.');
        socket.end();
        return;
      default:
        await sendLine('502 Command not implemented');
        break;
    }
  }
}

async function createCustomImplicitFtpsServer(credentials) {
  if (!credentials?.key || !credentials?.cert) {
    throw new TypeError('createCustomImplicitFtpsServer requires key and cert');
  }

  const stats = {
    sawClientCloseNotify: false,
    sentServerCloseNotify: false,
  };

  const server = net.createServer((socket) => {
    handleConnection(socket, credentials, stats).catch(() => {
      socket.destroy();
    });
  });

  return await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Unable to determine listening address for custom FTPS server'));
        return;
      }

      server.off('error', reject);
      resolve({
        port: addr.port,
        getStats: () => ({ ...stats }),
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((err) => (err ? closeReject(err) : closeResolve()));
          }),
      });
    });
  });
}

async function createCustomExplicitFtpsServer(credentials) {
  if (!credentials?.key || !credentials?.cert) {
    throw new TypeError('createCustomExplicitFtpsServer requires key and cert');
  }

  const stats = {
    sawClientCloseNotify: false,
    sentServerCloseNotify: false,
  };

  const server = net.createServer((socket) => {
    handleExplicitConnection(socket, credentials, stats).catch(() => {
      socket.destroy();
    });
  });

  return await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Unable to determine listening address for custom FTPS server'));
        return;
      }

      server.off('error', reject);
      resolve({
        port: addr.port,
        getStats: () => ({ ...stats }),
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((err) => (err ? closeReject(err) : closeResolve()));
          }),
      });
    });
  });
}

module.exports = {
  createCustomImplicitFtpsServer,
  createCustomExplicitFtpsServer,
};
