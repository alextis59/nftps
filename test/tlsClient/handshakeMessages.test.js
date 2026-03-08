const test = require('node:test');
const assert = require('node:assert');
const {
  buildClientHello,
  parseServerHello,
  parseCertificate,
  parseCertificateRequest,
  buildClientCertificate,
  buildCertificateVerify,
  parseFinishedHandshake,
} = require('../../src/tlsClient/handshakeMessages.js');
const {
  TLS_VERSION_1_2,
  SUPPORTED_CIPHER_SUITES,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
} = require('../../src/index.js');

function parseClientHello(handshake) {
  assert.strictEqual(handshake.readUInt8(0), 0x01);
  const bodyLength = handshake.readUIntBE(1, 3);
  const body = handshake.subarray(4, 4 + bodyLength);

  let offset = 0;
  const version = body.readUInt16BE(offset);
  offset += 2;
  offset += 32; // random
  const sessionIdLen = body.readUInt8(offset);
  offset += 1 + sessionIdLen;

  const cipherSuitesLen = body.readUInt16BE(offset);
  offset += 2;
  const cipherSuites = [];
  for (let i = 0; i < cipherSuitesLen; i += 2) {
    cipherSuites.push(body.readUInt16BE(offset + i));
  }
  offset += cipherSuitesLen;

  const compressionMethodsLen = body.readUInt8(offset);
  offset += 1;
  const compressionMethods = [...body.subarray(offset, offset + compressionMethodsLen)];
  offset += compressionMethodsLen;

  const extensionsLen = body.readUInt16BE(offset);
  offset += 2;
  const extensionsEnd = offset + extensionsLen;
  const extensions = new Map();
  while (offset + 4 <= extensionsEnd) {
    const type = body.readUInt16BE(offset);
    offset += 2;
    const len = body.readUInt16BE(offset);
    offset += 2;
    const data = body.subarray(offset, offset + len);
    offset += len;
    extensions.set(type, data);
  }
  assert.strictEqual(offset, extensionsEnd);

  return {
    version,
    cipherSuites,
    compressionMethods,
    extensions,
  };
}

function parseSignatureAlgorithmsExtension(data) {
  const listLength = data.readUInt16BE(0);
  const out = [];
  for (let i = 0; i < listLength; i += 2) {
    out.push({ hash: data.readUInt8(2 + i), signature: data.readUInt8(3 + i) });
  }
  return out;
}

test('buildClientHello emits TLS 1.2 defaults including null compression and standard extensions', () => {
  const { handshake } = buildClientHello('localhost');
  const parsed = parseClientHello(handshake);

  assert.strictEqual(parsed.version, TLS_VERSION_1_2);
  assert.deepStrictEqual(parsed.compressionMethods, [0x00]);
  assert.deepStrictEqual(parsed.cipherSuites, SUPPORTED_CIPHER_SUITES);
  assert.ok(parsed.extensions.has(0x0000), 'expected server_name extension');
  assert.ok(parsed.extensions.has(0x000d), 'expected signature_algorithms extension');
  assert.deepStrictEqual(parseSignatureAlgorithmsExtension(parsed.extensions.get(0x000d)), [
    { hash: 0x04, signature: 0x01 },
    { hash: 0x02, signature: 0x01 },
  ]);
});

test('buildClientHello accepts custom compression methods and extensions', () => {
  const { handshake } = buildClientHello(
    'localhost',
    [TLS_RSA_WITH_AES_128_CBC_SHA],
    [0x00, 0x01],
    {
      serverName: false,
      signatureAlgorithms: [{ hash: 0x04, signature: 0x01 }],
      extra: [{ type: 0x1234, data: Buffer.from([0xaa, 0xbb]) }],
    },
  );

  const parsed = parseClientHello(handshake);
  assert.deepStrictEqual(parsed.cipherSuites, [TLS_RSA_WITH_AES_128_CBC_SHA]);
  assert.deepStrictEqual(parsed.compressionMethods, [0x00, 0x01]);
  assert.strictEqual(parsed.extensions.has(0x0000), false);
  assert.deepStrictEqual(parseSignatureAlgorithmsExtension(parsed.extensions.get(0x000d)), [
    { hash: 0x04, signature: 0x01 },
  ]);
  assert.ok(parsed.extensions.get(0x1234).equals(Buffer.from([0xaa, 0xbb])));
});

test('buildClientHello omits signature_algorithms when explicitly disabled', () => {
  const { handshake } = buildClientHello(
    'localhost',
    [TLS_RSA_WITH_AES_128_CBC_SHA256],
    [0x00],
    {
      serverName: true,
      signatureAlgorithms: false,
      extra: [],
    },
  );

  const parsed = parseClientHello(handshake);
  assert.strictEqual(parsed.extensions.has(0x0000), true);
  assert.strictEqual(parsed.extensions.has(0x000d), false);
});

test('buildClientHello can emit only custom extensions', () => {
  const { handshake } = buildClientHello(
    'localhost',
    [TLS_RSA_WITH_AES_128_CBC_SHA],
    [0x00],
    {
      serverName: false,
      signatureAlgorithms: false,
      extra: [{ type: 0x1234, data: Buffer.from([0x42]) }],
    },
  );

  const parsed = parseClientHello(handshake);
  assert.strictEqual(parsed.extensions.size, 1);
  assert.ok(parsed.extensions.get(0x1234).equals(Buffer.from([0x42])));
});

test('buildClientHello validates required client hello inputs', () => {
  assert.throws(() => buildClientHello('localhost', []), /offeredCipherSuites must be a non-empty array/);
  assert.throws(
    () => buildClientHello('localhost', [TLS_RSA_WITH_AES_128_CBC_SHA], []),
    /compressionMethods must be a non-empty array/,
  );
  assert.throws(
    () => buildClientHello('localhost', [TLS_RSA_WITH_AES_128_CBC_SHA], [0x00], null),
    /extensionsConfig must be an object/,
  );
});

test('parseServerHello rejects trailing bytes after extensions', () => {
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x11),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x2f]),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x00, 0xde]),
  ]);

  assert.throws(() => parseServerHello(body), /Invalid ServerHello\.extensions length/);
});

test('parseServerHello validates truncated randoms and malformed extensions', () => {
  assert.throws(
    () => parseServerHello(Buffer.concat([Buffer.from([0x03, 0x03]), Buffer.alloc(31)])),
    /Invalid ServerHello\.random length/,
  );

  const missingExtensionsLength = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x11),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x2f]),
    Buffer.from([0x00]),
    Buffer.from([0xaa]),
  ]);
  assert.throws(
    () => parseServerHello(missingExtensionsLength),
    /Invalid ServerHello\.extensions length/,
  );

  const invalidExtensionLength = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x22),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x2f]),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x06, 0x12, 0x34, 0x00, 0x03, 0xaa, 0xbb]),
  ]);
  assert.throws(
    () => parseServerHello(invalidExtensionLength),
    /Invalid ServerHello extension length/,
  );
});

test('parseCertificate rejects trailing bytes after certificate list', () => {
  const cert = Buffer.from([0x30, 0x82, 0x01, 0x00]);
  const certLen = Buffer.alloc(3);
  certLen.writeUIntBE(cert.length, 0, 3);
  const certificateList = Buffer.concat([certLen, cert]);
  const listLen = Buffer.alloc(3);
  listLen.writeUIntBE(certificateList.length, 0, 3);
  const body = Buffer.concat([listLen, certificateList, Buffer.from([0xaa])]);

  assert.throws(() => parseCertificate(body), /Invalid total certificate length/);
});

test('parseCertificate validates message length, entry sizes, and empty chains', () => {
  assert.throws(() => parseCertificate(Buffer.alloc(2)), /Certificate message too short/);
  assert.throws(
    () => parseCertificate(Buffer.from([0x00, 0x00, 0x03, 0x00, 0x00, 0x04])),
    /Invalid certificate entry length/,
  );
  assert.throws(
    () => parseCertificate(Buffer.from([0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0xaa, 0xbb])),
    /Trailing bytes in Certificate message/,
  );
  assert.throws(() => parseCertificate(Buffer.from([0x00, 0x00, 0x00])), /Empty certificate chain/);
});

test('buildClientCertificate validates certificate chain entries', () => {
  assert.throws(
    () => buildClientCertificate([]),
    /Client certificate chain cannot be empty when building Certificate message/,
  );
  assert.throws(
    () => buildClientCertificate([Buffer.from([0x01]), 'not-a-buffer']),
    /Certificate entries must be Buffers/,
  );
});

test('buildCertificateVerify and parseFinishedHandshake validate required inputs', () => {
  assert.throws(
    () => buildCertificateVerify(null, [Buffer.from('handshake')]),
    /Private key required to build CertificateVerify/,
  );
  assert.throws(() => parseFinishedHandshake(Buffer.from([0x14, 0x00, 0x00])), /Finished handshake too short/);
  assert.throws(
    () => parseFinishedHandshake(Buffer.from([0x0e, 0x00, 0x00, 0x00])),
    /Unexpected handshake type 14 in Finished message/,
  );
  assert.throws(
    () => parseFinishedHandshake(Buffer.from([0x14, 0x00, 0x00, 0x04, 0xaa, 0xbb])),
    /Incomplete Finished verify_data/,
  );
});

test('parseCertificateRequest rejects trailing bytes after distinguished names', () => {
  const body = Buffer.from([
    0x01,
    0x01,
    0x00, 0x02,
    0x04, 0x01,
    0x00, 0x00,
    0xaa,
  ]);

  assert.throws(() => parseCertificateRequest(body), /Trailing bytes in CertificateRequest/);
});

test('parseCertificateRequest validates each variable-length field', () => {
  assert.throws(() => parseCertificateRequest(Buffer.alloc(0)), /CertificateRequest too short/);
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x02, 0x01])),
    /Invalid certificate_types length in CertificateRequest/,
  );
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x00])),
    /CertificateRequest missing signature_algorithms length/,
  );
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x00, 0x00, 0x03, 0x04, 0x01])),
    /Invalid signature_algorithms length in CertificateRequest/,
  );
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x00, 0x00, 0x01, 0x04, 0x00, 0x00])),
    /Trailing bytes in CertificateRequest signature_algorithms/,
  );
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x00, 0x00, 0x00])),
    /CertificateRequest missing distinguished_names length/,
  );
  assert.throws(
    () => parseCertificateRequest(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x02, 0xaa])),
    /Invalid distinguished_names length in CertificateRequest/,
  );
});
