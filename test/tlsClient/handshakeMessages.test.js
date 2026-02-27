const test = require('node:test');
const assert = require('node:assert');
const { buildClientHello } = require('../../src/tlsClient/handshakeMessages.js');
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
