const test = require('node:test');
const assert = require('node:assert');
const {
  parseConnectionOptions,
  parseCompressionMethods,
  parseCiphers,
  parseClientHelloExtensions,
} = require('../../src/tlsClient/options.js');
const {
  SUPPORTED_CIPHER_SUITES,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
} = require('../../src/index.js');

test('parseCompressionMethods returns defaults and deduplicates configured methods', () => {
  assert.deepStrictEqual(parseCompressionMethods(undefined), [0x00]);
  assert.deepStrictEqual(parseCompressionMethods([0x00, 0x00, 0x01]), [0x00, 0x01]);
});

test('parseCiphers handles whitespace list and rejects empty effective cipher list', () => {
  assert.deepStrictEqual(parseCiphers(' AES128-SHA256 : AES128-SHA256 : AES128-SHA '), [
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA,
  ]);
  assert.throws(() => parseCiphers(' : '), /ciphers must include at least one cipher name/);
});

test('parseClientHelloExtensions supports disabling defaults and accepts Uint8Array extra data', () => {
  const parsed = parseClientHelloExtensions({
    serverName: false,
    signatureAlgorithms: false,
    extra: [
      { type: 0x0000, data: Uint8Array.from([]) },
      { type: 0x000d, data: Uint8Array.from([0x00, 0x00]) },
      { type: 0x1234, data: Uint8Array.from([0xaa]) },
    ],
  });

  assert.strictEqual(parsed.serverName, false);
  assert.strictEqual(parsed.signatureAlgorithms, null);
  assert.deepStrictEqual(parsed.extra.map((entry) => entry.type), [0x0000, 0x000d, 0x1234]);
  assert.ok(Buffer.isBuffer(parsed.extra[0].data));
});

test('parseClientHelloExtensions validates malformed signature and extra extension entries', () => {
  assert.throws(
    () => parseClientHelloExtensions({ signatureAlgorithms: [null] }),
    /extensions.signatureAlgorithms entries must be objects/,
  );
  assert.throws(
    () => parseClientHelloExtensions({ signatureAlgorithms: [{ hash: 0x04, signature: 256 }] }),
    /extensions.signatureAlgorithms\[\].signature must be an 8-bit integer/,
  );
  assert.throws(
    () => parseClientHelloExtensions({ extra: [null] }),
    /extensions.extra entries must be objects/,
  );
  assert.throws(
    () => parseClientHelloExtensions({ extra: [{ type: -1, data: Buffer.alloc(0) }] }),
    /extensions.extra\[\].type must be a 16-bit integer/,
  );
  assert.throws(
    () =>
      parseClientHelloExtensions({
        extra: [
          { type: 0x1234, data: Buffer.from([0x01]) },
          { type: 0x1234, data: Buffer.from([0x02]) },
        ],
      }),
    /Duplicate extension type 0x1234/,
  );
});

test('parseConnectionOptions includes defaults and normalized extension fields', () => {
  const options = parseConnectionOptions({
    servername: 'localhost',
    compressionMethods: [0x00, 0x00],
    extensions: {
      serverName: true,
      signatureAlgorithms: true,
      extra: [{ type: 0x1234, data: Uint8Array.from([0x01, 0x02]) }],
    },
  });

  assert.deepStrictEqual(options.cipherSuites, SUPPORTED_CIPHER_SUITES);
  assert.deepStrictEqual(options.compressionMethods, [0x00]);
  assert.strictEqual(options.extensions.serverName, true);
  assert.ok(Array.isArray(options.extensions.signatureAlgorithms));
  assert.ok(options.extensions.signatureAlgorithms.length > 0);
  assert.ok(Buffer.isBuffer(options.extensions.extra[0].data));
});
