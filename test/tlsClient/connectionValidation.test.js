const test = require('node:test');
const assert = require('node:assert');
const { TlsClient } = require('../../src/index.js');
const { loadCertificateFixtures } = require('../../support/testCertFixtures.js');

test('TlsClient.connect validates host, port, and servername', async () => {
  await assert.rejects(() => TlsClient.connect({ host: '', port: 21 }), /host must be a non-empty string/);
  await assert.rejects(() => TlsClient.connect({ host: 'localhost', port: 0 }), /port must be an integer between 1 and 65535/);
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, servername: '' }),
    /servername must be a non-empty string/,
  );
});

test('TlsClient.connect validates auth option types', async () => {
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, rejectUnauthorized: 'yes' }),
    /rejectUnauthorized must be a boolean/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, checkServerIdentity: 'not-fn' }),
    /checkServerIdentity must be a function/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, cipherSuites: '0x002f' }),
    /cipherSuites must be a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, cipherSuites: [] }),
    /cipherSuites must be a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, cipherSuites: ['0x002f'] }),
    /cipherSuites entries must be 16-bit integers/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, cipherSuites: [0x9999] }),
    /Unsupported cipher suite 0x9999/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, ciphers: 123 }),
    /ciphers must be a non-empty string/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, ciphers: '' }),
    /ciphers must be a non-empty string/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, ciphers: 'AES128-SHA:NOT-A-CIPHER' }),
    /Unsupported cipher name "NOT-A-CIPHER"/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, cipherSuites: [0x002f], ciphers: 'AES128-SHA' }),
    /Provide either cipherSuites or ciphers, not both/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, minVersion: 1.2 }),
    /minVersion must be a string/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, maxVersion: 1.2 }),
    /maxVersion must be a string/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, minVersion: 'TLSv2' }),
    /minVersion must be one of: TLSv1, TLSv1.1, TLSv1.2, TLSv1.3/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.2' }),
    /minVersion cannot be greater than maxVersion/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, minVersion: 'TLSv1', maxVersion: 'TLSv1.1' }),
    /only supports TLSv1.2; minVersion\/maxVersion must include TLSv1.2/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, compressionMethods: 'null' }),
    /compressionMethods must be a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, compressionMethods: [] }),
    /compressionMethods must be a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, compressionMethods: [0, 256] }),
    /compressionMethods entries must be 8-bit integers/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: [] }),
    /extensions must be an object/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { serverName: 'yes' } }),
    /extensions.serverName must be a boolean/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { signatureAlgorithms: [] } }),
    /extensions.signatureAlgorithms must be false, true, or a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { signatureAlgorithms: [{ hash: 256, signature: 1 }] } }),
    /extensions.signatureAlgorithms\[\].hash must be an 8-bit integer/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { signatureAlgorithms: [{ hash: 4, signature: 256 }] } }),
    /extensions.signatureAlgorithms\[\].signature must be an 8-bit integer/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { extra: 'nope' } }),
    /extensions.extra must be an array/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { extra: [null] } }),
    /extensions.extra entries must be objects/,
  );
  await assert.rejects(
    () => TlsClient.connect({ host: 'localhost', port: 21, extensions: { extra: [{ type: -1, data: Buffer.alloc(0) }] } }),
    /extensions.extra\[\].type must be a 16-bit integer/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        extensions: {
          serverName: true,
          extra: [{ type: 0x0000, data: Buffer.alloc(0) }],
        },
      }),
    /Duplicate extension type 0x0000/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        extensions: {
          signatureAlgorithms: true,
          extra: [{ type: 0x000d, data: Buffer.alloc(0) }],
        },
      }),
    /Duplicate extension type 0x000d/,
  );
  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        extensions: {
          serverName: false,
          signatureAlgorithms: false,
          extra: [
            { type: 0x1234, data: Buffer.from([0x01]) },
            { type: 0x1234, data: Buffer.from([0x02]) },
          ],
        },
      }),
    /Duplicate extension type 0x1234/,
  );
});

test('TlsClient.connect validates client certificate material combinations', async () => {
  const fixtures = await loadCertificateFixtures();

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        clientCert: fixtures.clientCert,
      }),
    /clientKey is required when clientCert is provided/,
  );

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        clientKey: fixtures.clientKey,
      }),
    /clientCert is required when clientKey is provided/,
  );

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: 'localhost',
        port: 21,
        clientCert: fixtures.clientCert,
        clientKey: fixtures.serverKey,
      }),
    /clientCert and clientKey do not match/,
  );
});

test('TlsClient.fromExistingSocket validates socket and options before handshake', async () => {
  await assert.rejects(
    () => TlsClient.fromExistingSocket(null),
    /fromExistingSocket requires an active socket/,
  );

  const fakeSocket = { write() {} };

  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { servername: '' }),
    /servername must be a non-empty string/,
  );

  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { checkServerIdentity: 'nope' }),
    /checkServerIdentity must be a function/,
  );
  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { cipherSuites: [] }),
    /cipherSuites must be a non-empty array/,
  );
  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { ciphers: 'NOT-A-CIPHER' }),
    /Unsupported cipher name "NOT-A-CIPHER"/,
  );
  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }),
    /only supports TLSv1.2; minVersion\/maxVersion must include TLSv1.2/,
  );
  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { compressionMethods: [256] }),
    /compressionMethods entries must be 8-bit integers/,
  );
  await assert.rejects(
    () => TlsClient.fromExistingSocket(fakeSocket, { extensions: { extra: [{ type: 1, data: 'abc' }] } }),
    /extensions.extra\[\].data must be a Buffer or Uint8Array/,
  );
});
