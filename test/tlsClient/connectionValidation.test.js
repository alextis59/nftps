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
});
