const test = require('node:test');
const assert = require('node:assert');
const {
  createTestTlsServer,
  TlsClient,
  createEchoTlsServer,
  loadCertificateFixtures,
} = require('../../support/tlsClientTestHelpers.js');

test('custom TLS client presents a certificate when required', async (t) => {
  const fixtures = await loadCertificateFixtures();

  let serverAuthorized = false;
  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      requestCert: true,
      ca: [fixtures.caCert],
      rejectUnauthorized: true,
    },
    (socket) => {
      const peer = socket.getPeerCertificate(true);
      serverAuthorized = socket.authorized && peer?.subject?.CN === 'ftps-client';
      socket.on('data', (chunk) => socket.write(chunk));
    },
  );

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    clientCert: fixtures.clientCert,
    clientKey: fixtures.clientKey,
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(serverAuthorized, true, 'server should accept presented client certificate');
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('custom TLS client rejects server with untrusted CA', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });
  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'localhost',
        ca: [fixtures.wrongCaCert],
      }),
    /trusted CA/i,
  );
});

test('custom TLS client rejects server hostname mismatch', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });
  t.after(async () => {
    await server.close();
  });

  await assert.rejects(
    () =>
      TlsClient.connect({
        host: '127.0.0.1',
        port: server.port,
        servername: 'not-localhost',
        ca: [fixtures.caCert],
      }),
    /does not match certificate/,
  );
});

test('custom TLS client can skip CA validation when rejectUnauthorized is false', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createEchoTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });
  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.wrongCaCert],
    rejectUnauthorized: false,
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});
