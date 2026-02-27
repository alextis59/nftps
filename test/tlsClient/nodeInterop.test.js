const test = require('node:test');
const assert = require('node:assert');
const { once } = require('node:events');
const tls = require('node:tls');
const { createTestTlsServer, loadCertificateFixtures } = require('../../support/tlsClientTestHelpers.js');

test('node TLS client completes handshake and exchanges data', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert }, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });

  t.after(async () => {
    client.destroy();
    await server.close();
  });

  await once(client, 'secureConnect');
  assert.strictEqual(client.authorized, true, 'configured CA should authorize connection');

  client.write('ping');
  const [response] = await once(client, 'data');
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('node TLS client presents a certificate when required', async (t) => {
  if (process.versions?.bun) {
    return;
  }

  const fixtures = await loadCertificateFixtures();

  let resolveServerAuth;
  const serverAuth = new Promise((resolve) => {
    resolveServerAuth = resolve;
  });

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
      const accepted = socket.authorized && peer?.subject?.CN === 'ftps-client';
      resolveServerAuth(accepted);
      socket.on('data', (chunk) => socket.write(chunk));
    },
  );

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    cert: fixtures.clientCert,
    key: fixtures.clientKey,
  });

  t.after(async () => {
    client.destroy();
    await server.close();
  });

  await once(client, 'secureConnect');
  const serverAuthorized = await serverAuth;
  assert.strictEqual(client.authorized, true, 'configured CA should authorize connection');
  assert.strictEqual(serverAuthorized, true, 'server should accept presented client certificate');

  client.write('ping');
  const [response] = await once(client, 'data');
  assert.strictEqual(response.toString('utf8'), 'ping');
});
