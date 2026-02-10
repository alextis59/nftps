const test = require('node:test');
const assert = require('node:assert');
const { once } = require('node:events');
const tls = require('node:tls');
const { createTestTlsServer, TlsClient } = require('../src/index.js');
const { loadCertificateFixtures } = require('../support/testCertFixtures.js');

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

test('custom TLS client completes handshake and exchanges data', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert }, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});




test('custom TLS client emits handshake and application data logs in verbose mode', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert }, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });
  const logs = [];
  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    verbose: true,
    log: (line) => logs.push(line),
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  await client.readApplicationData();

  assert.ok(logs.some((line) => line.includes('starting TLS 1.2 handshake')));
  assert.ok(logs.some((line) => line.includes('received ServerHello')));
  assert.ok(logs.some((line) => line.includes('TLS handshake completed successfully')));
  assert.ok(logs.some((line) => line.includes('sent application data')));
  assert.ok(logs.some((line) => line.includes('received application data')));
});
test('custom TLS client supports TLS_RSA_WITH_AES_128_CBC_SHA256', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      ciphers: 'AES128-SHA256',
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    },
    (socket) => {
      socket.on('data', (chunk) => socket.write(chunk));
    },
  );

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});

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

  const server = await createTestTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert }, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });
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

test('server rejects malformed tls options', () => {
  assert.throws(
    () => createTestTlsServer({ key: undefined, cert: undefined }),
    /key/,
  );
});
