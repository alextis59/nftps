const test = require('node:test');
const assert = require('node:assert');
const { TlsClient, createEchoTlsServer, loadCertificateFixtures } = require('../../support/tlsClientTestHelpers.js');

test('custom TLS client completes handshake and exchanges data', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createEchoTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });

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

  const server = await createEchoTlsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });
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

  const server = await createEchoTlsServer({
    key: fixtures.serverKey,
    cert: fixtures.serverCert,
    ciphers: 'AES128-SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
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
