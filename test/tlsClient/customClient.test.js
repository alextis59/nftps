const test = require('node:test');
const assert = require('node:assert');
const { TlsClient, createEchoTlsServer, loadCertificateFixtures } = require('../../support/tlsClientTestHelpers.js');
const {
  SUPPORTED_CIPHER_SUITES,
  CIPHER_SUITE_TO_OPENSSL_NAME,
  OPENSSL_CIPHER_NAME_TO_SUITE,
} = require('../../src/index.js');

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

for (const suiteId of SUPPORTED_CIPHER_SUITES) {
  const opensslName = CIPHER_SUITE_TO_OPENSSL_NAME[suiteId];

  test(`custom TLS client supports cipher suite 0x${suiteId.toString(16)} as sole offered suite`, async (t) => {
    const fixtures = await loadCertificateFixtures();

    const server = await createEchoTlsServer({
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      ciphers: opensslName,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    });

    const client = await TlsClient.connect({
      host: '127.0.0.1',
      port: server.port,
      servername: 'localhost',
      ca: [fixtures.caCert],
      cipherSuites: [suiteId],
    });

    t.after(async () => {
      await client.close();
      await server.close();
    });

    assert.strictEqual(client.selectedCipherSuite, suiteId);
    await client.sendApplicationData(Buffer.from('ping'));
    const response = await client.readApplicationData();
    assert.strictEqual(response.toString('utf8'), 'ping');
  });
}

for (const suiteId of SUPPORTED_CIPHER_SUITES) {
  const opensslName = CIPHER_SUITE_TO_OPENSSL_NAME[suiteId];

  test(`custom TLS client supports ciphers="${opensslName}" as sole offered suite`, async (t) => {
    const fixtures = await loadCertificateFixtures();

    const server = await createEchoTlsServer({
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      ciphers: opensslName,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    });

    const client = await TlsClient.connect({
      host: '127.0.0.1',
      port: server.port,
      servername: 'localhost',
      ca: [fixtures.caCert],
      ciphers: opensslName,
    });

    t.after(async () => {
      await client.close();
      await server.close();
    });

    assert.strictEqual(client.selectedCipherSuite, suiteId);
    await client.sendApplicationData(Buffer.from('ping'));
    const response = await client.readApplicationData();
    assert.strictEqual(response.toString('utf8'), 'ping');
  });
}

test('custom TLS client accepts minVersion/maxVersion range when TLSv1.2 is included', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createEchoTlsServer({
    key: fixtures.serverKey,
    cert: fixtures.serverCert,
    ciphers: 'AES128-SHA',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    minVersion: 'TLSv1.1',
    maxVersion: 'TLSv1.3',
    ciphers: 'AES128-SHA',
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  assert.strictEqual(client.selectedCipherSuite, OPENSSL_CIPHER_NAME_TO_SUITE['AES128-SHA']);
  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('custom TLS client accepts compressionMethods and extensions options', async (t) => {
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
    ciphers: 'AES128-SHA256',
    compressionMethods: [0x00],
    extensions: {
      serverName: false,
      signatureAlgorithms: [{ hash: 0x04, signature: 0x01 }],
      extra: [{ type: 0x1234, data: Buffer.from([0x01]) }],
    },
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  assert.strictEqual(client.selectedCipherSuite, OPENSSL_CIPHER_NAME_TO_SUITE['AES128-SHA256']);
  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});
