const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  createTestTlsServer,
  TlsClient,
  createEchoTlsServer,
  loadCertificateFixtures,
} = require('../../support/tlsClientTestHelpers.js');
const {
  parsePemCertificateChain,
  parsePrivateKey,
  parseCaCertificates,
  verifyServerCertificateChain,
  parseServerCertificate,
  extractLegacyPublicServerCert,
  ensureClientAuthMaterial,
} = require('../../src/tlsClient/certificates.js');

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

test('certificate helpers parse PEM values into expected structures', async () => {
  const fixtures = await loadCertificateFixtures();

  assert.deepStrictEqual(parsePemCertificateChain(undefined), []);
  const combinedChain = parsePemCertificateChain(`${fixtures.serverCert}\n${fixtures.caCert}`);
  assert.strictEqual(combinedChain.length, 2);

  assert.strictEqual(parsePrivateKey(undefined), undefined);
  assert.match(parsePrivateKey(Buffer.from(fixtures.clientKey)), /BEGIN .*PRIVATE KEY/);

  assert.strictEqual(parseCaCertificates(undefined), undefined);
  const caCertificates = parseCaCertificates([fixtures.caCert, Buffer.from(fixtures.wrongCaCert)]);
  assert.strictEqual(caCertificates.length, 2);
  assert.ok(caCertificates.every((cert) => cert instanceof crypto.X509Certificate));

  const serverPem = parseServerCertificate(combinedChain[0]);
  assert.match(serverPem, /BEGIN CERTIFICATE/);
  assert.strictEqual(extractLegacyPublicServerCert(combinedChain), serverPem);
});

test('certificate helpers reject malformed material and accept matching client auth', async () => {
  const fixtures = await loadCertificateFixtures();
  const clientChain = parsePemCertificateChain(fixtures.clientCert);
  const clientKey = parsePrivateKey(fixtures.clientKey);

  assert.throws(() => parsePemCertificateChain(123), /clientCert must be a string or Buffer/);
  assert.throws(
    () => parsePemCertificateChain('not a certificate'),
    /clientCert must contain at least one CERTIFICATE block/,
  );
  assert.throws(() => parseCaCertificates(123), /ca must be a string or Buffer/);
  assert.throws(() => parsePrivateKey(123), /clientKey must be a string or Buffer/);
  assert.throws(() => parseServerCertificate('nope'), /server certificate must be a Buffer/);
  assert.throws(() => extractLegacyPublicServerCert([]), /Server certificate chain is empty/);

  assert.doesNotThrow(() => ensureClientAuthMaterial([], undefined));
  assert.doesNotThrow(() => ensureClientAuthMaterial(clientChain, clientKey));
});

test('verifyServerCertificateChain supports direct trust and issuer lookup paths', async () => {
  const fixtures = await loadCertificateFixtures();
  const [serverDer] = parsePemCertificateChain(fixtures.serverCert);
  const [caDer] = parsePemCertificateChain(fixtures.caCert);
  const trustLeaf = new crypto.X509Certificate(fixtures.serverCert);
  const trustCa = new crypto.X509Certificate(fixtures.caCert);

  assert.doesNotThrow(() =>
    verifyServerCertificateChain({
      chainDer: [serverDer],
      hostname: 'localhost',
      caCertificates: [trustLeaf],
    }),
  );
  assert.doesNotThrow(() =>
    verifyServerCertificateChain({
      chainDer: [serverDer],
      hostname: 'localhost',
      caCertificates: [trustCa],
    }),
  );
  assert.doesNotThrow(() =>
    verifyServerCertificateChain({
      chainDer: [serverDer, caDer],
      hostname: 'localhost',
      caCertificates: [trustCa],
    }),
  );
  assert.doesNotThrow(() =>
    verifyServerCertificateChain({
      chainDer: [serverDer],
      caCertificates: [trustLeaf],
    }),
  );
});

test('verifyServerCertificateChain rejects empty trust, malformed candidates, and untrusted defaults', async () => {
  const fixtures = await loadCertificateFixtures();
  const [serverDer] = parsePemCertificateChain(fixtures.serverCert);

  assert.throws(
    () =>
      verifyServerCertificateChain({
        chainDer: [],
        hostname: 'localhost',
        caCertificates: [new crypto.X509Certificate(fixtures.caCert)],
      }),
    /Server did not present a certificate chain/,
  );
  assert.throws(
    () =>
      verifyServerCertificateChain({
        chainDer: [serverDer],
        hostname: 'localhost',
        caCertificates: [],
      }),
    /No trusted CA certificates available for server validation/,
  );
  assert.throws(
    () =>
      verifyServerCertificateChain({
        chainDer: [serverDer],
        hostname: 'localhost',
        caCertificates: [{ fingerprint256: 'bogus' }],
      }),
    /Server certificate chain is not signed by a trusted CA/,
  );
  assert.throws(
    () =>
      verifyServerCertificateChain({
        chainDer: [serverDer],
        hostname: 'localhost',
      }),
    /Server certificate chain is not signed by a trusted CA/,
  );
});
