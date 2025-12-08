import test from 'node:test';
import assert from 'node:assert';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import tls from 'node:tls';
import { createTestTlsServer, TlsClient } from '../src/index.js';

const keyPath = new URL('../certs/server.key', import.meta.url);
const certPath = new URL('../certs/server.crt', import.meta.url);
const clientKeyPath = new URL('../certs/client.key', import.meta.url);
const clientCertPath = new URL('../certs/client.crt', import.meta.url);

async function loadCredentials() {
  const [key, cert] = await Promise.all([
    readFile(keyPath, 'utf8'),
    readFile(certPath, 'utf8'),
  ]);
  return { key, cert };
}

async function loadClientCredentials() {
  const [key, cert] = await Promise.all([
    readFile(clientKeyPath, 'utf8'),
    readFile(clientCertPath, 'utf8'),
  ]);
  return { key, cert };
}

test('node TLS client completes handshake and exchanges data', async (t) => {
  const creds = await loadCredentials();

  const server = await createTestTlsServer(creds, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [creds.cert],
  });

  t.after(async () => {
    client.destroy();
    await server.close();
  });

  await once(client, 'secureConnect');
  assert.strictEqual(client.authorized, true, 'self-signed CA should authorize connection');

  client.write('ping');
  const [response] = await once(client, 'data');
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('node TLS client presents a certificate when required', async (t) => {
  if (process.versions?.bun) {
    return;
  }

  const creds = await loadCredentials();
  const clientCreds = await loadClientCredentials();

  let serverAuthorized = false;
  const server = await createTestTlsServer(
    { ...creds, requestCert: true, ca: [creds.cert], rejectUnauthorized: true },
    (socket) => {
      const peer = socket.getPeerCertificate(true);
      serverAuthorized = peer?.subject?.CN === 'client';
      socket.on('data', (chunk) => socket.write(chunk));
    },
  );

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [creds.cert],
    cert: clientCreds.cert,
    key: clientCreds.key,
  });

  t.after(async () => {
    client.destroy();
    await server.close();
  });

  await once(client, 'secureConnect');
  assert.strictEqual(client.authorized, true, 'self-signed CA should authorize connection');
  assert.strictEqual(serverAuthorized, true, 'server should accept presented client certificate');

  client.write('ping');
  const [response] = await once(client, 'data');
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('custom TLS client completes handshake and exchanges data', async (t) => {
  const creds = await loadCredentials();

  const server = await createTestTlsServer(creds, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  assert.strictEqual(response.toString('utf8'), 'ping');
});

test('custom TLS client logs handshake events in verbose mode', async (t) => {
  const creds = await loadCredentials();
  const messages = [];

  const server = await createTestTlsServer(creds, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    verbose: true,
    logger: (msg) => messages.push(msg),
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  assert.ok(messages.some((msg) => msg.includes('ClientHello')), 'ClientHello should be logged');
  assert.ok(messages.some((msg) => msg.includes('ServerHello')), 'ServerHello should be logged');
  assert.ok(messages.some((msg) => msg.includes('TLS handshake complete')), 'handshake completion should be logged');
});

test('custom TLS client presents a certificate when required', async (t) => {
  const creds = await loadCredentials();
  const clientCreds = await loadClientCredentials();

  let serverAuthorized = false;
  const server = await createTestTlsServer(
    { ...creds, requestCert: true, ca: [creds.cert], rejectUnauthorized: true },
    (socket) => {
      const peer = socket.getPeerCertificate(true);
      serverAuthorized = peer?.subject?.CN === 'client';
      socket.on('data', (chunk) => socket.write(chunk));
    },
  );

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    clientCert: clientCreds.cert,
    clientKey: clientCreds.key,
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

test('server rejects malformed tls options', () => {
  assert.throws(
    () => createTestTlsServer({ key: undefined, cert: undefined }),
    /key/,
  );
});
