import test from 'node:test';
import assert from 'node:assert';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import tls from 'node:tls';
import { createTestTlsServer } from '../src/index.js';

const keyPath = new URL('../certs/server.key', import.meta.url);
const certPath = new URL('../certs/server.crt', import.meta.url);

async function loadCredentials() {
  const [key, cert] = await Promise.all([
    readFile(keyPath, 'utf8'),
    readFile(certPath, 'utf8'),
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

test('server rejects malformed tls options', async () => {
  await assert.rejects(
    () => createTestTlsServer({ key: undefined, cert: undefined }),
    /key/,
  );
});
