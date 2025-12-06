import test from 'node:test';
import assert from 'node:assert';
import tls from 'node:tls';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { FtpsClient } from '../src/index.js';

const keyPath = new URL('../certs/server.key', import.meta.url);
const certPath = new URL('../certs/server.crt', import.meta.url);

async function loadCredentials() {
  const [key, cert] = await Promise.all([
    readFile(keyPath, 'utf8'),
    readFile(certPath, 'utf8'),
  ]);
  return { key, cert };
}

async function createFtpsServer(credentials) {
  const { key, cert } = credentials;
  const server = tls.createServer({
    key,
    cert,
    ciphers: 'AES128-SHA',
    honorCipherOrder: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  server.on('secureConnection', (socket) => handleConnection(socket));

  return await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Unable to determine FTPS server address'));
        return;
      }

      server.off('error', reject);
      resolve({
        port: addr.port,
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((err) => (err ? closeReject(err) : closeResolve()));
          }),
      });
    });
  });
}

function handleConnection(socket) {
  let loggedIn = false;
  let buffer = Buffer.alloc(0);

  const sendLine = (line) => socket.write(`${line}\r\n`);
  const cleanup = () => socket.destroy();

  const processCommand = (line) => {
    const [command, ...rest] = line.trim().split(/\s+/);
    const arg = rest.join(' ');

    switch (command?.toUpperCase()) {
      case 'AUTH':
        sendLine('502 AUTH not needed on implicit FTPS connection');
        return;
      case 'USER':
        sendLine('331 User name okay, need password.');
        return;
      case 'PASS':
        loggedIn = true;
        sendLine('230 User logged in, proceed.');
        return;
      case 'PBSZ':
        sendLine('200 PBSZ set to 0.');
        return;
      case 'PROT':
        sendLine('200 Protection level set to Private.');
        return;
      case 'PWD':
        if (!loggedIn) {
          sendLine('530 Not logged in.');
          return;
        }
        sendLine('257 "/" is current directory');
        return;
      case 'QUIT':
        sendLine('221 Service closing control connection.');
        socket.end();
        return;
      default:
        sendLine('502 Command not implemented');
    }
  };

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const idx = buffer.indexOf(0x0a);
      if (idx === -1) break;
      const line = buffer.subarray(0, idx + 1).toString('utf8').replace(/\r?\n$/, '');
      buffer = buffer.subarray(idx + 1);
      processCommand(line);
    }
  };

  socket.on('data', onData);
  socket.once('error', cleanup);
  sendLine('220 Test FTPS server ready');
}

function createLineReader(stream) {
  let buf = Buffer.alloc(0);
  return async () => {
    while (true) {
      const idx = buf.indexOf(0x0a);
      if (idx !== -1) {
        const line = buf.subarray(0, idx + 1);
        buf = buf.subarray(idx + 1);
        return line.toString('utf8').replace(/\r?\n$/, '');
      }
      const [chunk] = await once(stream, 'data');
      buf = Buffer.concat([buf, chunk]);
    }
  };
}

test('node FTPS client negotiates and logs in', async (t) => {
  const creds = await loadCredentials();
  const server = await createFtpsServer(creds);

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [creds.cert],
    ciphers: 'AES128-SHA',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  t.after(async () => {
    client.destroy();
    await server.close();
  });

  await once(client, 'secureConnect');
  const read = createLineReader(client);

  const greeting = await read();
  assert.match(greeting, /^220/);

  client.write('USER test\r\n');
  const userResp = await read();
  assert.match(userResp, /^331/);

  client.write('PASS password\r\n');
  const passResp = await read();
  assert.match(passResp, /^230/);

  client.write('PBSZ 0\r\n');
  const pbszResp = await read();
  assert.match(pbszResp, /^200/);

  client.write('PROT P\r\n');
  const protResp = await read();
  assert.match(protResp, /^200/);

  client.write('PWD\r\n');
  const pwdResp = await read();
  assert.match(pwdResp, /^257/);

  client.write('QUIT\r\n');
  const quitResp = await read();
  assert.match(quitResp, /^221/);
});

test('custom FTPS client negotiates and logs in', async (t) => {
  const creds = await loadCredentials();
  const server = await createFtpsServer(creds);

  const client = new FtpsClient({ host: '127.0.0.1', port: server.port, servername: 'localhost' });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.connect();
  await client.login('test', 'password');
  await client.setProtectedDataChannel();
  const pwdResp = await client.pwd();
  assert.match(pwdResp, /^257/);
  await client.quit();
});
