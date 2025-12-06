import test from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
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

async function createFtpsServer(credentials, { pasvAdvertisedHost = '127.0.0.1' } = {}) {
  const { key, cert } = credentials;
  const server = tls.createServer({
    key,
    cert,
    ciphers: 'AES128-SHA',
    honorCipherOrder: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  server.on('secureConnection', (socket) => handleConnection(socket, credentials, { pasvAdvertisedHost }));

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

async function createExplicitFtpsServer(credentials, { pasvAdvertisedHost = '127.0.0.1' } = {}) {
  const { key, cert } = credentials;
  const secureContext = tls.createSecureContext({
    key,
    cert,
    ciphers: 'AES128-SHA',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  const server = net.createServer();

  server.on('connection', (socket) =>
    handleExplicitConnection(socket, secureContext, credentials, { pasvAdvertisedHost }),
  );

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

async function createPassiveDataServer({ secure, credentials }) {
  const server = secure
    ? tls.createServer({
        ...credentials,
        ciphers: 'AES128-SHA',
        honorCipherOrder: true,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.2',
      })
    : net.createServer();

  let resolveSocket;
  const socketPromise = new Promise((resolve) => {
    resolveSocket = resolve;
  });

  const eventName = secure ? 'secureConnection' : 'connection';
  server.once(eventName, (dataSocket) => resolveSocket(dataSocket));

  const listening = await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Unable to determine passive server address'));
        return;
      }
      server.off('error', reject);
      resolve(addr);
    });
  });

  const close = () =>
    new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));

  return { socketPromise, port: listening.port, close };
}

function handleConnection(socket, credentials, { pasvAdvertisedHost }) {
  let loggedIn = false;
  let buffer = Buffer.alloc(0);
  let passiveServer = null;
  let dataProtection = 'P';

  const sendLine = (line) => socket.write(`${line}\r\n`);
  const cleanup = () => socket.destroy();

  const teardownPassive = async () => {
    if (passiveServer) {
      await passiveServer.close();
      passiveServer = null;
    }
  };

  const [pasvH1, pasvH2, pasvH3, pasvH4] = pasvAdvertisedHost.split('.');

  const processCommand = async (line) => {
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
        dataProtection = 'P';
        return;
      case 'PASV': {
        await teardownPassive();
        const { port, socketPromise, close } = await createPassiveDataServer({
          secure: dataProtection === 'P',
          credentials,
        });
        passiveServer = { socketPromise, close };
        const p1 = Math.floor(port / 256);
        const p2 = port % 256;
        sendLine(`227 Entering Passive Mode (${pasvH1},${pasvH2},${pasvH3},${pasvH4},${p1},${p2}).`);
        return;
      }
      case 'RETR': {
        if (!passiveServer) {
          sendLine('425 Use PASV first.');
          return;
        }
        const dataSocket = await passiveServer.socketPromise;
        sendLine('150 Opening data connection.');
        dataSocket.end('file-data-for-testing');
        dataSocket.once('close', async () => {
          await teardownPassive();
          sendLine('226 Transfer complete.');
        });
        return;
      }
      case 'ECHO': {
        if (!passiveServer) {
          sendLine('425 Use PASV first.');
          return;
        }
        const dataSocket = await passiveServer.socketPromise;
        sendLine('150 Opening data connection.');
        dataSocket.end(arg || '');
        dataSocket.once('close', async () => {
          await teardownPassive();
          sendLine('226 Echo complete.');
        });
        return;
      }
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
      processCommand(line).catch(cleanup);
    }
  };

  socket.on('data', onData);
  socket.once('error', cleanup);
  sendLine('220 Test FTPS server ready');
}

function handleExplicitConnection(socket, secureContext, credentials, { pasvAdvertisedHost }) {
  let loggedIn = false;
  let buffer = Buffer.alloc(0);
  let currentSocket = socket;
  let secureSocket = null;
  let usingTls = false;
  let passiveServer = null;
  let dataProtection = 'C';

  const sendLine = (line) => currentSocket.write(`${line}\r\n`);
  const cleanup = () => currentSocket.destroy();

  const teardownPassive = async () => {
    if (passiveServer) {
      await passiveServer.close();
      passiveServer = null;
    }
  };

  const [pasvH1, pasvH2, pasvH3, pasvH4] = pasvAdvertisedHost.split('.');

  const processCommand = (line) => {
    const [command, ...rest] = line.trim().split(/\s+/);
    const arg = rest.join(' ');

    switch (command?.toUpperCase()) {
      case 'AUTH': {
        sendLine('234 Proceed with negotiation.');
        if (usingTls) return;
        return;
      }
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
        dataProtection = arg?.toUpperCase() || 'C';
        sendLine(`200 Protection level set to ${dataProtection === 'P' ? 'Private' : 'Clear'}.`);
        return;
      case 'CCC':
        sendLine('200 Command channel unprotected.');
        if (usingTls && secureSocket) {
          secureSocket.removeAllListeners('data');
          currentSocket = socket;
          buffer = Buffer.alloc(0);
          usingTls = false;
          socket.on('data', onData);
        }
        return;
      case 'PASV': {
        return (async () => {
          await teardownPassive();
          const { port, socketPromise, close } = await createPassiveDataServer({
            secure: dataProtection === 'P',
            credentials,
          });
          passiveServer = { socketPromise, close };
          const p1 = Math.floor(port / 256);
          const p2 = port % 256;
          sendLine(`227 Entering Passive Mode (${pasvH1},${pasvH2},${pasvH3},${pasvH4},${p1},${p2}).`);
        })();
      }
      case 'RETR': {
        return (async () => {
          if (!passiveServer) {
            sendLine('425 Use PASV first.');
            return;
          }
          const dataSocket = await passiveServer.socketPromise;
          sendLine('150 Opening data connection.');
          dataSocket.end('file-data-for-testing');
          dataSocket.once('close', async () => {
            await teardownPassive();
            sendLine('226 Transfer complete.');
          });
        })();
      }
      case 'ECHO': {
        return (async () => {
          if (!passiveServer) {
            sendLine('425 Use PASV first.');
            return;
          }
          const dataSocket = await passiveServer.socketPromise;
          sendLine('150 Opening data connection.');
          dataSocket.end(arg || '');
          dataSocket.once('close', async () => {
            await teardownPassive();
            sendLine('226 Echo complete.');
          });
        })();
      }
      case 'PWD':
        if (!loggedIn) {
          sendLine('530 Not logged in.');
          return;
        }
        sendLine('257 "/" is current directory');
        return;
      case 'QUIT':
        sendLine('221 Service closing control connection.');
        currentSocket.end();
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
      Promise.resolve(processCommand(line)).catch(cleanup);
    }
  };

  socket.on('data', onData);
  socket.once('error', cleanup);
  sendLine('220 Explicit FTPS server ready');
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

function parsePassiveResponse(resp) {
  const match = resp.match(/\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)/);
  if (!match) {
    throw new Error(`Invalid PASV response: ${resp}`);
  }
  const host = match[1].replace(/,/g, '.');
  const port = Number(match[2]) * 256 + Number(match[3]);
  return { host, port };
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

test('node FTPS client retrieves data over passive mode', async (t) => {
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

  assert.match(await read(), /^220/);
  client.write('USER test\r\n');
  assert.match(await read(), /^331/);
  client.write('PASS password\r\n');
  assert.match(await read(), /^230/);
  client.write('PBSZ 0\r\n');
  assert.match(await read(), /^200/);
  client.write('PROT P\r\n');
  assert.match(await read(), /^200/);

  client.write('PASV\r\n');
  const pasvResp = await read();
  assert.match(pasvResp, /^227/);
  const { host, port } = parsePassiveResponse(pasvResp);

  const dataSocket = tls.connect({
    host,
    port,
    servername: 'localhost',
    ca: [creds.cert],
    ciphers: 'AES128-SHA',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });
  await once(dataSocket, 'secureConnect');

  const chunks = [];
  dataSocket.on('data', (chunk) => chunks.push(chunk));
  const dataEnd = once(dataSocket, 'end');

  client.write('RETR file.txt\r\n');
  assert.match(await read(), /^150/);
  await dataEnd;
  assert.match(await read(), /^226/);

  const body = Buffer.concat(chunks).toString('utf8');
  assert.strictEqual(body, 'file-data-for-testing');

  client.write('QUIT\r\n');
  assert.match(await read(), /^221/);
});

test('custom FTPS client negotiates and logs in', async (t) => {
  const creds = await loadCredentials();
  const server = await createFtpsServer(creds);

  const client = new FtpsClient({ host: '127.0.0.1', port: server.port, servername: 'localhost' });
  const received = [];
  const sent = [];

  client.on('data', (line) => received.push(line));
  client.on('command', (cmd) => sent.push(cmd));

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

  assert.deepStrictEqual(sent, ['USER test', 'PASS password', 'PBSZ 0', 'PROT P', 'PWD', 'QUIT']);
  assert.deepStrictEqual(received, [
    '220 Test FTPS server ready',
    '331 User name okay, need password.',
    '230 User logged in, proceed.',
    '200 PBSZ set to 0.',
    '200 Protection level set to Private.',
    '257 "/" is current directory',
    '221 Service closing control connection.',
  ]);
});

test('custom FTPS client performs data transfers over PASV', async (t) => {
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

  const fileData = await client.retrieveFile('file.txt');
  assert.strictEqual(fileData.toString('utf8'), 'file-data-for-testing');

  const echoed = await client.executeDataCommand('ECHO hello world');
  assert.strictEqual(echoed.toString('utf8'), 'hello world');

  await client.quit();
});

test('custom FTPS client can ignore advertised PASV address', async (t) => {
  const creds = await loadCredentials();
  const server = await createFtpsServer(creds, { pasvAdvertisedHost: '192.0.2.10' });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ignorePasvAddress: true,
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.connect();
  await client.login('test', 'password');
  await client.setProtectedDataChannel();

  const fileData = await client.retrieveFile('file.txt');
  assert.strictEqual(fileData.toString('utf8'), 'file-data-for-testing');

  await client.quit();
});

test('custom FTPS client upgrades, downgrades, and continues over cleartext', async (t) => {
  const creds = await loadCredentials();
  const server = await createExplicitFtpsServer(creds);

  const client = new FtpsClient({ host: '127.0.0.1', port: server.port, servername: 'localhost', secure: false });
  const sent = [];
  const received = [];

  client.on('command', (cmd) => sent.push(cmd));
  client.on('data', (line) => received.push(line));

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await client.connect();
  await client.upgradeControlChannel();
  await client.login('test', 'password');

  const pbszResp = await client.sendCommand('PBSZ 0');
  assert.match(pbszResp, /^200/);

  const protResp = await client.sendCommand('PROT C');
  assert.match(protResp, /^200/);

  const cccResp = await client.clearCommandChannel();
  assert.match(cccResp, /^200/);

  const pwdResp = await client.pwd();
  assert.match(pwdResp, /^257/);
  await client.quit();

  assert.deepStrictEqual(sent, [
    'AUTH TLS',
    'USER test',
    'PASS password',
    'PBSZ 0',
    'PROT C',
    'CCC',
    'PWD',
    'QUIT',
  ]);

  assert.deepStrictEqual(received, [
    '220 Explicit FTPS server ready',
    '234 Proceed with negotiation.',
    '331 User name okay, need password.',
    '230 User logged in, proceed.',
    '200 PBSZ set to 0.',
    '200 Protection level set to Clear.',
    '200 Command channel unprotected.',
    '257 "/" is current directory',
    '221 Service closing control connection.',
  ]);
});
