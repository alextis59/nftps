const test = require('node:test');
const assert = require('node:assert');
const tls = require('node:tls');
const net = require('node:net');
const { once } = require('node:events');
const { FtpsClient } = require('../src/index.js');
const {
  createCustomImplicitFtpsServer,
  createCustomExplicitFtpsServer,
} = require('../support/customImplicitFtpsServer.js');
const { loadCertificateFixtures } = require('../support/testCertFixtures.js');

async function createFtpsServer(credentials, onSecureConnection = () => {}) {
  const { key, cert, ...rest } = credentials;
  const server = tls.createServer({
    key,
    cert,
    ...rest,
    ciphers: 'AES128-SHA',
    honorCipherOrder: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
  });

  server.on('secureConnection', (socket) => {
    onSecureConnection(socket);
    handleConnection(socket);
  });

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

async function withTimeout(promise, label, ms = 4000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Timeout while waiting for ${label}`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test('node FTPS client negotiates and logs in', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createFtpsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });

  const client = tls.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
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
  const fixtures = await loadCertificateFixtures();
  const server = await createFtpsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });
  const received = [];
  const sent = [];

  client.on('data', (line) => received.push(line));
  client.on('command', (cmd) => sent.push(cmd));

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'connect and implicit TLS handshake');
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

test('custom FTPS client downgrades to clear TCP after explicit TLS shutdown', { timeout: 6000 }, async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createCustomImplicitFtpsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    secure: true,
    ca: [fixtures.caCert],
  });
  const sent = [];
  const received = [];

  client.on('command', (cmd) => sent.push(cmd));
  client.on('data', (line) => received.push(line));

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'connect and implicit TLS handshake');
  await withTimeout(client.login('test', 'password'), 'login');
  const cccResp = await withTimeout(client.clearCommandChannel(), 'CCC downgrade');
  assert.match(cccResp, /^200/);
  assert.strictEqual(client.secure, false, 'client should switch to clear control channel');
  assert.strictEqual(client.tlsClient, null, 'TLS client should be detached after downgrade');

  const pwdResp = await withTimeout(client.pwd(), 'PWD in clear mode');
  assert.match(pwdResp, /^257/);
  await withTimeout(client.quit(), 'QUIT in clear mode');
  const shutdownStats = server.getStats();
  assert.strictEqual(shutdownStats.sawClientCloseNotify, true, 'server should receive client close_notify');
  assert.strictEqual(shutdownStats.sentServerCloseNotify, true, 'server should send server close_notify');

  assert.deepStrictEqual(sent, [
    'USER test',
    'PASS password',
    'CCC',
    'PWD',
    'QUIT',
  ]);

  assert.deepStrictEqual(received, [
    '220 Custom implicit FTPS server ready',
    '331 User name okay, need password.',
    '230 User logged in, proceed.',
    '200 Command channel unprotected.',
    '257 "/" is current directory',
    '221 Service closing control connection.',
  ]);
});

test('custom FTPS client upgrades with AUTH TLS then downgrades to clear TCP', { timeout: 8000 }, async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createCustomExplicitFtpsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    secure: false,
    ca: [fixtures.caCert],
  });
  const sent = [];
  const received = [];

  client.on('command', (cmd) => sent.push(cmd));
  client.on('data', (line) => received.push(line));

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'plain FTP connect');
  await withTimeout(client.upgradeControlChannel(), 'AUTH TLS upgrade');
  assert.strictEqual(client.secure, true, 'client should switch to TLS after AUTH TLS');
  assert.ok(client.tlsClient, 'TLS client should be present after upgrade');

  await withTimeout(client.login('test', 'password'), 'login over TLS');
  const pbszResp = await withTimeout(client.sendCommand('PBSZ 0'), 'PBSZ over TLS');
  assert.match(pbszResp, /^200/);
  const protResp = await withTimeout(client.sendCommand('PROT C'), 'PROT C over TLS');
  assert.match(protResp, /^200/);

  const cccResp = await withTimeout(client.clearCommandChannel(), 'CCC downgrade');
  assert.match(cccResp, /^200/);
  assert.strictEqual(client.secure, false, 'client should downgrade to clear channel after CCC');
  assert.strictEqual(client.tlsClient, null, 'TLS client should be detached after downgrade');

  const pwdResp = await withTimeout(client.pwd(), 'PWD in clear mode after downgrade');
  assert.match(pwdResp, /^257/);
  await withTimeout(client.quit(), 'QUIT in clear mode after downgrade');

  const shutdownStats = server.getStats();
  assert.strictEqual(shutdownStats.sawClientCloseNotify, true, 'server should receive client close_notify');
  assert.strictEqual(shutdownStats.sentServerCloseNotify, true, 'server should send server close_notify');

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
    '220 Custom explicit FTPS server ready',
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

test('custom FTPS client presents client certificate when required', async (t) => {
  const fixtures = await loadCertificateFixtures();

  let resolveServerAuth;
  const serverAuth = new Promise((resolve) => {
    resolveServerAuth = resolve;
  });

  const server = await createFtpsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      requestCert: true,
      ca: [fixtures.caCert],
      rejectUnauthorized: true,
    },
    (socket) => {
      const peer = socket.getPeerCertificate(true);
      resolveServerAuth(socket.authorized && peer?.subject?.CN === 'ftps-client');
    },
  );

  const client = new FtpsClient({
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

  await withTimeout(client.connect(), 'connect over TLS with client certificate');
  await withTimeout(client.login('test', 'password'), 'login');
  const serverAuthorized = await serverAuth;
  assert.strictEqual(serverAuthorized, true, 'server should accept the client certificate');
  await withTimeout(client.quit(), 'quit');
});

test('custom FTPS client rejects server with untrusted CA', async (t) => {
  const fixtures = await loadCertificateFixtures();

  const server = await createFtpsServer({ key: fixtures.serverKey, cert: fixtures.serverCert });
  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.wrongCaCert],
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await assert.rejects(
    () => withTimeout(client.connect(), 'connect with wrong CA'),
    /trusted CA/i,
  );
});

test('custom FTPS client parses PASV and can ignore server-advertised address', async (t) => {
  const dataServer = net.createServer();
  await new Promise((resolve, reject) => {
    dataServer.once('error', reject);
    dataServer.listen(0, '127.0.0.1', resolve);
  });
  const dataAddress = dataServer.address();
  if (!dataAddress || typeof dataAddress === 'string') {
    throw new Error('Unable to determine passive data server address');
  }

  const p1 = Math.floor(dataAddress.port / 256);
  const p2 = dataAddress.port % 256;

  const controlServer = net.createServer((socket) => {
    socket.write('220 FTP ready\r\n');
    socket.on('data', (chunk) => {
      const input = chunk.toString('utf8');
      if (input.includes('PASV')) {
        socket.write(`227 Entering Passive Mode (10,0,0,1,${p1},${p2})\r\n`);
      }
      if (input.includes('QUIT')) {
        socket.write('221 Goodbye\r\n');
        socket.end();
      }
    });
  });

  await new Promise((resolve, reject) => {
    controlServer.once('error', reject);
    controlServer.listen(0, '127.0.0.1', resolve);
  });
  const controlAddress = controlServer.address();
  if (!controlAddress || typeof controlAddress === 'string') {
    throw new Error('Unable to determine FTP control server address');
  }

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: controlAddress.port,
    secure: false,
    ignorePasvAddress: true,
  });

  t.after(async () => {
    await client.close();
    await new Promise((resolve) => controlServer.close(resolve));
    await new Promise((resolve) => dataServer.close(resolve));
  });

  await client.connect();

  const endpointWithDefaultIgnore = await client.enterPassiveMode();
  assert.deepStrictEqual(endpointWithDefaultIgnore, { host: '127.0.0.1', port: dataAddress.port });

  const endpointWithoutIgnore = await client.enterPassiveMode({ ignoreAddress: false });
  assert.deepStrictEqual(endpointWithoutIgnore, { host: '10.0.0.1', port: dataAddress.port });

  const accepted = once(dataServer, 'connection');
  const dataSocket = await client.openPassiveDataSocket();
  const [acceptedSocket] = await accepted;

  assert.strictEqual(dataSocket.remoteAddress, '127.0.0.1');
  acceptedSocket.destroy();
  dataSocket.destroy();

  await client.quit();
});
