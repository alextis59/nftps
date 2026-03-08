const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');

const { FtpsClient } = require('../src/index.js');
const { createTestTlsServer, loadCertificateFixtures } = require('../support/tlsClientTestHelpers.js');

function attachFtpControlHandler(socket, { authReply = '502 AUTH not needed on implicit FTPS connection' } = {}) {
  let loggedIn = false;
  let buffer = Buffer.alloc(0);

  const sendLine = (line) => socket.write(`${line}\r\n`);
  const cleanup = () => socket.destroy();

  const processCommand = (line) => {
    const [command, ...rest] = line.trim().split(/\s+/);
    const arg = rest.join(' ');

    switch (command?.toUpperCase()) {
      case 'AUTH':
        if (arg.toUpperCase() === 'TLS') {
          sendLine(authReply);
          return;
        }
        sendLine('502 Only AUTH TLS is supported');
        return;
      case 'USER':
        sendLine('331 User name okay, need password.');
        return;
      case 'PASS':
        loggedIn = true;
        sendLine('230 User logged in, proceed.');
        return;
      case 'CCC':
        sendLine('200 Command channel unprotected.');
        return;
      case 'PWD':
        if (!loggedIn) {
          sendLine('530 Not logged in.');
          return;
        }
        sendLine('257 "/" is current directory');
        return;
      case 'QUIT':
        sendLine('221 Goodbye.');
        socket.end();
        return;
      default:
        sendLine('502 Command not implemented');
    }
  };

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const newlineIndex = buffer.indexOf(0x0a);
      if (newlineIndex === -1) {
        break;
      }

      const line = buffer.subarray(0, newlineIndex + 1).toString('utf8').replace(/\r?\n$/, '');
      buffer = buffer.subarray(newlineIndex + 1);
      processCommand(line);
    }
  };

  socket.on('data', onData);
  socket.once('error', cleanup);
  sendLine('220 Test FTPS server ready');
}

async function createPlainFtpServer(onConnection = () => {}) {
  const server = net.createServer((socket) => onConnection(socket));

  return await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unable to determine plain FTP server address'));
        return;
      }

      server.off('error', reject);
      resolve({
        port: address.port,
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((err) => (err ? closeReject(err) : closeResolve()));
          }),
      });
    });
  });
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

test('FtpsClient keeps the custom transport when TLSv1.2 is the highest allowed version', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      ciphers: 'AES128-SHA',
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    },
    (socket) => attachFtpControlHandler(socket),
  );

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    minVersion: 'TLSv1.1',
    maxVersion: 'TLSv1.2',
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'connect with TLSv1.2 max version');
  assert.strictEqual(client.tlsTransportType, 'custom');
  assert.ok(!client.tlsClient.implementation, 'custom transport should not report a Node implementation');

  await withTimeout(client.login('test', 'password'), 'login with custom transport');
  await withTimeout(client.quit(), 'quit with custom transport');
});

test('FtpsClient rejects TLSv1.3 sessions that request custom TLS-only options', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    (socket) => attachFtpControlHandler(socket),
  );

  t.after(async () => {
    await server.close();
  });

  const cases = [
    {
      label: 'cipherSuites',
      options: { cipherSuites: [0x002f] },
      pattern: /cipherSuites is only supported by the custom TLSv1\.2 transport/i,
    },
    {
      label: 'compressionMethods',
      options: { compressionMethods: [0x00] },
      pattern: /compressionMethods is only supported by the custom TLSv1\.2 transport/i,
    },
    {
      label: 'extensions',
      options: { extensions: { serverName: false } },
      pattern: /extensions is only supported by the custom TLSv1\.2 transport/i,
    },
  ];

  for (const testCase of cases) {
    const client = new FtpsClient({
      host: '127.0.0.1',
      port: server.port,
      servername: 'localhost',
      ca: [fixtures.caCert],
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ...testCase.options,
    });

    await assert.rejects(
      () => withTimeout(client.connect(), `${testCase.label} validation`),
      testCase.pattern,
    );

    await client.close();
  }
});

test('FtpsClient validates TLS version strings and ordering before transport selection', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    (socket) => attachFtpControlHandler(socket),
  );

  t.after(async () => {
    await server.close();
  });

  const invalidNameClient = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    minVersion: 'TLSv2',
    maxVersion: 'TLSv1.3',
  });

  await assert.rejects(
    () => withTimeout(invalidNameClient.connect(), 'invalid minVersion validation'),
    /minVersion must be one of: TLSv1, TLSv1\.1, TLSv1\.2, TLSv1\.3/,
  );
  await invalidNameClient.close();

  const invalidRangeClient = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.2',
  });

  await assert.rejects(
    () => withTimeout(invalidRangeClient.connect(), 'invalid TLS range validation'),
    /minVersion cannot be greater than maxVersion/,
  );
  await invalidRangeClient.close();

  const invalidTypeClient = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
    minVersion: 123,
    maxVersion: 'TLSv1.3',
  });

  await assert.rejects(
    () => withTimeout(invalidTypeClient.connect(), 'invalid minVersion type validation'),
    /minVersion must be a string/,
  );
  await invalidTypeClient.close();
});

test('FtpsClient sends CCC over a plain control channel when no TLS session is active', async (t) => {
  const commandsSeen = [];
  const server = await createPlainFtpServer((socket) => {
    socket.write('220 Plain FTP ready\r\n');
    socket.on('data', (chunk) => {
      const lines = chunk.toString('utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        commandsSeen.push(line);
        if (line === 'CCC') {
          socket.write('200 Command channel already clear\r\n');
          continue;
        }
        if (line === 'QUIT') {
          socket.write('221 Goodbye\r\n');
          socket.end();
        }
      }
    });
  });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    secure: false,
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'plain FTP connect');
  const cccResp = await withTimeout(client.clearCommandChannel(), 'plain CCC');
  assert.match(cccResp, /^200/);
  await withTimeout(client.quit(), 'plain quit');
  assert.deepStrictEqual(commandsSeen, ['CCC', 'QUIT']);
});

test('FtpsClient validates disconnected and malformed plain FTP flows', async (t) => {
  const missingHostClient = new FtpsClient();
  await assert.rejects(
    () => missingHostClient.connect(),
    /FtpsClient requires a host/,
  );

  const disconnectedClient = new FtpsClient({ host: '127.0.0.1', secure: false });
  await assert.rejects(
    () => disconnectedClient.sendCommand('PWD'),
    /FTPS client is not connected/,
  );
  await disconnectedClient.quit();

  const server = await createPlainFtpServer((socket) => {
    socket.write('220 Plain FTP ready\r\n');
    socket.on('data', (chunk) => {
      const input = chunk.toString('utf8');
      if (input.includes('PASV')) {
        socket.write('227 malformed response\r\n');
        return;
      }
      if (input.includes('PWD')) {
        socket.write('500 not here\r\n');
        return;
      }
      if (input.includes('QUIT')) {
        socket.write('221 Goodbye\r\n');
        socket.end();
      }
    });
  });

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    secure: false,
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'plain FTP connect for malformed flow checks');
  await assert.rejects(
    () => withTimeout(client.enterPassiveMode(), 'malformed PASV response'),
    /unable to parse endpoint/,
  );
  await assert.rejects(
    () => withTimeout(client.pwd(), 'unexpected PWD response code'),
    /PWD response failed: expected 257, got "500 not here"/,
  );
});

test('FtpsClient.exitPassiveMode can skip closing the passive socket', async () => {
  const client = new FtpsClient({ host: '127.0.0.1', secure: false });
  let endCalls = 0;
  client.passiveDataSocket = {
    destroyed: false,
    end: () => {
      endCalls += 1;
    },
  };
  client.passiveBuffer = Buffer.from('pending');

  await client.exitPassiveMode({ closeSocket: false });

  assert.strictEqual(client.passiveDataSocket, null);
  assert.strictEqual(client.passiveBuffer.length, 0);
  assert.strictEqual(endCalls, 0);
});

test('FtpsClient rejects AUTH TLS upgrade when the control channel is already secured', async (t) => {
  const fixtures = await loadCertificateFixtures();
  const server = await createTestTlsServer(
    {
      key: fixtures.serverKey,
      cert: fixtures.serverCert,
      ciphers: 'AES128-SHA',
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    },
    (socket) => attachFtpControlHandler(socket),
  );

  const client = new FtpsClient({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });

  t.after(async () => {
    await client.close();
    await server.close();
  });

  await withTimeout(client.connect(), 'implicit FTPS connect');
  await assert.rejects(
    () => client.upgradeControlChannel(),
    /Control channel already secured/,
  );
  await withTimeout(client.quit(), 'quit after rejected upgrade');
});
