# Quickstart

## Requirements

- Node.js (modern LTS recommended)
- npm

## Install

```bash
npm install
```

## Run Tests

```bash
npm test
```

Equivalent command:

```bash
node --test
```

## Minimal TLS Example

```js
const { createTestTlsServer, TlsClient } = require('./src');
const { loadCertificateFixtures } = require('./support/testCertFixtures');

async function run() {
  const fixtures = await loadCertificateFixtures();

  const server = await createTestTlsServer(
    { key: fixtures.serverKey, cert: fixtures.serverCert },
    (socket) => socket.on('data', (chunk) => socket.write(chunk)),
  );

  const client = await TlsClient.connect({
    host: '127.0.0.1',
    port: server.port,
    servername: 'localhost',
    ca: [fixtures.caCert],
  });

  await client.sendApplicationData(Buffer.from('ping'));
  const response = await client.readApplicationData();
  console.log(response.toString('utf8'));

  await client.close();
  await server.close();
}

run().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
```

## Minimal FTPS Example

```js
const { FtpsClient } = require('./src');

async function run() {
  const client = new FtpsClient({
    host: '127.0.0.1',
    port: 21,
    servername: 'localhost',
    secure: false,
    ca: [/* your CA cert PEM */],
  });

  await client.connect();
  await client.upgradeControlChannel();
  await client.login('user', 'pass');
  await client.clearCommandChannel();
  console.log(await client.pwd());
  await client.quit();
}

run().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
```
