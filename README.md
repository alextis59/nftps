# nftps

Experimental FTPS/TLS playground for protocol testing in Node.js.

## Documentation

- [Quickstart](docs/quickstart.md)
- [API Reference](docs/api.md)
- [Architecture](docs/architecture.md)
- [Testing](docs/testing.md)
- [Docs Index](docs/README.md)

## Repository Purpose

This repository is test-first and intended for experimentation.

It includes:
- a custom TLS 1.2 client (`TlsClient`)
- a custom FTPS client (`FtpsClient`) on top of that TLS client
- local TLS test server helpers (`createTestTlsServer`)

`transcript.md` contains background discussion. Runtime behavior is defined by code under `src/` and tests under `test/`.

## Quick Commands

```bash
npm install
npm test
```

## Public Exports

```js
const {
  createTestTlsServer,
  TcpStream,
  TLS_VERSION_1_2,
  TlsRecordLayer,
  TlsClient,
  makeCipherStateFromKeyBlock,
  FtpsClient,
} = require('./src');
```
