# nftps

This repository captures a testing harness for experimenting with FTPS/TLS flows inspired by the ideas in `transcript.md`.

## Testing

The project uses Node's built-in test runner and TLS client to validate a locally generated TLS server. The test suite spins up a TLS echo server with the bundled self-signed certificate and verifies the handshake and data exchange using the Node TLS client. To run the tests, use [Bun](https://bun.sh/), which implements the Node-compatible `node:test` API:

```
bun test
```

If you prefer npm-style scripts, you can also use `npm test` or `node --test` in environments where Node.js is available.

## Validated environment versions

The test suite has been validated with the following toolchain versions:

- Bun 1.2.14
- Node.js v22.21.0
- OpenSSL 3.0.13
