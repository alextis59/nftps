# nftps

This repository captures a testing harness for experimenting with FTPS/TLS flows inspired by the ideas in `transcript.md`.

## Testing

The project uses Node's built-in test runner and TLS client to validate a locally generated TLS server. The test suite spins up a TLS echo server with the bundled self-signed certificate and verifies the handshake and data exchange using the Node TLS client. To run the tests:

```
node --test
```

If you prefer npm-style scripts, you can also use `npm test` once Node.js is available in your environment.

> **Note:** The provided execution environment for this repository does not include a Node.js binary and cannot install one via `apt` because outbound package downloads are blocked. The test suite has been validated with [Bun](https://bun.sh/), which implements the Node-compatible `node:test` API:
>
> ```
> bun test
> ```
