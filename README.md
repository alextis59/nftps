# nftps

This repository captures a testing harness for experimenting with FTPS/TLS flows inspired by the ideas in `transcript.md`.

## Testing

The project uses Node's built-in test runner and TLS client to validate TLS and FTPS flows, including certificate validation and explicit FTPS TLS downgrade (`CCC`). To run the tests:

```
node --test
```

You can also run:

```
npm test
```

## FTPS Notes

- `FtpsClient.clearCommandChannel()` now supports two modes:
  - Default: `clearCommandChannel()` sends TLS `close_notify`, waits for peer `close_notify`, then downgrades the control channel to cleartext on the same TCP socket.
  - Optional compatibility: `clearCommandChannel({ downgrade: false })` sends `CCC` but keeps TLS active.
- Test coverage includes both:
  - implicit FTPS (`secure: true`) with `CCC` downgrade to cleartext
  - explicit FTPS (`secure: false` + `AUTH TLS`) with `CCC` downgrade to cleartext
- Passive mode (`PASV`) support:
  - `enterPassiveMode()` parses `227` responses and returns `{ host, port }`
  - `openPassiveDataSocket()` connects to the announced passive data endpoint
  - commands/replies stay on the control channel after entering passive mode; data-transfer payloads (for example `RETR`) arrive on the passive data socket
  - passive data bytes are emitted via `passive-data` events and included in verbose logs as `received passive data: ...`
  - set `ignorePasvAddress: true` to use the control-channel host instead of the server-advertised PASV address (useful for NAT/broken servers)

## Certificate Support

- `TlsClient` and `FtpsClient` support:
  - server certificate + hostname verification
  - custom CA trust via `ca`
  - client authentication via `clientCert` + `clientKey`
  - optional bypass with `rejectUnauthorized: false`
  - handshake troubleshooting logs via `verbose: true` (override output sink with `log: (line) => {}`)
- Test fixtures in `test/fixtures/pki` provide a CA root, server cert, client cert, and a wrong CA for negative tests.
