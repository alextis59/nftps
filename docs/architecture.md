# Architecture

## Goals

- Provide a controlled environment for FTPS/TLS behavior testing.
- Validate custom TLS and FTPS client behavior against local servers.
- Keep implementation explicit and inspectable for protocol experiments.

## Module Structure

- `src/index.js`: public API exports.
- `src/tlsClient.js`: compatibility shim that re-exports `src/tlsClient/index.js`.
- `src/tlsClient/`: custom TLS client split by concern.
- `src/ftpsClient.js`: FTPS control/data channel workflow built on `TlsClient`.
- `src/tlsServer.js`: helper to spin up local TLS test servers.

## TLS Client Internals (`src/tlsClient/`)

- `TcpStream`: exact-byte buffered reads from `net.Socket`.
- `TlsRecordLayer`: TLS record framing, encryption/decryption, MAC verification.
- `TlsClient`: handshake flow, certificate validation path, app data I/O, shutdown.
- `handshakeMessages`: handshake encode/decode helpers.
- `cryptoPrimitives`: PRF, key derivation, pre-master secret helpers.
- `certificates`: PEM/DER parsing and chain verification helpers.
- `cipherState`: slices key block into MAC keys, keys, IVs, sequence numbers.
- `options`: connection option parsing/validation and verbose logging helpers.
- `constants`: TLS version, cipher suite IDs, cipher specs.

## FTPS Flow

`FtpsClient` supports both:
- Implicit FTPS (`secure: true`): TLS handshake on connect.
- Explicit FTPS (`secure: false`): clear FTP connect, then `AUTH TLS` upgrade.

Control channel operations:
- `sendCommand` writes command and reads line response.
- `clearCommandChannel` sends `CCC`; default path performs TLS `close_notify` and downgrades to clear TCP.

Passive data channel operations:
- `enterPassiveMode` parses `PASV` response (`227 (...)`).
- `openPassiveDataSocket` opens the announced host/port.
- Optional `ignorePasvAddress` uses control-channel host instead of advertised host.

## Testing Strategy

The Node test suite validates:
- custom TLS handshake/data exchange behavior
- server verification failures and mTLS success path
- FTPS implicit and explicit upgrade/downgrade flows
- passive mode endpoint parsing and data socket handling

Run with:

```bash
npm test
```
