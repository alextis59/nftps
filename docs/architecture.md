# Architecture

## Goals

- Provide a controlled environment for FTPS/TLS behavior testing.
- Validate custom TLS and FTPS client behavior against local servers.
- Keep implementation explicit and inspectable for protocol experiments.

## Module Structure

- `src/index.js`: public API exports.
- `src/tlsClient.js`: compatibility shim that re-exports `src/tlsClient/index.js`.
- `src/tlsClient/`: custom TLS client split by concern.
- `src/ftpsClient.js`: FTPS control/data channel workflow with transport selection.
- `src/nodeTlsTransport.js`: internal adapter around Node's `tls` module for FTPS sessions that negotiate TLS 1.3.
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

Transport selection:
- `maxVersion <= TLSv1.2`: use the custom `TlsClient`.
- `maxVersion > TLSv1.2`: use Node's `tls` stack so the control channel can negotiate TLS 1.3.

Control channel operations:
- `sendCommand` writes command and reads line response.
- `clearCommandChannel` sends `CCC`; the custom TLS 1.2 path can perform `close_notify` and downgrade to clear TCP.
- Node TLS sessions cannot unwrap back to raw TCP after shutdown, so `clearCommandChannel({ downgrade: false })` is required when the FTPS client is using TLS 1.3.

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
