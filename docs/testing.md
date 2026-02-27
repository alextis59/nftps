# Testing

## Run the Suite

```bash
npm test
```

This runs `node --test` and executes all tests under `test/`.

## Test Files

- `test/tlsClient/nodeInterop.test.js`
- `test/tlsClient/customClient.test.js`
- `test/tlsClient/certificateValidation.test.js`
- `test/tlsClient/serverOptions.test.js`
- `test/tlsClient/connectionValidation.test.js`
- `test/tlsClient/cipherState.test.js`
- `test/tlsClient/tcpStream.test.js`
- `test/tlsClient/tlsRecordLayer.test.js`
- `test/ftps.test.js`

## Coverage Areas

- baseline Node TLS behavior against local TLS servers
- custom `TlsClient` handshake + encrypted application data
- cipher negotiation path for `AES128-SHA` and `AES128-SHA256`
- certificate validation failures (wrong CA, hostname mismatch)
- optional bypass path (`rejectUnauthorized: false`)
- client-certificate authentication (mTLS)
- `TlsClient` option and input validation paths
- cipher state derivation and validation helpers
- TCP stream buffering/write/detach behavior
- TLS record-layer guard/error paths
- FTPS implicit TLS flow
- FTPS explicit `AUTH TLS` upgrade flow
- FTPS `CCC` downgrade flow back to clear control channel
- passive mode (`PASV`) parsing and passive data transfer behavior

## Fixtures

Certificate fixtures are stored in `test/fixtures/pki/` and loaded by:

- `support/testCertFixtures.js`

They include:
- CA cert/key
- server cert/key
- client cert/key
- wrong CA cert (negative-path tests)
