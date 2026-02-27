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
- `test/tlsClient/options.test.js`
- `test/tlsClient/cipherState.test.js`
- `test/tlsClient/handshakeMessages.test.js`
- `test/tlsClient/tcpStream.test.js`
- `test/tlsClient/tlsRecordLayer.test.js`
- `test/ftps.test.js`

## Coverage Areas

- baseline Node TLS behavior against local TLS servers
- custom `TlsClient` handshake + encrypted application data
- cipher negotiation path for all supported RSA AES-CBC suites (`AES128-SHA`, `AES256-SHA`, `AES128-SHA256`, `AES256-SHA256`)
- `cipherSuites` option validation and single-suite offer coverage for each supported suite
- `ciphers` option validation and single-suite offer coverage for each supported suite
- `minVersion` / `maxVersion` validation and compatible-range handshake coverage
- `compressionMethods` and `extensions` option validation and handshake coverage
- direct option parser normalization/validation coverage for TLS client option helpers
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
