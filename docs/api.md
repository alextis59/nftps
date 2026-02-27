# API Reference

Import everything from the package entrypoint:

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

## `TLS_VERSION_1_2`

Numeric constant for TLS 1.2 (`0x0303`).

## `TcpStream`

Minimal buffered TCP helper used by the TLS record layer.

### Constructor

- `new TcpStream(socket)`

### Methods

- `await tcp.readExactly(n)`
- `await tcp.write(buffer)`
- `tcp.detach()`

## `makeCipherStateFromKeyBlock(keyBlock, cipherSpec?)`

Slices a TLS key block into client/server MAC keys, encryption keys, IVs, and
initial sequence numbers.

Returns an object consumed by `TlsRecordLayer.installCipher(...)`.

## `TlsRecordLayer`

Record framing and encryption/decryption for TLS records.

### Constructor

- `new TlsRecordLayer(tcpStream)`

### Properties

- `state`: one of `PLAIN`, `ENCRYPTING`, `ENCRYPTED`, `CLOSED`
- `version`: TLS record version (defaults to `TLS_VERSION_1_2`)

### Methods

- `installCipher(cipherState)`
- `await writePlainRecord(contentType, fragment)`
- `await readPlainRecord()`
- `await sendChangeCipherSpec()`
- `await sendAlertCloseNotify()`
- `await writeEncryptedRecord(contentType, plaintext)`
- `await readEncryptedRecord()`

## `TlsClient`

### Static Methods

- `TlsClient.connect(options)`
- `TlsClient.fromExistingSocket(socket, options)`

`options`:
- `host` (`connect` only)
- `port` (`connect` only)
- `servername` (SNI/hostname verification target)
- `clientCert` (PEM string or Buffer; can include a chain)
- `clientKey` (PEM string or Buffer)
- `ca` (PEM cert or array of PEM certs)
- `rejectUnauthorized` (default `true`)
- `checkServerIdentity` (optional function)
- `verbose` (default `false`)
- `log` (optional logger function)

### Instance Methods

- `await client.doHandshake()`
- `await client.sendApplicationData(data)`
- `await client.readApplicationData()`
- `await client.readHandshakeMessage(encrypted = false)`
- `await client.shutdownToPlain({ waitForPeer = true, timeoutMs = 5000 })`
- `await client.close({ destroySocket = true, sendCloseNotify = true, detach = true })`

### Instance Fields

- `client.authorized` (`boolean`)
- `client.authorizationError` (`Error | null`)

## `FtpsClient`

`FtpsClient` extends `EventEmitter`.

### Constructor Options

- `host`
- `port` (default `21`)
- `servername` (default `host`)
- `secure` (default `true`) for implicit FTPS
- `clientCert`
- `clientKey`
- `ca`
- `rejectUnauthorized` (default `true`)
- `checkServerIdentity`
- `verbose` (default `false`)
- `log`
- `ignorePasvAddress` (default `false`)

### Methods

- `await client.connect()`
- `await client.login(username, password)`
- `await client.sendCommand(command)`
- `await client.setProtectedDataChannel()`
- `await client.upgradeControlChannel()`
- `await client.clearCommandChannel({ downgrade = true, waitForPeerCloseNotify = true, closeNotifyTimeoutMs = 5000 })`
- `await client.enterPassiveMode({ ignoreAddress = this.ignorePasvAddress })`
- `await client.openPassiveDataSocket(options)`
- `await client.exitPassiveMode({ closeSocket = true })`
- `await client.pwd()`
- `await client.quit()`
- `await client.close()`

### Events

- `command`: emitted with each outbound control command
- `data`: emitted for each inbound control line
- `passive-data`: emitted with passive data socket `Buffer` chunks

## `createTestTlsServer(credentials, onConnection)`

Creates a TLS server bound to `127.0.0.1` on an ephemeral port.

`credentials`:
- `key` (required)
- `cert` (required)
- `requestCert` (default `false`)
- `ca` (array of cert PEM/buffers)
- `rejectUnauthorized` (default `false`)
- `ciphers`
- `minVersion`
- `maxVersion`

Returns a Promise resolving to:
- `{ server, port, close }`
