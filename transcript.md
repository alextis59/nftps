You said:
Is there a way to rewrite a js lib like node-curllib from scratch (including ftps handling with certificates) ?
If possible without relying on curl (maybe going low level and handling all TCP/TLS protocol from scratch)
ChatGPT said:

Thought for 10s
Short answer: yes, in theory — you can write something that behaves like node-curllib from scratch and even avoid depending on curl itself.
But in practice, there are three very different levels you can play at, and only the first two are realistic:

1. “From scratch” but using Node’s networking primitives (realistic)
Here you don’t use curl, but you do use Node’s built-in net, tls, and maybe http/https as building blocks.

a) FTPS on top of net + tls
FTPS is basically FTP + TLS:

Control connection on port 21 (or 990 for implicit FTPS)

Data connections opened separately (active or passive mode)

TLS can be:

Explicit FTPS: connect in plain FTP, then AUTH TLS → upgrade to TLS.

Implicit FTPS: connect directly with TLS.

How you’d implement it in Node:

Use net.connect() for plain FTP, or tls.connect() for implicit FTPS.

For explicit FTPS:

net.connect() to server:21

Speak plain FTP until you send AUTH TLS.

Once server replies OK, wrap the socket with tls.connect({ socket, ...options }) to upgrade to TLS.

Implement:

Client state machine (waiting for 220, sending USER/PASS, etc.)

Parsing of reply codes (3-digit codes + text).

Passive vs active mode for data connections (PASV / EPSV vs PORT / EPRT).

Separate TLS handling for data connections if required (some servers want encrypted data too → PROT P).

Certificate handling:

Node’s tls.connect already gives you:

ca, cert, key, rejectUnauthorized, servername (SNI), etc.

Ability to get peer cert via socket.getPeerCertificate().

So you can expose a nice JS API that looks like:

const client = new FtpsClient({
  host: 'example.com',
  port: 21,
  user: 'foo',
  password: 'bar',
  secure: true,
  secureOptions: {
    ca: fs.readFileSync('ca.pem'),
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key'),
    rejectUnauthorized: true,
  }
});
…and under the hood you’re just using net + tls.

b) HTTP(S)/REST “curl-like” behavior
For “curl-like” generic HTTP(S) features (headers, redirects, proxy, etc.), you can build on:

http / https modules

Or undici (Node’s newer HTTP client) for better performance & HTTP/2

You’d re-implement:

Redirect logic (3xx chaining)

Following Location headers

Proxy handling (HTTP proxies, CONNECT tunneling)

Timeouts, retries, backoff

Uploading files (multipart/form-data), etc.

All without curl, just with Node primitives.

This is absolutely feasible and what many HTTP libs already do.

2. “From scratch” including TLS, but still using OS TCP (very hard and not worth it)
Here, you keep net sockets for raw TCP but try to implement TLS yourself in JS.

Problems:

TLS is:

Cryptographically complex (key exchange, ciphers, MACs, AEAD, etc.)

Full of edge cases and security pitfalls.

You lose:

Constantly maintained, audited C/OpenSSL/BoringSSL/etc. implementations.

OS/Node’s built-in optimizations and mitigations.

You’d have to:

Implement or embed a full TLS stack in JS (or WASM).

Keep up with protocol changes, cipher deprecations, vulnerabilities.

Realistically: that’s not sane for a general-purpose library.
At most, people embed existing TLS stacks (like mbedtls, boringssl) compiled to WASM for special environments, not for a normal Node lib.

3. “From scratch” including TCP + TLS in userland (not realistic at all)
What you suggested at the extreme:

handling all TCP/TLS protocol from scratch

To do real TCP you need:

Access to IP packets, sockets in raw mode, or NIC driver level.

The OS kernel already implements TCP; re-implementing it in a userland Node library means:

Building a TCP stack in JS.

Handling retransmissions, congestion control, sliding windows, timeouts, etc.

Integrating with real network devices (which Node does not expose).

That’s basically writing your own OS networking stack. It’s research-project territory, not something you’d ship as a NPM lib.

So no, you can’t meaningfully do that in Node without extreme hacks (custom drivers, tun/tap + privileged helper, etc.), and even then it’s totally overkill.

So what’s actually a good architecture?
If your goal is:

“Rewrite a curl-like lib in JS, support FTPS with certificates, but not depend on curl binary”

Then the sensible layers are:

Use OS TCP via Node net.

Use OS TLS via Node tls.

Build:

FtpsClient using net+tls.

HttpClient/CurlLikeClient using https/undici+tls.

Design a high-level API similar to node-curllib:

request({ url, method, headers, body, timeout, ca, cert, key, ... })

download({ url, output, ... })

Support FTP/FTPS specific methods: upload, list, mkdir, etc.

You won’t rely on curl the binary; you’ll rely on Node’s networking stack, which is already a thin wrapper over the OS + OpenSSL/BoringSSL.

Practical note: complexity vs. safety
Re-implementing FTPS protocol logic yourself is non-trivial but realistic:

Parsing replies, managing modes, handling TLS upgrades, resume, etc.

Handling weird servers and network conditions.

Re-implementing TLS or TCP is crypto/kernel engineering and not recommended unless you’re literally working on a new TLS stack.

If you tell me which exact node-curllib features you want (e.g. just FTPS upload/download? full curl-style protocol zoo?), I can sketch a more concrete architecture and some Node code skeletons for an FTPS client that uses only net + tls.

You said:
It's for a niche use case to connect to a specific ftp server which handle connectivity in a way that cannot be done with the tls lib nor node-libcurl due to build issues.
Basically the client needs to connect in plain ftp, then upgrade to tls for user authentication (with AUTH TLS), then downgrade back to plain with client tls shutdown.
So I need to implement a custom ftp client in node to handle that and I will go with the tls implementation from scratch over the net socket lib.
Can you research a maximum of information about the tls protocol and draft me a detailed document that will help me achieve that ? (With each step of tls handshakes, including client tls shutdown to downgrade to plain)
ChatGPT said:

Thought for 1m 50s
Yes, you can do it, but you’re basically signing up to write a mini-TLS stack plus FTP/FTPS logic. I’ll give you a structured “design doc” you can work from.

I’ll assume:

You’re targeting one specific FTP server whose behavior you can test.

You will reuse crypto primitives from Node’s crypto (AES, HMAC, RSA/ECDH, SHA-256, etc.) and only implement the TLS protocol logic, not raw math.

You mainly need TLS 1.2 (1.0/1.1 are obsolete, 1.3 is significantly more complex).
Wikipédia
+1

And your FTPS flow is:

Connect in clear FTP

Send AUTH TLS

Do a TLS handshake on the control connection

Send USER/PASS inside TLS

Then downgrade back to plaintext on same TCP socket

That downgrade is essentially the FTP CCC (Clear Command Channel) behavior: protect control channel for auth, then revert to clear text. RFC 4217 describes exactly this pattern.
RFC Editor
+2
IBM
+2

0. Strong warning before we start
Implementing TLS yourself is:

Easy to get functionally working for your one server

Very easy to get subtly insecure in ways you won’t notice (padding oracles, truncation, downgrade issues, etc.)

If this ever touches untrusted networks or real credentials in production, the “proper” solution is:

Use an external helper (e.g. stunnel, small C helper using OpenSSL) and speak plain FTP to that from Node, or

Fix the build issues with node-libcurl / tls and add CCC support via that, or

Use a small local proxy that does AUTH TLS + CCC for you.

That said, you asked explicitly for protocol details, so here we go.

1. TLS high-level architecture
TLS splits into layers:
Wikipédia
+1

Record layer: framing + encryption/MAC for all data

Handshake protocol: negotiates version, cipher suite, keys, certs

ChangeCipherSpec (TLS ≤ 1.2): flips connection into “encrypted” mode

Alert protocol: error and close notifications (close_notify)

Application Data: your FTP commands/responses after handshake

For your client you need:

A TLS record encoder/decoder

A TLS 1.2 client handshake state machine

A cipher suite implementation (hopefully just 1 strong one)

Shutdown logic (close_notify) that allows you to “turn off” TLS while leaving TCP open.

2. TLS versions & scope choice
Practically:

Implement TLS 1.2 only (version field 0x03 0x03)
datatracker.ietf.org
+1

Disable TLS 1.0 and 1.1 (obsolete).

Ignore TLS 1.3 unless your FTP server only supports it (then the job is significantly harder).

Pick one cipher suite your FTP server supports; for example:
ciphersuite.info

Modern (preferred, but more work):
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

Legacy (simpler key exchange, no PFS):
TLS_RSA_WITH_AES_128_CBC_SHA

You can see the server’s supported suites with openssl s_client -connect host:21 -starttls ftp -tlsextdebug or similar from the shell.

3. TLS record layer (TLS 1.2)
Every TLS record is:
Wikipédia
+1

struct {
  uint8  content_type;   // 0x16=Handshake, 0x17=App, 0x15=Alert, 0x14=ChangeCipherSpec
  uint16 version;        // e.g. 0x0303 for TLS 1.2
  uint16 length;         // length of fragment (<= 2^14)
  uint8  fragment[length]; // plaintext or ciphertext depending on state
} TLSRecord;
Content types you care about:

0x16 – Handshake

0x14 – ChangeCipherSpec

0x15 – Alert

0x17 – Application Data

Internally, handshake messages have their own mini-header inside the record:
tls12.xargs.org
+1

struct {
  uint8  msg_type;   // ClientHello=1, ServerHello=2, Certificate=11, etc.
  uint24 length;
  uint8  body[length];
} Handshake;
Your record-layer code must:

Read from net.Socket until it has at least 5 bytes (header).

Parse length, then read exactly length more bytes for the fragment.

Dispatch based on content_type and current handshake state.

When encryption is enabled, the fragment is ciphertext; you must decrypt/MAC-verify before interpreting it.

4. TLS 1.2 handshake flow (server-authenticated only)
We’ll focus on the common case: server has a cert, client doesn’t.
Wikipédia
+2
IBM
+2

4.1. Message sequence (no client cert)
Typical TLS 1.2 handshake (RSA key exchange case):

Client ➜ Server: ClientHello (Handshake)

Version (max supported) = TLS 1.2

Random (32 bytes)

Session ID (optional)

Cipher suites list

Compression methods (usually just null)

Extensions (SNI, supported signature algorithms, etc.)

Server ➜ Client: ServerHello (Handshake)

Chosen version (≤ offered)

Server random (32 bytes)

Chosen cipher suite

Chosen compression (typically null)

Extensions

Server ➜ Client: Certificate (Handshake)

Server certificate chain (X.509)

Server ➜ Client: [ServerKeyExchange] (Handshake, if using DHE/ECDHE)

Contains DH/ECDH parameters + server signature

Server ➜ Client: [CertificateRequest] (if mutual auth; may be omitted)

Server ➜ Client: ServerHelloDone (Handshake)

Client ➜ Server: [Certificate] (only if server requested client cert)

Client ➜ Server: ClientKeyExchange (Handshake)

RSA key exchange: 48-byte PreMasterSecret encrypted with server’s public RSA key.

ECDHE: client’s ephemeral public key.

Client ➜ Server: [CertificateVerify] (if client cert sent)

Client ➜ Server: ChangeCipherSpec (CCS record, type 0x14)

Client ➜ Server: Finished (Handshake) [encrypted]

MAC over all previous handshake messages.

Server ➜ Client: ChangeCipherSpec

Server ➜ Client: Finished [encrypted]

After step 13, both sides switch to application data mode and your FTP commands go inside encrypted ApplicationData records.

Specifically, TLS 1.2 handshake is defined in RFC 5246.
datatracker.ietf.org
+2
IBM
+2

4.2. Key schedule (TLS 1.2)
Basic idea:
datatracker.ietf.org
+1

Compute PreMasterSecret:

RSA: client generates 48 random bytes, sets first 2 bytes to client_version, encrypts with server RSA public key.

(EC)DHE: output of DH/ECDH operation.

Compute MasterSecret:

master_secret = PRF(pre_master_secret,
                    "master secret",
                    ClientHello.random + ServerHello.random)[48]
Where PRF is HMAC-based pseudorandom function (usually HMAC-SHA256).

From master_secret, derive key_block:

key_block = PRF(master_secret,
                "key expansion",
                ServerHello.random + ClientHello.random)[needed]
Split key_block into:

client_write_MAC_key

server_write_MAC_key

client_write_key

server_write_key

client_write_IV (if needed)

server_write_IV (if needed)

Once both sides send/receive ChangeCipherSpec, they start using these keys.

Your implementation must:

Collect all handshake messages as raw bytes for the Finished MAC.

Implement PRF using Node’s HMAC (SHA-256).

5. Cipher suites: minimal implementation plan
Pick one suite and implement that cleanly.

5.1. CBC + HMAC (easier to reason about than GCM, but older)
Example: TLS_RSA_WITH_AES_128_CBC_SHA
ciphersuite.info
+1

For each ApplicationData/Handshake/Alert record after CCS:

Build the plaintext fragment:

plaintext = content_bytes || HMAC(write_MAC_key, seq_num || header || content_bytes) || padding
seq_num is an 8-byte monotonically increasing counter per direction.

header is type+version+length before encryption.

Padding: PKCS#7-like; last byte = pad length, all pad bytes equal to that length.

Generate an IV:

For TLS 1.2 AES-CBC, usually an explicit IV per record is sent as the first block of ciphertext.

Encrypt with AES-128-CBC.

Record fragment = IV || ciphertext.

Your record encoder/decoder must:

Maintain sequence numbers.

Verify HMAC on decryption and reject on mismatch.

5.2. AEAD (AES-GCM) – more modern, more moving parts
Example: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 uses AEAD:
datatracker.ietf.org
+1

No separate MAC field; authentication is integrated.

You need to handle:

Nonces (static/implicit + explicit per record)

Additional authenticated data (AAD) (type, version, length, seq_num)

Authentication tag

If your server supports a simple RSA+CBC suite, that’s probably easiest for this one specialized client.

6. TLS alerts & clean shutdown (close_notify)
The Alert protocol is just another record type (0x15) whose payload is:
datatracker.ietf.org
+1

struct {
  uint8 level;       // 1=warning, 2=fatal
  uint8 description; // e.g. 0=close_notify
} Alert;
For TLS 1.2, the relevant closure rules (RFC 4346/5246):
datahunter.org
+3
datatracker.ietf.org
+3
RFC Editor
+3

Either side should send close_notify before closing the write side.

The other side must respond with its own close_notify and then close.

After sending close_notify, you must not send more application data; data received after a close_notify is ignored.

TLS 1.3 slightly relaxes reciprocity but the idea is similar.
datatracker.ietf.org
+1

For your downgrade:

To “turn off” TLS but keep TCP open, conceptually:

You and server exchange close_notify alerts.

Then you stop interpreting bytes as TLS records and treat everything afterward as raw FTP text.

This behavior (“shut down TLS but keep socket open”) is exactly what RFC 4217 describes for FTP CCC: server receives CCC, sends 200, then “Shutdown the TLS session on the socket and leave it open. Continue the control connection in plaintext.”
RFC Editor
+2
IBM
+2

7. FTP + AUTH TLS + CCC sequence with your own TLS
Putting it all together for your use case:

7.1. Control connection flow
Plain TCP / FTP phase

C: (TCP connect)
S: 220 FTP Server ready
C: AUTH TLS\r\n
S: 234 AUTH TLS successful
Start TLS handshake on same TCP socket

Switch your stack to “TLS mode”.

Send ClientHello → complete full TLS 1.2 handshake as described above.

After handshake Finished messages, your FTP commands go into ApplicationData records.

Send FTP auth over TLS

C (via TLS AppData): USER foo\r\n
S (via TLS AppData): 331 Password required for foo
C (via TLS AppData): PASS bar\r\n
S (via TLS AppData): 230 User logged in
If needed, also:

C (TLS): PBSZ 0\r\n
S (TLS): 200 PBSZ=0
C (TLS): PROT C\r\n   // Control channel stays clear for data; or PROT P if you want encrypted data c.
S (TLS): 200 PROT command successful
Request clear command channel (CCC)

C (TLS): CCC\r\n
S (TLS): 200 Command OK, switching to clear control channel
RFC 4217 says server must: send 200, shutdown TLS, leave TCP open, and expect next command in plaintext.
RFC Editor
+2
proftpd.org
+2

TLS shutdown sequence

Likely behavior:

Server sends an Alert(close_notify) record.

Your client sends its own Alert(close_notify) back.

You now mark the TLS session as closed; do not attempt to parse remaining bytes as TLS records.

Continue plain FTP

C (plain TCP text): PWD\r\n
S: 257 "/" is current directory
...
7.2. Important edge cases
The server might:

Send its close_notify before 200, or combine them in some weird order (test and adapt).

Close TCP immediately after close_notify (non-compliant with RFC 4217 CCC expectations but possible).

After you decide TLS is “off”:

Any bytes you see must be treated as FTP line-oriented text (\r\n), not TLS records.

If you mis-detect the end of TLS and start treating ciphertext as text, everything will explode, so be strict:

Once you see a valid close_notify and then EOF on encrypted stream, or a change in pattern, you cut TLS.

8. Implementation blueprint in Node
Here’s how I’d organize the code logically (no full implementation, but structure).

8.1. Binary I/O engine
Wrap the net.Socket in a small I/O abstraction:

class TcpStream {
  socket: net.Socket;
  // buffered read, write methods, etc.
}
On top of this, add a TLSRecordLayer:

class TlsRecordLayer {
  stream: TcpStream;
  state: "PLAIN" | "HANDSHAKE" | "ENCRYPTED" | "CLOSED";
  // cipher state, MAC keys, seq nums...

  async readRecord(): Promise<TlsRecord>;
  async writeRecord(rec: TlsRecord): Promise<void>;
}
In TLS mode:

writeRecord encrypts & MACs.

readRecord decrypts & verifies before returning.

8.2. Handshake state machine
A TlsClientHandshake that uses TlsRecordLayer:

class TlsClientHandshake {
  recordLayer: TlsRecordLayer;
  transcript: Buffer[]; // concat of all handshake messages
  version = "TLS1.2";
  chosenCipher: CipherSuite;

  async performHandshake(options: { serverName, caCerts, clientCert?, clientKey? }): Promise<void>;
}
Implementation tasks:

Build ClientHello with:

Supported ciphers (your one cipher + maybe a fallback)

SNI extension

SignatureAlgorithms extension (if using ECDHE).

Parse:

ServerHello (cipher, version)

Certificate (validate chain against CA)

ServerKeyExchange (verify signature)

CertificateRequest/ServerHelloDone as needed

Generate keys and install them in TlsRecordLayer.

Compute and verify Finished messages.

Use Node’s crypto for:

crypto.randomBytes

crypto.createHmac('sha256', ...)

crypto.createCipheriv / createDecipheriv (or AEAD via crypto.createCipheriv('aes-128-gcm', ...), etc.)

RSA and ECDH operations (crypto.createPublicKey, crypto.privateDecrypt, crypto.createECDH, etc.)

8.3. Shutdown / downgrade logic
In your FTPS client:

Maintain a mode: "PLAIN_FTP" | "TLS_FTP" | "PLAIN_AFTER_CCC".

Rough flow:

await ftp.sendPlain("AUTH TLS\r\n");
await ftp.expectPlain(/^234/);

// perform TLS handshake
await tlsHandshake.performHandshake({ serverName: host, caCerts, ... });

// now use TLS AppData wrappers for FTP commands
await ftp.sendTls("USER " + user + "\r\n");
...

// request CCC
await ftp.sendTls("CCC\r\n");
const reply = await ftp.readTlsReply(); // 200?
// expect server to send close_notify
await tlsRecordLayer.expectCloseNotify();
// send your close_notify
await tlsRecordLayer.sendCloseNotify();

// switch to plain mode
tlsRecordLayer.state = "CLOSED";
ftp.mode = "PLAIN_AFTER_CCC";
If the server doesn’t send close_notify but just stops sending records or starts sending cleartext, you’ll need heuristics, but RFC 4217 expects a proper TLS shutdown.
RFC Editor
+2
datahunter.org
+2

9. Things you must not forget (security & correctness)
Even for a “niche” client, at least:

Certificate validation

Parse X.509, validate chain to a trusted CA or pin server cert.

Check hostname (SNI vs CN/SAN).

Failing that, you are completely MITM-able.

Strong randomness

Use crypto.randomBytes for all nonces, PreMasterSecret, etc.

Replay / truncation awareness

Don’t treat TCP FIN or break in TLS stream as successful end unless a close_notify was seen; otherwise you are vulnerable to truncation attacks (server thinks connection is still open, client thinks done).
Wikipédia
+1

Version/cipher negotiation

Reject downgrade to < TLS 1.2.

Reject cipher suites you don’t explicitly support.

Error handling

On unexpected content type or malformed handshake, send fatal alert and abort.
bugzilla.mozilla.org
+1

10. References worth keeping open while coding
TLS 1.2 spec – RFC 5246 (and summary pages):
datatracker.ietf.org
+1

TLS 1.3 spec – RFC 8446 (read for conceptual clarity even if you don’t implement):
datatracker.ietf.org
+1

FTP over TLS / AUTH TLS / CCC – RFC 4217:
RFC Editor
+2
RFC Editor
+2

Illustrated TLS 1.2 connection – step-by-step bytes:
tls12.xargs.org

Some readable overviews of TLS handshakes: Cloudflare / GCore / OSDev tutorial.
cloudflare.com
+2
gcore.com
+2

If you want, next step I can:

Design a very specific subset (exact cipher, exact message layout) and

Sketch concrete binary structures + pseudo-code for ClientHello, ClientKeyExchange, and Finished for one chosen cipher suite (e.g. RSA + AES-128-CBC), so you can start implementing your mini-stack progressively and test it against that FTP server.

You said:
Yes please
ChatGPT said:

Thought for 8s
Alright, let’s lock this down into something you can actually implement.

I’ll assume:

Version: TLS 1.2 (0x03 0x03)

Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
(RSA key exchange, AES-128-CBC encryption, HMAC-SHA1 MAC)

No client certificate (server-auth only)

No session resumption, no compression, minimal extensions

We’ll walk through:

Overall handshake skeleton

Precise binary layout for:

ClientHello

ClientKeyExchange

Finished

Pseudo-code for each step (using Node’s crypto)

Where each piece plugs into your FTPS AUTH TLS / CCC flow

1. Minimal TLS 1.2 handshake you’ll implement
For TLS_RSA_WITH_AES_128_CBC_SHA and no client cert, the handshake sequence is:

ClientHello

ServerHello

Certificate

[optional ServerKeyExchange] – NOT used for pure RSA key exchange

[optional CertificateRequest] – you’ll ignore this path

ServerHelloDone

ClientKeyExchange

ChangeCipherSpec (record type 0x14)

Finished (Handshake, encrypted)

ChangeCipherSpec from server

Finished from server (encrypted)

After that, you’re in ApplicationData mode and can send FTP commands.

Everything handshake-related is wrapped inside TLS records:

struct TLSRecord {
  uint8  ContentType;      // 0x16=Handshake, 0x14=CCS, 0x15=Alert, 0x17=AppData
  uint16 ProtocolVersion;  // 0x0303 for TLS 1.2
  uint16 Length;
  uint8  Fragment[Length]; // plaintext or ciphertext, depending on state
}
2. ClientHello – full binary layout
2.1. Handshake header
Every handshake message has an inner header:

struct HandshakeMessage {
  uint8  msg_type;   // 1 = ClientHello
  uint24 length;     // length of body (3 bytes, big endian)
  uint8  body[length];
}
2.2. ClientHello body
RFC 5246 definition, stripped to what you’ll actually send:
datatracker.ietf.org
+1

struct {
  ProtocolVersion client_version;   // 0x03 0x03 (TLS 1.2)
  Random random;
  SessionID session_id;
  CipherSuite cipher_suites<2..2^16-2>;
  CompressionMethod compression_methods<1..2^8-1>;
  Extension extensions<0..2^16-1>;  // we’ll keep minimal
} ClientHello;
Random (32 bytes)
struct {
  uint32 gmt_unix_time;   // can be real or random
  uint8  random_bytes[28];
} Random;
You’ll generate 32 random bytes; you can set the first 4 to Date.now()/1000 if you like.

SessionID
For no resumption, send empty:

uint8 session_id_length = 0x00;
(no bytes follow)
CipherSuites
cipher_suites is a length-prefixed list of 2-byte codes:

uint16 length = 0x00 0x02;          // 2 bytes of data
uint16 cipher_suite = 0x00 0x2F;    // TLS_RSA_WITH_AES_128_CBC_SHA
Compression methods
You send only null (0x00):

uint8 length = 0x01;
uint8 method = 0x00; // "null" compression
Extensions
Keep it minimal with only SNI (Server Name Indication) – many servers need it nowadays.

Structure:

uint16 extensions_length;
  // Repeated:
  struct {
    uint16 ext_type;
    uint16 ext_length;
    uint8  ext_data[ext_length];
  } Extension;
SNI extension (type 0x0000):
datatracker.ietf.org
+1

struct {
  uint16 extension_type = 0x00 0x00; // server_name
  uint16 extension_length = ...;

  uint16 server_name_list_length;
    uint8  name_type = 0x00;         // host_name
    uint16 host_name_length;
    uint8  host_name[host_name_length]; // ASCII hostname
} ServerNameExtension;
Concrete example for ftp.example.com:

host_name = "ftp.example.com"  // 15 bytes

server_name_list_length = 1 (name_type) + 2 (len) + 15 = 18 = 0x00 0x12
host_name_length = 15 = 0x00 0x0F

ext_data:
  00               // name_type
  00 0F            // host_name_length
  66 74 70 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D // "ftp.example.com"

server_name_list_length = 00 12
// but note: TLS encoding wraps a list of names, so it's:

[server_name_list_length]
[ name_type ]
[ host_name_length ]
[ host_name bytes ]

So ext_data is:
  00 12  // list length
  00     // name_type
  00 0F  // host_name_length
  66 74 70 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D
Then:

extension_type   = 00 00
extension_length = 00 14  // 2 + server_name_list_length (2 + 18 = 20 = 0x14)
ext_data = 00 12 00 00 0F "ftp.example.com"
Finally:

uint16 extensions_length = total length of all extensions blocks
2.3. Assembled ClientHello (pseudo-code)
In Node-ish pseudo-code:

function buildClientHello(hostname) {
  const clientRandom = Buffer.alloc(32);
  clientRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  crypto.randomBytes(28).copy(clientRandom, 4);

  const sessionId = Buffer.alloc(1); // length 0

  // Cipher suites: just TLS_RSA_WITH_AES_128_CBC_SHA
  const cipherSuites = Buffer.alloc(2 + 2); // length + 1 suite
  cipherSuites.writeUInt16BE(2, 0);       // length
  cipherSuites.writeUInt16BE(0x002F, 2);  // suite

  // Compression methods: null
  const compressionMethods = Buffer.from([0x01, 0x00]);

  const hostBuf = Buffer.from(hostname, 'ascii');
  const serverNameListLen = 1 + 2 + hostBuf.length;
  const extData = Buffer.alloc(2 + serverNameListLen);
  extData.writeUInt16BE(serverNameListLen, 0);
  extData.writeUInt8(0x00, 2); // name_type = host_name
  extData.writeUInt16BE(hostBuf.length, 3);
  hostBuf.copy(extData, 5);

  const ext = Buffer.alloc(4 + extData.length);
  ext.writeUInt16BE(0x0000, 0);                 // extension_type = server_name
  ext.writeUInt16BE(extData.length, 2);         // extension_length
  extData.copy(ext, 4);

  const extensions = Buffer.alloc(2 + ext.length);
  extensions.writeUInt16BE(ext.length, 0);      // extensions_length
  ext.copy(extensions, 2);

  // Body = version + random + session_id + cipher_suites + compression + extensions
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),  // client_version TLS1.2
    clientRandom,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions
  ]);

  const handshake = Buffer.alloc(4);
  handshake.writeUInt8(0x01, 0);            // msg_type = ClientHello
  handshake.writeUIntBE(body.length, 1, 3); // length (3 bytes)

  const handshakeMsg = Buffer.concat([handshake, body]);

  // Wrap in record
  const recordHeader = Buffer.alloc(5);
  recordHeader.writeUInt8(0x16, 0);                // Handshake
  recordHeader.writeUInt16BE(0x0303, 1);           // TLS 1.2
  recordHeader.writeUInt16BE(handshakeMsg.length, 3);

  const record = Buffer.concat([recordHeader, handshakeMsg]);

  return {
    clientRandom,
    record,
    rawHandshake: handshakeMsg, // for transcript
  };
}
3. ClientKeyExchange – RSA key exchange
For pure RSA key exchange (TLS_RSA_*), the ClientKeyExchange is conceptually:

struct {
  uint8  msg_type = 16; // ClientKeyExchange
  uint24 length;
  uint8  body[length];
} Handshake;

body:
struct {
  uint16 encrypted_pre_master_secret_length;
  uint8  encrypted_pre_master_secret[...];
} ClientKeyExchange_RSA;
3.1. PreMasterSecret generation
RFC 5246: 48 bytes total:
datatracker.ietf.org
+1

struct {
  uint16 client_version; // MUST be the same as client_version in ClientHello (0x0303)
  opaque random[46];
} PreMasterSecret;
Pseudo-code:

function buildPreMasterSecret() {
  const pms = Buffer.alloc(48);
  pms.writeUInt16BE(0x0303, 0); // TLS 1.2
  crypto.randomBytes(46).copy(pms, 2);
  return pms;
}
3.2. Encrypt PMS with server’s RSA key
You will have parsed the server’s X.509 certificate and extracted its RSA public key (e.g. via crypto.createPublicKey).

Encryption must use PKCS#1 v1.5 padding for TLS 1.2 RSA key exchange.

function encryptPreMasterSecret(preMasterSecret, serverPublicKeyPem) {
  const publicKey = crypto.createPublicKey(serverPublicKeyPem);
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    preMasterSecret
  );
  return encrypted;
}
3.3. Assembling the ClientKeyExchange handshake
function buildClientKeyExchange(encryptedPms) {
  const body = Buffer.alloc(2 + encryptedPms.length);
  body.writeUInt16BE(encryptedPms.length, 0);
  encryptedPms.copy(body, 2);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x10, 0);            // msg_type = ClientKeyExchange (16)
  header.writeUIntBE(body.length, 1, 3); // length

  const handshakeMsg = Buffer.concat([header, body]);

  return handshakeMsg;
}
You’ll then wrap that handshake message in a TLS record:

function wrapHandshakeRecord(handshakeMsg) {
  const recordHeader = Buffer.alloc(5);
  recordHeader.writeUInt8(0x16, 0);               // Handshake
  recordHeader.writeUInt16BE(0x0303, 1);          // TLS 1.2
  recordHeader.writeUInt16BE(handshakeMsg.length, 3);
  return Buffer.concat([recordHeader, handshakeMsg]);
}
4. Finished – computing verify_data and encryption
The Finished message is the first thing protected by the newly negotiated keys.

4.1. TLS 1.2 Finished definition
struct {
  HandshakeType msg_type = finished (20);
  uint24 length;
  opaque verify_data[verify_data_length]; // 12 bytes in TLS 1.2
} Finished;
verify_data is:
datatracker.ietf.org
+1

For client:

verify_data = PRF(master_secret,
                  "client finished",
                  MD5(handshake_messages) + SHA-1(handshake_messages))[12]
For server: same but label "server finished".

Where handshake_messages is the concatenation of all handshake messages sent and received so far, in the exact raw bytes form as carried in the TLS records, but not including the Finished itself.

Important: For TLS 1.2, the PRF uses the negotiated hash (usually SHA-256), but the original spec uses MD5+SHA1 combo; servers typically accept the standard MD5+SHA1 construction for compatibility. To keep it conservative for TLS_RSA_WITH_AES_128_CBC_SHA, you can do the classical MD5+SHA1 variant consistent with RFC 5246, section 7.4.9.
datatracker.ietf.org
+1

A safe pattern:

Compute MD5(handshake_messages) → 16 bytes

Compute SHA1(handshake_messages) → 20 bytes

Concatenate → 36-byte seed for the PRF.

4.2. PRF for TLS 1.2 (HMAC-SHA256 version)
If the server strictly follows TLS 1.2’s “new” PRF (with SHA-256), the PRF is:
datatracker.ietf.org
+1

PRF(secret, label, seed) = P_hash(secret, label + seed)

P_hash(secret, seed):
  A(0) = seed
  A(i) = HMAC_hash(secret, A(i-1))
  output = HMAC_hash(secret, A(1) + seed) ||
           HMAC_hash(secret, A(2) + seed) || ...
  (truncate to needed length)
For verify_data: needed length = 12.

If you want maximum interoperability, use the digest defined by the cipher suite (SHA1 here) or SHA256 (modern TLS 1.2 PRF); you may need to test against your specific FTP server to see what it expects.

4.3. Pseudo-code for computing verify_data
Assuming TLS 1.2 PRF with SHA-256:

function tls12Prf(secret, label, seed, length) {
  const labelBytes = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBytes, seed]);

  function pHash(secret, seed, length) {
    let A = seed;
    let result = Buffer.alloc(0);

    while (result.length < length) {
      A = crypto.createHmac('sha256', secret).update(A).digest();
      const chunk = crypto.createHmac('sha256', secret)
        .update(A)
        .update(seed)
        .digest();
      result = Buffer.concat([result, chunk]);
    }
    return result.subarray(0, length);
  }

  return pHash(secret, fullSeed, length);
}

function computeFinishedVerifyData(masterSecret, handshakeTranscript, label) {
  // MD5 + SHA1 of transcript (classic style)
  const md5 = crypto.createHash('md5').update(handshakeTranscript).digest();
  const sha1 = crypto.createHash('sha1').update(handshakeTranscript).digest();
  const seed = Buffer.concat([md5, sha1]);  // 36 bytes

  const verifyData = tls12Prf(masterSecret, label, seed, 12);
  return verifyData;
}
Then build the Finished handshake:

function buildFinished(masterSecret, handshakeTranscript, forClient) {
  const label = forClient ? "client finished" : "server finished";

  const verifyData = computeFinishedVerifyData(
    masterSecret,
    handshakeTranscript,
    label
  );

  const body = verifyData; // already 12 bytes
  const header = Buffer.alloc(4);
  header.writeUInt8(0x14, 0);           // msg_type = Finished (20)
  header.writeUIntBE(body.length, 1, 3);

  const handshakeMsg = Buffer.concat([header, body]);
  return handshakeMsg;
}
Then you encrypt it via your record layer (AES-CBC + HMAC-SHA1):

Compute MAC over:

8-byte sequence number

Record header (type, version, length BEFORE encryption)

Plaintext (the Finished handshake message)

Append MAC

Add padding to AES block size (16 bytes)

Prepend explicit IV

Wrap in TLS record header

5. Key derivation recap (from PMS to record keys)
Once you have:

preMasterSecret (48 bytes)

client_random (32 bytes from your ClientHello)

server_random (32 bytes from ServerHello)

You compute:
datatracker.ietf.org
+1

5.1. Master secret
master_secret = PRF(pre_master_secret,
                    "master secret",
                    client_random + server_random)[48]
Using same PRF as above (TLS 1.2 style with SHA-256).

Pseudo-code:

function deriveMasterSecret(preMasterSecret, clientRandom, serverRandom) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  return tls12Prf(preMasterSecret, "master secret", seed, 48);
}
5.2. Key block
For TLS_RSA_WITH_AES_128_CBC_SHA you need:

client_write_MAC_key (20 bytes for HMAC-SHA1)

server_write_MAC_key (20)

client_write_key (16 bytes for AES-128)

server_write_key (16)

client_write_IV (16, depending on variant)

server_write_IV (16)

So total 20 + 20 + 16 + 16 + 16 + 16 = 104 bytes.

function deriveKeyBlock(masterSecret, serverRandom, clientRandom, neededLength) {
  const seed = Buffer.concat([serverRandom, clientRandom]);
  return tls12Prf(masterSecret, "key expansion", seed, neededLength);
}
Then slice:

const keyBlock = deriveKeyBlock(masterSecret, serverRandom, clientRandom, 104);

let offset = 0;
const clientWriteMacKey = keyBlock.subarray(offset, offset += 20);
const serverWriteMacKey = keyBlock.subarray(offset, offset += 20);
const clientWriteKey    = keyBlock.subarray(offset, offset += 16);
const serverWriteKey    = keyBlock.subarray(offset, offset += 16);
const clientWriteIV     = keyBlock.subarray(offset, offset += 16);
const serverWriteIV     = keyBlock.subarray(offset, offset += 16);
You install those into your TlsRecordLayer state struct.

6. Record encryption (TLS_RSA_WITH_AES_128_CBC_SHA)
For an outgoing encrypted record (client ➜ server) in your direction:

Maintain an 8-byte seq_num (Buffer) per direction. Start at 0 and increment per record.

Build the TLSInnerPlaintext:

content = plaintext_handshake_or_app_data;
mac = HMAC_SHA1(client_write_MAC_key, seq_num || hdr || content);
plain = content || mac || padding;
hdr = 5-byte TLS header with length = plain.length + IV length, depending on version; some variants compute MAC over length of plaintext only — follow RFC precisely.
datatracker.ietf.org
+1

padding: if block size is 16, add k bytes where k = (block_size - (len(plain)+1) mod block_size) mod block_size; last byte is k, all pad bytes are k.

Choose IV:

For TLS 1.2 with AES-CBC, an explicit IV is prepended to each ciphertext record; use crypto.randomBytes(16).

Encrypt:

const cipher = crypto.createCipheriv('aes-128-cbc', clientWriteKey, iv);
cipher.setAutoPadding(false);
const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
The final fragment = iv || ciphertext.

Set TLS header type/version and length = fragment.length.

Send header + fragment.

For incoming records, you reverse the steps, verify MAC, and reject on mismatch.

7. Where this fits in your FTP AUTH TLS / CCC flow
Putting it all together in rough steps for your client:

Plain FTP step

Connect via net.Socket.

Read 220 service ready.

Send AUTH TLS\r\n, expect 234.

TLS handshake

Switch to TLS mode on the same socket:

Build and send ClientHello record as above.

Read records and parse:

ServerHello (store server_random, chosen cipher)

Certificate (extract RSA pubkey, validate cert)

ServerHelloDone

Generate PreMasterSecret, encrypt with server’s RSA key.

Build & send ClientKeyExchange handshake.

Derive master_secret, then key_block.

Install keys in record layer.

Send ChangeCipherSpec record (type 0x14, version 0x0303, length 1, body [0x01]).

Compute handshake transcript and send encrypted Finished.

Read server’s ChangeCipherSpec + encrypted Finished, verify.

FTP over TLS

Now send USER, PASS, PBSZ, PROT, CCC as ApplicationData records (encrypted using the record layer).

Downgrade (CCC)

After sending CCC and reading 200 reply (still via TLS), expect server to send an Alert close_notify.

Send your close_notify alert.

Mark TLS session CLOSED.

From this point, re-interpret socket bytes as plain FTP text.

If you want, next step I can zoom in on parsing the server’s ServerHello and Certificate messages (binary structures) and sketch how to splice everything into a minimal TlsRecordLayer class + state machine so you can start coding incrementally and test each step with openssl s_client and then your FTP server.

You said:
Seems like a good plan
ChatGPT said:

Thought for 20s
Nice 😄 Then let’s move from “spec” to “thing you can actually code”.

I’ll give you:

A minimal architecture (classes + responsibilities)

How to parse ServerHello

How to parse Certificate

How to glue it into a handshake loop that you can plug onto your FTP AUTH TLS flow

Everything will be happy-path only (one cipher, TLS 1.2, RSA key exchange) — which is exactly what you want for a one-server niche client.

1. Minimal architecture overview
Think in 3 layers:

net.Socket
  ↕
TcpStream        (framing: buffering, readExactly(N), write)
  ↕
TlsRecordLayer  (record framing + optional encrypt/decrypt)
  ↕
TlsClient       (handshake state machine, key derivation)
  ↕
FtpsClient      (FTP commands, AUTH TLS, CCC, etc.)
Rough TypeScript-ish shapes:

type TlsState = "PLAIN" | "HANDSHAKE" | "ENCRYPTED" | "CLOSED";

class TcpStream {
  constructor(private socket: net.Socket) {}
  async readExactly(n: number): Promise<Buffer> {}
  async write(buf: Buffer): Promise<void> {}
}

interface CipherState {
  clientWriteMacKey: Buffer;
  serverWriteMacKey: Buffer;
  clientWriteKey: Buffer;
  serverWriteKey: Buffer;
  clientWriteIV: Buffer;
  serverWriteIV: Buffer;
  clientSeqNum: bigint;
  serverSeqNum: bigint;
}

class TlsRecordLayer {
  state: TlsState = "PLAIN";
  version = 0x0303;
  cipher?: CipherState;

  constructor(private tcp: TcpStream) {}

  async writePlainRecord(type: number, data: Buffer): Promise<void> {}
  async readPlainRecord(): Promise<{ type: number; fragment: Buffer }> {}

  async writeEncryptedRecord(type: number, data: Buffer): Promise<void> {}
  async readEncryptedRecord(): Promise<{ type: number; fragment: Buffer }> {}

  async sendChangeCipherSpec(): Promise<void> {}
  async sendAlertCloseNotify(): Promise<void> {}
}
Then:

class TlsClient {
  clientRandom!: Buffer;
  serverRandom!: Buffer;
  preMasterSecret!: Buffer;
  masterSecret!: Buffer;
  handshakeTranscript: Buffer[] = [];
  serverCertChain: Buffer[] = [];

  constructor(private recordLayer: TlsRecordLayer) {}

  async doHandshake(hostname: string): Promise<void> {}
}
2. Parsing ServerHello
2.1. First: generic handshake parser
You already know: any handshake message = 1-byte type + 3-byte length.

Helper:

interface HandshakeMsg {
  type: number;    // 1=ClientHello, 2=ServerHello, 11=Certificate, 14=ServerHelloDone, etc.
  body: Buffer;    // raw body
  raw: Buffer;     // header + body, for transcript
}

async function readHandshakeMessage(recordLayer: TlsRecordLayer): Promise<HandshakeMsg> {
  const { type, fragment } = await recordLayer.readPlainRecord(); // still unencrypted at this point
  if (type !== 0x16) {
    throw new Error(`Expected Handshake record, got type ${type}`);
  }
  if (fragment.length < 4) throw new Error("Handshake fragment too short");

  const msgType = fragment.readUInt8(0);
  const length = fragment.readUIntBE(1, 3);
  if (fragment.length < 4 + length) {
    throw new Error("Incomplete handshake message in record");
  }

  const body = fragment.subarray(4, 4 + length);
  const raw = fragment.subarray(0, 4 + length);

  return { type: msgType, body, raw };
}
For simplicity, assume the record only contains a single handshake message (valid for small messages like ServerHello). If you want to be rigorous, you’d loop over multiple handshake messages inside a single record; you can add that later.

You’ll store raw into handshakeTranscript.

2.2. ServerHello structure
Body layout:

struct {
  ProtocolVersion server_version;    // 2 bytes
  Random random;                     // 32 bytes
  SessionID session_id;              // 1 byte length + data
  CipherSuite cipher_suite;          // 2 bytes
  CompressionMethod compression;     // 1 byte
  Extension extensions<0..2^16-1>;   // 2 bytes length + data
} ServerHello;
Parser:

interface ParsedServerHello {
  version: number;         // 0x0303
  random: Buffer;          // 32 bytes
  sessionId: Buffer;       // may be empty
  cipherSuite: number;     // 0x002F
  compression: number;     // 0x00
  extensions: Map<number, Buffer>; // type -> raw data
}

function parseServerHello(body: Buffer): ParsedServerHello {
  let offset = 0;

  const version = body.readUInt16BE(offset); offset += 2;

  const random = body.subarray(offset, offset + 32);
  if (random.length !== 32) throw new Error("Invalid ServerHello.random length");
  offset += 32;

  const sessionIdLen = body.readUInt8(offset); offset += 1;
  const sessionId = body.subarray(offset, offset + sessionIdLen);
  offset += sessionIdLen;

  const cipherSuite = body.readUInt16BE(offset); offset += 2;
  const compression = body.readUInt8(offset); offset += 1;

  let extensions = new Map<number, Buffer>();
  if (offset < body.length) {
    const extensionsLen = body.readUInt16BE(offset); offset += 2;
    const end = offset + extensionsLen;
    if (end > body.length) throw new Error("Invalid ServerHello.extensions length");

    while (offset + 4 <= end) {
      const extType = body.readUInt16BE(offset); offset += 2;
      const extLen = body.readUInt16BE(offset); offset += 2;
      const extData = body.subarray(offset, offset + extLen);
      offset += extLen;
      extensions.set(extType, extData);
    }
  }

  return { version, random, sessionId, cipherSuite, compression, extensions };
}
In your TlsClient.doHandshake:

// after sending ClientHello:
const serverHelloMsg = await readHandshakeMessage(this.recordLayer);
if (serverHelloMsg.type !== 0x02) throw new Error("Expected ServerHello");
this.handshakeTranscript.push(serverHelloMsg.raw);

const sh = parseServerHello(serverHelloMsg.body);
this.serverRandom = sh.random;

if (sh.version !== 0x0303) throw new Error(`Unsupported TLS version 0x${sh.version.toString(16)}`);
if (sh.cipherSuite !== 0x002F) throw new Error(`Server selected unsupported cipher suite 0x${sh.cipherSuite.toString(16)}`);
if (sh.compression !== 0x00) throw new Error("Server selected non-null compression");
You can inspect extensions if you want, but strictly you don’t need to.

3. Parsing Certificate
The Certificate handshake body (TLS 1.2) is:

struct {
  opaque certificate_list<0..2^24-1>;
} Certificate;

certificate_list:
  uint24 total_length;
  repeated:
    uint24 cert_length;
    opaque cert_data[cert_length];   // DER-encoded X.509
Parser:

function parseCertificate(body: Buffer): Buffer[] {
  let offset = 0;

  if (body.length < 3) throw new Error("Certificate message too short");
  const totalLen = body.readUIntBE(0, 3);
  offset += 3;

  if (offset + totalLen > body.length) {
    throw new Error("Invalid certificate_list length");
  }

  const end = offset + totalLen;
  const certs: Buffer[] = [];

  while (offset + 3 <= end) {
    const certLen = body.readUIntBE(offset, 3);
    offset += 3;
    const cert = body.subarray(offset, offset + certLen);
    offset += certLen;
    certs.push(cert);
  }

  return certs;
}
In the handshake:

const certMsg = await readHandshakeMessage(this.recordLayer);
if (certMsg.type !== 0x0b) throw new Error("Expected Certificate");
this.handshakeTranscript.push(certMsg.raw);

this.serverCertChain = parseCertificate(certMsg.body);
if (this.serverCertChain.length === 0) {
  throw new Error("Empty certificate chain");
}
Now you have serverCertChain[0] as DER (Buffer). For Node’s crypto, you can convert to PEM or pass DER directly depending on methods you use:

function derToPem(der: Buffer, label: string): string {
  const base64 = der.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

// For an X.509 cert:
const serverCertPem = derToPem(this.serverCertChain[0], "CERTIFICATE");
const publicKey = crypto.createPublicKey(serverCertPem);
For a niche one-server client, you can:

Either validate the chain properly (node-forge, PKI libraries, or spawning openssl), or

Pin the server cert: compare SHA256 hash with a known value and accept only if it matches.

4. The rest of the handshake in a happy-path loop
Let’s outline TlsClient.doHandshake(hostname) now that you can parse ServerHello and Certificate:

class TlsClient {
  constructor(private recordLayer: TlsRecordLayer) {}

  async doHandshake(hostname: string) {
    // 1) Build & send ClientHello
    const { clientRandom, record, rawHandshake } = buildClientHello(hostname);
    this.clientRandom = clientRandom;
    this.handshakeTranscript = [rawHandshake];

    await this.recordLayer.writePlainRecord(0x16, record.subarray(5)); 
    // or just tcp.write(record) if your writePlainRecord expects full record

    // 2) Read ServerHello
    let msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x02) throw new Error("Expected ServerHello");
    this.handshakeTranscript.push(msg.raw);

    const sh = parseServerHello(msg.body);
    this.serverRandom = sh.random;
    // check version, cipher, etc.

    // 3) Read Certificate
    msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x0b) throw new Error("Expected Certificate");
    this.handshakeTranscript.push(msg.raw);

    this.serverCertChain = parseCertificate(msg.body);

    // TODO: validate server certificate (or pin it)
    const serverCertPem = derToPem(this.serverCertChain[0], "CERTIFICATE");
    const publicKey = crypto.createPublicKey(serverCertPem);

    // 4) Possibly ServerHelloDone comes after optional messages
    //   In pure RSA, you expect ServerHelloDone next (type=14)
    msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x0e) throw new Error("Expected ServerHelloDone");
    this.handshakeTranscript.push(msg.raw);

    // 5) Build PMS, ClientKeyExchange
    this.preMasterSecret = buildPreMasterSecret();
    const encPms = encryptPreMasterSecret(this.preMasterSecret, serverCertPem);
    const ckxHandshake = buildClientKeyExchange(encPms);
    this.handshakeTranscript.push(ckxHandshake);

    // 6) Derive keys
    this.masterSecret = deriveMasterSecret(this.preMasterSecret, this.clientRandom, this.serverRandom);
    const keyBlock = deriveKeyBlock(this.masterSecret, this.serverRandom, this.clientRandom, 104);
    const cipherState = sliceKeyBlock(keyBlock); // your helper to populate CipherState

    // 7) Send ClientKeyExchange as plaintext Handshake record
    const ckxRecord = wrapHandshakeRecord(ckxHandshake);
    await this.recordLayer.writePlainRecord(0x16, ckxRecord.subarray(5));

    // 8) Send ChangeCipherSpec (plaintext)
    await this.recordLayer.installPendingCipher(cipherState); // mark cipher but not yet active
    await this.recordLayer.sendChangeCipherSpec();           // state: will use cipher for next writes

    // 9) Send Finished (first encrypted message)
    const transcriptBuf = Buffer.concat(this.handshakeTranscript);
    const finishedHandshake = buildFinished(this.masterSecret, transcriptBuf, true); // forClient = true
    // Once built, you must also append this raw Finished to transcript for server's verification,
    // but in TLS 1.2, the Finished verify_data is computed over *previous* messages, not including this one.
    await this.recordLayer.writeEncryptedRecord(0x16, finishedHandshake);
    this.handshakeTranscript.push(finishedHandshake);

    // 10) Read server ChangeCipherSpec + Finished
    // CCS: record type 0x14, payload [0x01]
    const ccs = await this.recordLayer.readPlainRecord();
    if (ccs.type !== 0x14) throw new Error("Expected ChangeCipherSpec from server");
    // at this moment, you mark server->client direction as ENCRYPTED

    const srvFinishedRec = await this.recordLayer.readEncryptedRecord();
    if (srvFinishedRec.type !== 0x16) throw new Error("Expected Handshake record for server Finished");
    const srvFinished = parseFinishedHandshake(srvFinishedRec.fragment); // type=0x14, verify_data

    // Verify server Finished
    const transcriptForServer = Buffer.concat(this.handshakeTranscript);
    const expected = computeFinishedVerifyData(this.masterSecret, transcriptForServer, "server finished");
    if (!srvFinished.verifyData.equals(expected)) {
      throw new Error("Server Finished verify_data mismatch");
    }

    // Handshake complete: both directions encrypted, ready for AppData
    this.recordLayer.state = "ENCRYPTED";
  }
}
Note:

I’m glossing over some details to keep the code readable (how writePlainRecord expects its arguments, when you exactly flip to ENCRYPTED state internally).

Conceptually:

Before CCS, both directions use plaintext records.

After sending your CCS, your outbound direction uses encryption.

After receiving server’s CCS, inbound direction uses decryption.

5. Integrating CCC / TLS shutdown
Once handshake is done, your FtpsClient:

Uses recordLayer.writeEncryptedRecord(0x17, ftpCommandBuffer) to send commands.

Uses recordLayer.readEncryptedRecord() and parses the FTP replies from decrypted bytes.

After CCC and the 200 reply:

Expect a TLS Alert with close_notify from server (type 0x15, level warning(1)/fatal(2) + description 0).

Call sendAlertCloseNotify() on your side.

Mark recordLayer.state = "CLOSED".

From now on, you read/write bytes through TcpStream directly as plain text FTP.

Your TlsRecordLayer will need:

async sendAlertCloseNotify() {
  const alert = Buffer.from([0x01, 0x00]); // warning, close_notify (0)
  // if already encrypted, sendEncryptedRecord; if still plaintext, sendPlainRecord
}
Once both sides have closed TLS, don’t attempt to parse any more TLS records on that socket — just treat it as raw FTP.

If you want, next step I can help you:

Sketch a minimal TlsRecordLayer with real readPlainRecord / writePlainRecord / writeEncryptedRecord including AES-CBC+HMAC-SHA1 MACing and padding, so you have a full “skeleton stack” ready to start testing against openssl s_client first, then your FTP server.

You said:
Yes please
ChatGPT said:

Thought for 40s
Nice, let’s build the “engine room” 😊
Below is a minimal-but-realistic TlsRecordLayer you can adapt. It:

Works over a net.Socket via a small TcpStream.

Implements:

Plain records (handshake phase)

AES-128-CBC + HMAC-SHA1 encrypted records (TLS_RSA_WITH_AES_128_CBC_SHA)

Sequence numbers

MAC calculation

Padding

ChangeCipherSpec

close_notify alert

It’s deliberately single-direction client (you’re the client), but handles both inbound and outbound keys.

⚠️ This is still a simplified implementation. It’s enough to get you talking to your specific FTP server and experimenting with AUTH TLS + CCC, but you should treat it as experimental code, not production-grade TLS.

1. TcpStream helper (buffered readExactly)
import * as net from "net";
import * as crypto from "crypto";

class TcpStream {
  private buffer = Buffer.alloc(0);

  constructor(private socket: net.Socket) {
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
    });
  }

  async readExactly(n: number): Promise<Buffer> {
    if (n === 0) return Buffer.alloc(0);

    while (this.buffer.length < n) {
      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error) => {
          this.socket.off("error", onError);
          reject(err);
        };
        this.socket.once("error", onError);
        this.socket.once("data", () => {
          this.socket.off("error", onError);
          resolve();
        });
      });
    }
    const out = this.buffer.subarray(0, n);
    this.buffer = this.buffer.subarray(n);
    return out;
  }

  async write(buf: Buffer): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.socket.write(buf, (err?: Error | null) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
2. Cipher state & helpers
type TlsState = "PLAIN" | "ENCRYPTING" | "ENCRYPTED" | "CLOSED";

interface CipherState {
  clientWriteMacKey: Buffer;
  serverWriteMacKey: Buffer;
  clientWriteKey: Buffer;
  serverWriteKey: Buffer;
  clientWriteIV: Buffer;   // initial IV (used/updated per record)
  serverWriteIV: Buffer;
  clientSeqNum: bigint;
  serverSeqNum: bigint;
}

// Increment 64-bit sequence number (BigInt)
function incSeq(num: bigint): bigint {
  return num + 1n;
}
3. TlsRecordLayer skeleton
class TlsRecordLayer {
  public state: TlsState = "PLAIN";
  public version: number = 0x0303; // TLS 1.2

  private cipher?: CipherState;

  constructor(private tcp: TcpStream) {}

  installCipher(cipher: CipherState) {
    this.cipher = cipher;
    // Initially, still in PLAIN for handshake; we only switch writes
    // to encrypted after Client CCS (ENCRYPTING).
  }

  // === Plain record I/O (handshake phase) ===

  async writePlainRecord(contentType: number, fragment: Buffer): Promise<void> {
    if (this.state === "CLOSED") {
      throw new Error("TLS connection closed");
    }

    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);           // type
    header.writeUInt16BE(this.version, 1);       // version
    header.writeUInt16BE(fragment.length, 3);    // length (plaintext)

    const record = Buffer.concat([header, fragment]);
    await this.tcp.write(record);
  }

  async readPlainRecord(): Promise<{ type: number; fragment: Buffer }> {
    if (this.state === "CLOSED") {
      throw new Error("TLS connection closed");
    }

    const header = await this.tcp.readExactly(5);
    const type = header.readUInt8(0);
    const ver = header.readUInt16BE(1);
    const length = header.readUInt16BE(3);

    if (ver !== this.version) {
      // You may want to relax this, but let's keep it strict
      throw new Error(`Unexpected TLS version in record: 0x${ver.toString(16)}`);
    }

    const fragment = await this.tcp.readExactly(length);
    return { type, fragment };
  }

  // === ChangeCipherSpec & Alert helpers ===

  async sendChangeCipherSpec(): Promise<void> {
    // CCS is always a single byte of value 1
    const body = Buffer.from([0x01]);
    await this.writePlainRecord(0x14, body); // type 0x14 = ChangeCipherSpec

    // After CCS, all *outgoing* records must be encrypted.
    if (!this.cipher) throw new Error("Cipher state not installed");
    this.state = "ENCRYPTING";
  }

  async sendAlertCloseNotify(): Promise<void> {
    const alert = Buffer.from([
      0x01, // level: warning (1)
      0x00, // description: close_notify (0)
    ]);

    if (this.state === "PLAIN") {
      await this.writePlainRecord(0x15, alert); // Alert = 0x15
    } else if (this.state === "ENCRYPTING" || this.state === "ENCRYPTED") {
      await this.writeEncryptedRecord(0x15, alert);
    }

    // After we send close_notify, we won't send further app data.
    // You may still want to read the peer's close_notify before
    // truly marking connection CLOSED.
  }

  // === Encrypted record I/O (post-CCS) ===

  async writeEncryptedRecord(contentType: number, plaintext: Buffer): Promise<void> {
    if (!this.cipher) throw new Error("Cipher state not installed");
    if (this.state !== "ENCRYPTING" && this.state !== "ENCRYPTED") {
      throw new Error("Cannot write encrypted record while not in ENCRYPTING/ENCRYPTED state");
    }
    const c = this.cipher;

    const seqNum = c.clientSeqNum;
    const macKey = c.clientWriteMacKey;
    const encKey = c.clientWriteKey;

    // 1) Build MAC input: seq_num(8) || type(1) || version(2) || length(2) || plaintext
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(contentType, 0);
    headerForMac.writeUInt16BE(this.version, 1);
    headerForMac.writeUInt16BE(plaintext.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, plaintext]);
    const mac = crypto.createHmac("sha1", macKey).update(macInput).digest(); // 20 bytes

    // 2) Plain fragment before padding: plaintext || mac
    let plain = Buffer.concat([plaintext, mac]);

    // 3) Add PKCS#7-style padding to block size 16 (AES)
    const blockSize = 16;
    const padLen = blockSize - ((plain.length + 1) % blockSize);
    const pad = Buffer.alloc(padLen + 1, padLen); // each byte = padLen
    plain = Buffer.concat([plain, pad]);

    // 4) Explicit IV (TLS 1.2 CBC uses 16-byte explicit IV per record)
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv("aes-128-cbc", encKey, iv);
    cipher.setAutoPadding(false); // we're doing padding manually
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

    const fragment = Buffer.concat([iv, encrypted]);

    // 5) Build record header for wire: length = fragment.length
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(this.version, 1);
    header.writeUInt16BE(fragment.length, 3);

    await this.tcp.write(Buffer.concat([header, fragment]));

    // 6) Increment client sequence number
    c.clientSeqNum = incSeq(seqNum);
    this.state = "ENCRYPTED";
  }

  async readEncryptedRecord(): Promise<{ type: number; fragment: Buffer }> {
    if (!this.cipher) throw new Error("Cipher state not installed");

    const header = await this.tcp.readExactly(5);
    const type = header.readUInt8(0);
    const ver = header.readUInt16BE(1);
    const length = header.readUInt16BE(3);

    if (ver !== this.version) {
      throw new Error(`Unexpected TLS version in encrypted record: 0x${ver.toString(16)}`);
    }

    const fragment = await this.tcp.readExactly(length);
    const c = this.cipher;

    const seqNum = c.serverSeqNum;
    const macKey = c.serverWriteMacKey;
    const encKey = c.serverWriteKey;

    // 1) Split IV + ciphertext
    if (fragment.length < 16) {
      throw new Error("Encrypted fragment too short (no IV)");
    }
    const iv = fragment.subarray(0, 16);
    const ciphertext = fragment.subarray(16);

    // 2) Decrypt
    const decipher = crypto.createDecipheriv("aes-128-cbc", encKey, iv);
    decipher.setAutoPadding(false);
    let plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // 3) Remove padding
    if (plain.length === 0) throw new Error("Decrypted plaintext empty");
    const padLen = plain[plain.length - 1];
    const totalPadLen = padLen + 1;
    if (totalPadLen > plain.length) {
      throw new Error("Invalid padding length");
    }
    // Optionally: constant-time check all padding bytes equal padLen
    plain = plain.subarray(0, plain.length - totalPadLen);

    // 4) Split MAC and content
    if (plain.length < 20) {
      throw new Error("Plaintext too short to contain HMAC-SHA1");
    }
    const content = plain.subarray(0, plain.length - 20);
    const macRecv = plain.subarray(plain.length - 20);

    // 5) Recompute MAC
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(type, 0);
    headerForMac.writeUInt16BE(ver, 1);
    headerForMac.writeUInt16BE(content.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, content]);
    const macExpected = crypto.createHmac("sha1", macKey).update(macInput).digest();

    if (!crypto.timingSafeEqual(macRecv, macExpected)) {
      throw new Error("TLS MAC verification failed");
    }

    // 6) Increment server seq num
    c.serverSeqNum = incSeq(seqNum);

    return { type, fragment: content };
  }
}
Note on MAC header: we use content.length (plaintext length) in the headerForMac length field, per TLS spec (compressed length). We don’t include IV or padding in that length. That’s why we build headerForMac separately from the wire header.

4. Creating CipherState from your key_block
When your TlsClient has derived key_block (104 bytes for TLS_RSA_WITH_AES_128_CBC_SHA), slice it into the CipherState:

function makeCipherStateFromKeyBlock(keyBlock: Buffer): CipherState {
  let offset = 0;
  const clientWriteMacKey = keyBlock.subarray(offset, offset += 20);
  const serverWriteMacKey = keyBlock.subarray(offset, offset += 20);
  const clientWriteKey    = keyBlock.subarray(offset, offset += 16);
  const serverWriteKey    = keyBlock.subarray(offset, offset += 16);
  const clientWriteIV     = keyBlock.subarray(offset, offset += 16);
  const serverWriteIV     = keyBlock.subarray(offset, offset += 16);

  return {
    clientWriteMacKey,
    serverWriteMacKey,
    clientWriteKey,
    serverWriteKey,
    clientWriteIV,
    serverWriteIV,
    clientSeqNum: 0n,
    serverSeqNum: 0n,
  };
}
Then in your handshake code:

const keyBlock = deriveKeyBlock(masterSecret, serverRandom, clientRandom, 104);
const cipherState = makeCipherStateFromKeyBlock(keyBlock);
recordLayer.installCipher(cipherState);
// send CCS, then use writeEncryptedRecord for Finished & later
5. How this plugs into your FTPS flow
Control connection (AUTH TLS + CCC) overview:

Plain FTP: AUTH TLS ➜ get 234.

Run TlsClient.doHandshake():

Uses recordLayer.writePlainRecord() / readPlainRecord() for all handshake messages.

Installs cipher state, sends CCS, then writeEncryptedRecord() for Finished.

Receives server CCS + readEncryptedRecord() for server Finished.

Now for FTP commands (USER/PASS/PBSZ/PROT/CCC), you:

encode as ASCII lines (Buffer.from("USER foo\r\n"))

send with recordLayer.writeEncryptedRecord(0x17, commandBuf)

receive responses with recordLayer.readEncryptedRecord() and parse FTP status lines from fragment.

When you send CCC and get 200 back (still via TLS):

Server should send close_notify alert.

You detect type === 0x15 (Alert) in readEncryptedRecord(), parse level/description from fragment:

[level, description] = fragment

if description === 0: close_notify

You call recordLayer.sendAlertCloseNotify() back.

Then set recordLayer.state = "CLOSED" and stop using it.

From that moment, go back to TcpStream directly for plain FTP over same socket.

If you’d like, next step I can:

Show a tiny test harness that:

connects to some TLS server,

runs your TlsRecordLayer + TlsClient just up to handshake,

and compares behavior with openssl s_client,
so you can debug handshake/record issues before you integrate with the FTP server and AUTH TLS + CCC.

You said:
Yes perfect
ChatGPT said:

Thought for 21s
Nice, let’s wire this thing up into something you can actually run and debug 😎

Below is a minimal test harness that:

Connects to your FTP server on port 21

Does the plain FTP banner + AUTH TLS exchange

Runs your custom TLS handshake on the same socket

Sends a test FTP command (USER) inside TLS

(Later you’ll add PASS, PBSZ, PROT, CCC, etc.)

I’ll keep everything in one file so it’s easier to tweak. You can then refactor into modules.

1. Assumptions
I’ll assume you already have (from our previous messages):

buildClientHello, buildPreMasterSecret, encryptPreMasterSecret,
buildClientKeyExchange, deriveMasterSecret, deriveKeyBlock,
buildFinished, computeFinishedVerifyData, etc.

parseServerHello, parseCertificate, readHandshakeMessage

TcpStream and TlsRecordLayer as we just designed

makeCipherStateFromKeyBlock helper

I’ll now:

Show a minimal TlsClient skeleton that uses those helpers.

Show a runFtpsAuthTlsTest() harness using your FTP server.

You’ll fill in any missing helpers from your earlier code.

2. Minimal TlsClient that uses TlsRecordLayer
import * as net from "net";
import * as crypto from "crypto";

// ---- assume these are implemented somewhere ----
// - TcpStream
// - TlsRecordLayer
// - buildClientHello
// - readHandshakeMessage
// - parseServerHello
// - parseCertificate
// - derToPem
// - buildPreMasterSecret
// - encryptPreMasterSecret
// - buildClientKeyExchange
// - wrapHandshakeRecord
// - deriveMasterSecret
// - deriveKeyBlock
// - makeCipherStateFromKeyBlock
// - buildFinished
// - computeFinishedVerifyData
// ------------------------------------------------

class TlsClient {
  clientRandom!: Buffer;
  serverRandom!: Buffer;
  preMasterSecret!: Buffer;
  masterSecret!: Buffer;
  handshakeTranscript: Buffer[] = [];
  serverCertChain: Buffer[] = [];

  constructor(private recordLayer: TlsRecordLayer) {}

  async doHandshake(hostname: string) {
    // 1) ClientHello
    const { clientRandom, record, rawHandshake } = buildClientHello(hostname);
    this.clientRandom = clientRandom;
    this.handshakeTranscript.push(rawHandshake);

    // record is full TLS record (5-byte header + body)
    // If your TlsRecordLayer.writePlainRecord expects only fragment,
    // you can instead do:
    const fragment = record.subarray(5);
    await this.recordLayer.writePlainRecord(0x16, fragment);
    console.log("[TLS] Sent ClientHello");

    // 2) ServerHello
    let msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x02) throw new Error("Expected ServerHello");
    this.handshakeTranscript.push(msg.raw);
    const sh = parseServerHello(msg.body);
    this.serverRandom = sh.random;
    console.log("[TLS] Got ServerHello, cipher = 0x" + sh.cipherSuite.toString(16));

    if (sh.cipherSuite !== 0x002F) {
      throw new Error("Server chose unsupported cipher suite (expected 0x002F)");
    }

    // 3) Certificate
    msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x0b) throw new Error("Expected Certificate");
    this.handshakeTranscript.push(msg.raw);
    this.serverCertChain = parseCertificate(msg.body);
    console.log("[TLS] Got Certificate chain, length =", this.serverCertChain.length);

    if (this.serverCertChain.length === 0) {
      throw new Error("Empty certificate chain");
    }

    // For a niche client you can pin the cert instead of full PKI validation
    const serverCertPem = derToPem(this.serverCertChain[0], "CERTIFICATE");
    const publicKey = crypto.createPublicKey(serverCertPem);
    console.log("[TLS] Extracted server public key");

    // 4) ServerHelloDone (assuming pure RSA, no ServerKeyExchange)
    msg = await readHandshakeMessage(this.recordLayer);
    if (msg.type !== 0x0e) throw new Error("Expected ServerHelloDone");
    this.handshakeTranscript.push(msg.raw);
    console.log("[TLS] Got ServerHelloDone");

    // 5) PMS + ClientKeyExchange
    this.preMasterSecret = buildPreMasterSecret();
    const encPms = encryptPreMasterSecret(this.preMasterSecret, serverCertPem);
    const ckxHandshake = buildClientKeyExchange(encPms);
    this.handshakeTranscript.push(ckxHandshake);

    // 6) derive keys
    this.masterSecret = deriveMasterSecret(
      this.preMasterSecret,
      this.clientRandom,
      this.serverRandom
    );
    const keyBlock = deriveKeyBlock(this.masterSecret, this.serverRandom, this.clientRandom, 104);
    const cipherState = makeCipherStateFromKeyBlock(keyBlock);

    // 7) send ClientKeyExchange (still plaintext)
    const ckxRecord = wrapHandshakeRecord(ckxHandshake);
    await this.recordLayer.writePlainRecord(0x16, ckxRecord.subarray(5));
    console.log("[TLS] Sent ClientKeyExchange");

    // 8) install cipher + send CCS
    this.recordLayer.installCipher(cipherState);
    await this.recordLayer.sendChangeCipherSpec();
    console.log("[TLS] Sent ChangeCipherSpec");

    // 9) send Finished (first encrypted record)
    const transcriptBeforeFinished = Buffer.concat(this.handshakeTranscript);
    const finishedHandshake = buildFinished(
      this.masterSecret,
      transcriptBeforeFinished,
      true // forClient
    );
    await this.recordLayer.writeEncryptedRecord(0x16, finishedHandshake);
    this.handshakeTranscript.push(finishedHandshake);
    console.log("[TLS] Sent Finished");

    // 10) read server CCS
    const ccs = await this.recordLayer.readPlainRecord();
    if (ccs.type !== 0x14 || ccs.fragment.length !== 1 || ccs.fragment[0] !== 0x01) {
      throw new Error("Expected server ChangeCipherSpec");
    }
    console.log("[TLS] Got server ChangeCipherSpec");

    // 11) read server Finished (encrypted)
    const srvFinishedRec = await this.recordLayer.readEncryptedRecord();
    if (srvFinishedRec.type !== 0x16) {
      throw new Error("Expected Handshake record for server Finished");
    }
    const srvFinishedFrag = srvFinishedRec.fragment;
    if (srvFinishedFrag[0] !== 0x14) {
      throw new Error("Expected Finished handshake type (20)");
    }
    const srvFinishedLen = srvFinishedFrag.readUIntBE(1, 3);
    const srvVerifyData = srvFinishedFrag.subarray(4, 4 + srvFinishedLen);

    // verify server Finished
    const transcriptForServer = Buffer.concat(this.handshakeTranscript);
    const expected = computeFinishedVerifyData(
      this.masterSecret,
      transcriptForServer,
      "server finished"
    );
    if (!crypto.timingSafeEqual(srvVerifyData, expected)) {
      throw new Error("Server Finished verify_data mismatch");
    }
    console.log("[TLS] Server Finished OK, handshake complete");
  }
}
3. Tiny FTP helper for the control channel
We need something to:

Read FTP lines (\r\n) over plain TCP

Send commands easily

class FtpControl {
  private buffer = Buffer.alloc(0);

  constructor(private socket: net.Socket) {
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
    });
  }

  async readLine(): Promise<string> {
    while (true) {
      const idx = this.buffer.indexOf("\r\n");
      if (idx !== -1) {
        const lineBuf = this.buffer.subarray(0, idx);
        this.buffer = this.buffer.subarray(idx + 2);
        return lineBuf.toString("ascii");
      }
      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error) => {
          this.socket.off("error", onError);
          reject(err);
        };
        this.socket.once("error", onError);
        this.socket.once("data", () => {
          this.socket.off("error", onError);
          resolve();
        });
      });
    }
  }

  async sendCommand(cmd: string): Promise<void> {
    const line = cmd.endsWith("\r\n") ? cmd : cmd + "\r\n";
    await new Promise<void>((resolve, reject) => {
      this.socket.write(line, (err?: Error | null) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
4. The FTPS AUTH TLS test harness
This is the thing you actually run:

async function runFtpsAuthTlsTest() {
  const host = "your.ftp.server"; // TODO
  const port = 21;

  const socket = net.createConnection({ host, port });

  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });

  console.log(`[FTP] Connected to ${host}:${port}`);

  const ftp = new FtpControl(socket);

  // 1) Read FTP banner (e.g., "220 Service ready")
  const banner = await ftp.readLine();
  console.log("[FTP] Banner:", banner);

  // 2) Send AUTH TLS
  await ftp.sendCommand("AUTH TLS");
  const authReply = await ftp.readLine();
  console.log("[FTP] AUTH TLS reply:", authReply);

  if (!authReply.startsWith("234")) {
    throw new Error("Expected 234 reply to AUTH TLS, got: " + authReply);
  }

  // 3) Wrap the same socket into TcpStream and TlsRecordLayer
  const tcpStream = new TcpStream(socket);
  const recordLayer = new TlsRecordLayer(tcpStream);
  const tlsClient = new TlsClient(recordLayer);

  // 4) Perform TLS handshake
  await tlsClient.doHandshake(host);

  console.log("[FTPS] TLS handshake complete, now sending USER inside TLS");

  // 5) Send FTP USER over TLS as ApplicationData (type 0x17)
  const user = "anonymous"; // or your actual user
  const cmdBuf = Buffer.from(`USER ${user}\r\n`, "ascii");
  await recordLayer.writeEncryptedRecord(0x17, cmdBuf);

  // 6) Read FTP reply line over TLS
  const reply = await readFtpLineOverTls(recordLayer);
  console.log("[FTPS] Reply to USER:", reply);

  // You can continue with PASS, PBSZ, PROT, CCC, etc.
  // ...
}
We just need readFtpLineOverTls, which is basically FtpControl.readLine but over decrypted TLS records.

5. FTP line reader on top of TLS ApplicationData
You’re going to get FTP data split across TLS records. We’ll maintain a small buffer of decrypted bytes and parse \r\n.

async function readFtpLineOverTls(recordLayer: TlsRecordLayer): Promise<string> {
  let appBuffer = Buffer.alloc(0);

  while (true) {
    // read next application record (type 0x17)
    const rec = await recordLayer.readEncryptedRecord();
    if (rec.type !== 0x17) {
      if (rec.type === 0x15) {
        // Alert: close_notify, etc.
        const level = rec.fragment[0];
        const desc = rec.fragment[1];
        throw new Error(`TLS alert from server: level=${level}, desc=${desc}`);
      }
      throw new Error("Unexpected TLS record type " + rec.type);
    }

    appBuffer = Buffer.concat([appBuffer, rec.fragment]);

    // try to find CRLF
    const idx = appBuffer.indexOf("\r\n");
    if (idx !== -1) {
      const lineBuf = appBuffer.subarray(0, idx);
      appBuffer = appBuffer.subarray(idx + 2);
      return lineBuf.toString("ascii");
    }

    // else loop and get more application data
  }
}
Later, when you implement CCC:

You’ll send CCC\r\n via writeEncryptedRecord.

Read the 200 reply via readFtpLineOverTls.

Then expect an Alert close_notify from server with readEncryptedRecord().

Call recordLayer.sendAlertCloseNotify().

Set recordLayer.state = "CLOSED".

From that point, use FtpControl (or similar) directly on the raw socket for plain FTP.

6. How to actually run this
Put all of this into a TypeScript or JS file.

Fill the TODOs:

host of your FTP server

actual user/pass

import/implement all helper functions we sketched in previous messages.

Add:

runFtpsAuthTlsTest()
  .then(() => {
    console.log("Done.");
    process.exit(0);
  })
  .catch((err) => {
    console.error("Error:", err);
    process.exit(1);
  });
Run with ts-node or node (if you transpile).

If you want, next step I can:

Help you write a really small “local echo” test server in Node that uses the real tls module, so you can point your custom stack at it and debug the handshake / record logic in a controlled environment before hitting the actual FTP server.

You said:
Good idea
ChatGPT said:
AWESOME — a controlled test environment will save you days of debugging against a real FTP server.

Below is a minimal custom TLS test server written in Node without using tls.createServer.
Why? Because the point is to simulate the FTP server as your code will see it:

Plain TCP first

Then TLS handshake triggered by receiving the string AUTH TLS\r\n

Then send a 234 FTP reply

Then speak full TLS records (ServerHello, Certificate, etc.) using Node’s native TLS implementation as the backend, while you manually control the network bytes.

This lets you do:

Test your ClientHello parsing

Test your record-layer encrypt/decrypt

Inspect every incoming/outgoing TLS structure

Verify your CCS / Finished logic

Debug RSA PMS encryption

Do controlled attack cases (bad padding, truncated records, out-of-order messages)

All locally and repeatably, before talking to the real FTP server.

🚀 OVERVIEW OF THE LOCAL TLS-FTP TEST SERVER
We’ll create a fake FTP server with this behavior:

Client connects → server sends "220 Test FTP Server Ready\r\n"

If client sends "AUTH TLS\r\n":
    server responds "234 AUTH TLS OK\r\n"
    server SWITCHES TO TLS MODE:
        → Accepts the ClientHello as raw bytes
        → Feeds them into a real TLSSocket in memory
        → Outputs ServerHello / Certificate / ServerHelloDone / CCS / Finished
          as raw TLS records back to your client.
So your TLS client code sees exactly what a real server sends — but we can log or modify anything we want.

This is done using:

A TCP server (net.createServer)

A pair of connected sockets using tls.TLSSocket(options, isServer=true) in "encapsulated" mode

We manually pipe TLS encrypted bytes to the real network socket

This technique is known as a "TLS terminator with manual transcript control".

⭐ STEP 1 — Create a self-signed certificate (1 command)
Run:

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout test.key -out test.crt \
  -subj "/CN=localhost" -days 3650
⭐ STEP 2 — Minimal controlled TLS test server
✔ Accepts ClientHello
✔ Generates proper ServerHello / Certificate / Finished
✔ Sends FTP replies before and after TLS
✔ Lets you log all TLS records
✔ Lets you shape behavior (inject errors, delay messages, corrupt records…)

import * as net from "net";
import * as tls from "tls";
import * as fs from "fs";

// Load test certificate / key
const key = fs.readFileSync("test.key");
const cert = fs.readFileSync("test.crt");

// This function creates a TLS server but in MANUAL mode.
// We will feed TCP bytes into this TLS socket manually.
function createManualTlsServerSocket() {
  const tlsSocket = new tls.TLSSocket(null, {
    isServer: true,
    cert,
    key,
    requestCert: false,
    rejectUnauthorized: false,
  });

  return tlsSocket;
}

function startTestServer(port = 2121) {
  const server = net.createServer((socket) => {
    console.log("[SERVER] Client connected!");

    socket.write("220 Test FTP Ready\r\n");

    let tlsMode = false;
    let tlsSocket: tls.TLSSocket | null = null;

    socket.on("data", (chunk) => {
      if (!tlsMode) {
        const text = chunk.toString("ascii");

        console.log("[SERVER] Plaintext received:", JSON.stringify(text));

        if (text.startsWith("AUTH TLS")) {
          socket.write("234 AUTH TLS OK\r\n");

          // Switch to TLS mode
          tlsMode = true;
          tlsSocket = createManualTlsServerSocket();

          // When TLS engine produces encrypted bytes, send them over the real socket.
          tlsSocket.on("data", (encrypted) => {
            console.log("[TLS-SERVER] → Sending encrypted TLS bytes:", encrypted.length);
            socket.write(encrypted);
          });

          tlsSocket.on("secureConnection", () => {
            console.log("[TLS-SERVER] Secure connection established!");
          });

          tlsSocket.on("error", (err) => {
            console.error("[TLS-SERVER] Error:", err);
          });

          tlsSocket.on("close", () => {
            console.log("[TLS-SERVER] Closed.");
          });

          return;
        }

        // Any other plaintext commands:
        socket.write("200 OK (plaintext)\r\n");
      } else {
        //
        // TLS MODE:
        // We must feed the encrypted TLS bytes into the TLSSocket engine:
        //
        console.log("[SERVER] Feeding encrypted bytes into TLS engine:", chunk.length);

        tlsSocket!.write(chunk);
      }
    });

    socket.on("error", (err) => {
      console.error("[SERVER] Socket error:", err);
    });

    socket.on("close", () => {
      console.log("[SERVER] Client disconnected.");
    });
  });

  server.listen(port, () => {
    console.log(`[TEST TLS SERVER] Listening on port ${port}`);
  });
}

startTestServer();
💡 WHAT THIS SERVER DOES IN REALITY
Before AUTH TLS:
Pure plaintext FTP

Behaves just like a real FTP server:

220 Test FTP Ready
C → AUTH TLS
234 AUTH TLS OK
After AUTH TLS:
The server:

Creates a tls.TLSSocket in server mode not attached to any real network socket

All encrypted bytes from your TLS client are fed into:

tlsSocket.write(encryptedData)
The Node TLS engine inside tlsSocket responds with:

ServerHello

Certificate

ServerHelloDone

ChangeCipherSpec

Finished

etc.

These are emitted as raw TLS encrypted bytes via:

tlsSocket.on("data", (encryptedBytes) => socket.write(encryptedBytes))
So from your client’s perspective, it is talking to a real TLS server.

But you can:

Log every byte

Mutate records

Delay or reorder packets

Introduce random corruption

Remove CCS to see how your client reacts

Change cipher suites in real time

Send malformed records

This is the perfect debugging sandbox.

⭐ STEP 3 — Test it with your TLS client stack
Point your earlier test harness at localhost:2121:

runFtpsAuthTlsTest("localhost", 2121);
Expected output:

[FTP] Connected
[FTP] Banner: 220 Test FTP Ready
[FTP] AUTH TLS reply: 234 AUTH TLS OK
[TLS] Sent ClientHello
[TLS-SERVER] → Sending encrypted TLS bytes: 1350
[TLS] Got ServerHello
[TLS] Got Certificate
[TLS] Got ServerHelloDone
[TLS] Sent ClientKeyExchange
[TLS] Sent ChangeCipherSpec
[TLS] Sent Finished
[TLS] Got server ChangeCipherSpec
[TLS] Server Finished OK, handshake complete!
At that moment, you know:

Your ClientHello is correctly formed

Your ServerHello parsing is correct

Your Certificate parsing is correct

Your PMS encryption matches what Node’s TLS engine expects

Your key derivation, MAC logic, padding, AES-CBC encryption are working

Your Finished verify_data is correct

Your record framing is correct

You can read/write ApplicationData afterward

⭐ STEP 4 — Push this further
Now that you have full control, you can simulate:

❌ Corrupted padding
encryptedBytes[encryptedBytes.length - 1] ^= 0xFF;
❌ Wrong MAC
encryptedBytes[10] ^= 0x55;
❌ Missing CCS
You can intercept the generated Server CCS and skip writing it to the client:

if (isChangeCipherSpec(encrypted)) return; // Drop it
❌ Wrong cipher suite
Force Node's TLS engine to use an unsupported cipher suite and test whether your client properly rejects it.

❌ Slow handshake
Delay messages artificially.

💥 CCC simulation
After handshake:

Accept encrypted FTP commands

Send FTP 200 OK

Send TLS close_notify

Stop TLS engine, go back to plaintext

This will perfectly mimic the FTPS control-channel downgrade.

🎉 SUMMARY
You now have:

✔ Full custom TLS client stack under your control
✔ A local fake FTP server that behaves exactly like AUTH TLS
✔ A real TLS engine generating ServerHello/Certificate/Finished
✔ Ability to inspect, modify, delay, corrupt any TLS byte
✔ A complete environment to perfect your CCC downgrade logic
✔ A playground to build a future production Node TLS-offload proxy
