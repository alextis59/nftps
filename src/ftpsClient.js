const net = require('node:net');
const { EventEmitter } = require('node:events');
const { TlsClient } = require('./tlsClient.js');

class FtpsClient extends EventEmitter {
  constructor({
    host,
    port = 21,
    servername = host,
    clientCert,
    clientKey,
    ca,
    rejectUnauthorized = true,
    checkServerIdentity,
    cipherSuites,
    ciphers,
    minVersion,
    maxVersion,
    compressionMethods,
    extensions,
    verbose = false,
    log,
    secure = true,
    ignorePasvAddress = false,
  } = {}) {
    super();
    this.host = host;
    this.port = port;
    this.servername = servername || host || 'localhost';
    this.clientCert = clientCert;
    this.clientKey = clientKey;
    this.ca = ca;
    this.rejectUnauthorized = rejectUnauthorized;
    this.checkServerIdentity = checkServerIdentity;
    this.cipherSuites = cipherSuites;
    this.ciphers = ciphers;
    this.minVersion = minVersion;
    this.maxVersion = maxVersion;
    this.compressionMethods = compressionMethods;
    this.extensions = extensions;
    this.verbose = verbose;
    this.log = log;
    this.secure = secure;
    this.ignorePasvAddress = ignorePasvAddress;

    this.socket = null;
    this.passiveDataSocket = null;
    this.tlsClient = null;
    this.secureBuffer = Buffer.alloc(0);
    this.plainBuffer = Buffer.alloc(0);
    this.passiveBuffer = Buffer.alloc(0);
  }

  async enterPassiveMode({ ignoreAddress = this.ignorePasvAddress } = {}) {
    const resp = await this.#sendControlCommand('PASV');
    this.#assertCode(resp, 227, 'PASV response');

    const endpoint = this.#parsePasvResponse(resp);
    if (ignoreAddress) {
      endpoint.host = this.host;
    }

    await this.#openPassiveSocket(endpoint);
    return endpoint;
  }

  async openPassiveDataSocket(options = {}) {
    if (this.passiveDataSocket && !this.passiveDataSocket.destroyed) {
      return this.passiveDataSocket;
    }

    const endpoint = await this.enterPassiveMode(options);
    return this.passiveDataSocket || this.#openPassiveSocket(endpoint);
  }

  async exitPassiveMode({ closeSocket = true } = {}) {
    const socket = this.passiveDataSocket;
    this.passiveDataSocket = null;
    this.passiveBuffer = Buffer.alloc(0);

    if (!socket || socket.destroyed || !closeSocket) {
      return;
    }

    return await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.end(() => {
        socket.off('error', reject);
        resolve();
      });
    });
  }

  async connect() {
    if (!this.host) {
      throw new TypeError('FtpsClient requires a host');
    }

    this.socket = net.connect({ host: this.host, port: this.port });
    await new Promise((resolve, reject) => {
      this.socket.once('error', reject);
      this.socket.once('connect', resolve);
    });

    if (this.secure) {
      this.tlsClient = await TlsClient.fromExistingSocket(this.socket, {
        servername: this.servername,
        clientCert: this.clientCert,
        clientKey: this.clientKey,
        ca: this.ca,
        rejectUnauthorized: this.rejectUnauthorized,
        checkServerIdentity: this.checkServerIdentity,
        cipherSuites: this.cipherSuites,
        ciphers: this.ciphers,
        minVersion: this.minVersion,
        maxVersion: this.maxVersion,
        compressionMethods: this.compressionMethods,
        extensions: this.extensions,
        verbose: this.verbose,
        log: this.log,
      });
    }

    const greeting = await this.#readLine();
    this.#assertCode(greeting, 220, 'FTPS server greeting');
  }

  async login(username, password) {
    const userResp = await this.sendCommand(`USER ${username}`);
    this.#assertCode(userResp, 331, 'USER response');

    const passResp = await this.sendCommand(`PASS ${password}`);
    this.#assertCode(passResp, 230, 'PASS response');
    return passResp;
  }

  async setProtectedDataChannel() {
    const pbszResp = await this.sendCommand('PBSZ 0');
    this.#assertCode(pbszResp, 200, 'PBSZ response');

    const protResp = await this.sendCommand('PROT P');
    this.#assertCode(protResp, 200, 'PROT response');
    return protResp;
  }

  async upgradeControlChannel() {
    if (this.tlsClient) {
      throw new Error('Control channel already secured');
    }

    const authResp = await this.sendCommand('AUTH TLS');
    this.#assertCode(authResp, 234, 'AUTH TLS response');

    this.tlsClient = await TlsClient.fromExistingSocket(this.socket, {
      servername: this.servername,
      clientCert: this.clientCert,
      clientKey: this.clientKey,
      ca: this.ca,
      rejectUnauthorized: this.rejectUnauthorized,
      checkServerIdentity: this.checkServerIdentity,
      cipherSuites: this.cipherSuites,
      ciphers: this.ciphers,
      minVersion: this.minVersion,
      maxVersion: this.maxVersion,
      compressionMethods: this.compressionMethods,
      extensions: this.extensions,
      verbose: this.verbose,
      log: this.log,
    });
    this.secure = true;
    this.secureBuffer = Buffer.alloc(0);
  }

  /**
   * Send CCC on the control channel.
   *
   * By default we actively downgrade to cleartext on the same socket. Some
   * Node-based test servers cannot unwrap TLSSocket back to raw TCP; for those
   * environments pass `{ downgrade: false }` to keep using TLS after CCC.
   */
  async clearCommandChannel({
    downgrade = true,
    waitForPeerCloseNotify = true,
    closeNotifyTimeoutMs = 5000,
  } = {}) {
    if (!this.tlsClient) {
      return this.sendCommand('CCC');
    }

    const resp = await this.sendCommand('CCC');
    this.#assertCode(resp, 200, 'CCC response');
    if (downgrade) {
      await this.tlsClient.shutdownToPlain({
        waitForPeer: waitForPeerCloseNotify,
        timeoutMs: closeNotifyTimeoutMs,
      });
      this.tlsClient = null;
      this.secure = false;
      this.plainBuffer = Buffer.alloc(0);
    }
    return resp;
  }

  async pwd() {
    const resp = await this.sendCommand('PWD');
    this.#assertCode(resp, 257, 'PWD response');
    return resp;
  }

  async quit() {
    if (this.socket) {
      const resp = await this.sendCommand('QUIT');
      this.#assertCode(resp, 221, 'QUIT response');
    }
    await this.close();
  }

  async close() {
    try {
      if (this.tlsClient) {
        await this.tlsClient.close();
      }
    } finally {
      await this.exitPassiveMode();
      this.tlsClient = null;
      if (this.socket) {
        this.socket.destroy();
        this.socket = null;
      }
    }
  }

  async sendCommand(command) {
    this.emit('command', command);
    this.#verboseLog(`sent control command: ${JSON.stringify(command)}`);
    if (this.tlsClient) {
      await this.tlsClient.sendApplicationData(Buffer.from(`${command}\r\n`, 'utf8'));
    } else if (this.socket) {
      await new Promise((resolve, reject) => {
        this.socket.write(`${command}\r\n`, (err) => (err ? reject(err) : resolve()));
      });
    } else {
      throw new Error('FTPS client is not connected');
    }

    return this.#readLine();
  }

  async #readLine() {
    if (this.tlsClient) {
      return this.#readLineFromSource('secureBuffer', async () => this.tlsClient.readApplicationData());
    }
    return this.#readLineFromSource('plainBuffer', async () =>
      new Promise((resolve) => this.socket.once('data', resolve)),
    );
  }

  async #readLineFromSource(bufferKey, nextChunk) {
    while (true) {
      const buf = this[bufferKey];
      const newlineIndex = buf.indexOf(0x0a);
      if (newlineIndex !== -1) {
        const line = buf.subarray(0, newlineIndex + 1);
        this[bufferKey] = buf.subarray(newlineIndex + 1);
        const text = line.toString('utf8').replace(/\r?\n$/, '');
        this.emit('data', text);
        this.#verboseLog(`received ${this.#sourceName(bufferKey)} data: ${JSON.stringify(text)}`);
        return text;
      }

      const chunk = await nextChunk();
      this[bufferKey] = Buffer.concat([buf, chunk]);
    }
  }

  #assertCode(line, expected, context) {
    if (!line || !line.startsWith(String(expected))) {
      throw new Error(`${context} failed: expected ${expected}, got "${line}"`);
    }
  }

  #sourceName(bufferKey) {
    switch (bufferKey) {
      case 'passiveBuffer':
        return 'passive';
      case 'secureBuffer':
        return 'secure control';
      default:
        return 'plain control';
    }
  }

  #verboseLog(message) {
    if (!this.verbose) {
      return;
    }

    const sink = typeof this.log === 'function' ? this.log : console.log;
    sink(`[ftps-client:${this.servername}] ${message}`);
  }

  #parsePasvResponse(line) {
    const match = line.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
    if (!match) {
      throw new Error(`PASV response failed: unable to parse endpoint from "${line}"`);
    }

    const [, h1, h2, h3, h4, p1, p2] = match;
    return {
      host: `${h1}.${h2}.${h3}.${h4}`,
      port: Number.parseInt(p1, 10) * 256 + Number.parseInt(p2, 10),
    };
  }

  async #sendControlCommand(command) {
    return this.sendCommand(command);
  }

  async #openPassiveSocket({ host, port }) {
    await this.exitPassiveMode();

    this.passiveDataSocket = await new Promise((resolve, reject) => {
      const dataSocket = net.connect({ host, port });
      dataSocket.once('error', reject);
      dataSocket.once('connect', () => {
        dataSocket.off('error', reject);
        resolve(dataSocket);
      });
    });

    this.passiveDataSocket.on('data', (chunk) => {
      this.emit('passive-data', chunk);
      this.#verboseLog(`received passive data: ${JSON.stringify(chunk.toString('utf8'))}`);
    });

    this.passiveBuffer = Buffer.alloc(0);
    return this.passiveDataSocket;
  }
}

module.exports = {
  FtpsClient,
};
