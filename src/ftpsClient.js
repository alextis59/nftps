import { EventEmitter } from 'node:events';
import { TlsClient } from './tlsClient.js';

export class FtpsClient extends EventEmitter {
  constructor({ host, port = 21, servername = host, clientCert, clientKey } = {}) {
    super();
    this.host = host;
    this.port = port;
    this.servername = servername || host || 'localhost';
    this.clientCert = clientCert;
    this.clientKey = clientKey;

    this.tlsClient = null;
    this.secureBuffer = Buffer.alloc(0);
  }

  async connect() {
    if (!this.host) {
      throw new TypeError('FtpsClient requires a host');
    }

    this.tlsClient = await TlsClient.connect({
      host: this.host,
      port: this.port,
      servername: this.servername,
      clientCert: this.clientCert,
      clientKey: this.clientKey,
    });

    const greeting = await this.#readSecureLine();
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

  async pwd() {
    const resp = await this.sendCommand('PWD');
    this.#assertCode(resp, 257, 'PWD response');
    return resp;
  }

  async quit() {
    if (this.tlsClient) {
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
      this.tlsClient = null;
    }
  }

  async sendCommand(command) {
    if (!this.tlsClient) {
      throw new Error('FTPS control channel is not secured yet');
    }
    this.emit('command', command);
    await this.tlsClient.sendApplicationData(Buffer.from(`${command}\r\n`, 'utf8'));
    return this.#readSecureLine();
  }

  async #readSecureLine() {
    return this.#readLineFromSource(async () => this.tlsClient.readApplicationData());
  }

  async #readLineFromSource(nextChunk) {
    const bufferKey = 'secureBuffer';
    while (true) {
      const buf = this[bufferKey];
      const newlineIndex = buf.indexOf(0x0a);
      if (newlineIndex !== -1) {
        const line = buf.subarray(0, newlineIndex + 1);
        this[bufferKey] = buf.subarray(newlineIndex + 1);
        const text = line.toString('utf8').replace(/\r?\n$/, '');
        this.emit('data', text);
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
}
