const crypto = require('node:crypto');
const { TLS_VERSION_1_2 } = require('./constants.js');
const { incSeq } = require('./cryptoPrimitives.js');

class TlsRecordLayer {
  state = 'PLAIN';
  version = TLS_VERSION_1_2;

  /**
   * @param {import('./tcpStream.js').TcpStream} tcp
   */
  constructor(tcp) {
    this.tcp = tcp;
    this.cipher = undefined;
  }

  installCipher(cipher) {
    this.cipher = cipher;
  }

  async writePlainRecord(contentType, fragment) {
    if (this.state === 'CLOSED') {
      throw new Error('TLS connection closed');
    }

    if (!Buffer.isBuffer(fragment)) {
      throw new TypeError('TLS record fragment must be a Buffer');
    }

    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(this.version, 1);
    header.writeUInt16BE(fragment.length, 3);

    await this.tcp.write(Buffer.concat([header, fragment]));
  }

  async readPlainRecord() {
    if (this.state === 'CLOSED') {
      throw new Error('TLS connection closed');
    }

    const header = await this.tcp.readExactly(5);
    const type = header.readUInt8(0);
    const ver = header.readUInt16BE(1);
    const length = header.readUInt16BE(3);

    if (ver !== this.version) {
      throw new Error(`Unexpected TLS version in record: 0x${ver.toString(16)}`);
    }

    const fragment = await this.tcp.readExactly(length);
    return { type, fragment };
  }

  async sendChangeCipherSpec() {
    const body = Buffer.from([0x01]);
    await this.writePlainRecord(0x14, body);

    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }
    this.state = 'ENCRYPTING';
  }

  async sendAlertCloseNotify() {
    const alert = Buffer.from([0x01, 0x00]);

    if (this.state === 'PLAIN') {
      await this.writePlainRecord(0x15, alert);
    } else if (this.state === 'ENCRYPTING' || this.state === 'ENCRYPTED') {
      await this.writeEncryptedRecord(0x15, alert);
    }
  }

  async writeEncryptedRecord(contentType, plaintext) {
    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }
    if (this.state !== 'ENCRYPTING' && this.state !== 'ENCRYPTED') {
      throw new Error('Cannot write encrypted record while not in ENCRYPTING/ENCRYPTED state');
    }
    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('TLS record fragment must be a Buffer');
    }

    const c = this.cipher;
    const seqNum = c.clientSeqNum;

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(contentType, 0);
    headerForMac.writeUInt16BE(this.version, 1);
    headerForMac.writeUInt16BE(plaintext.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, plaintext]);
    const mac = crypto.createHmac(c.macAlgorithm, c.clientWriteMacKey).update(macInput).digest();

    let plain = Buffer.concat([plaintext, mac]);
    const blockSize = 16;
    const padLen = blockSize - ((plain.length + 1) % blockSize);
    const pad = Buffer.alloc(padLen + 1, padLen);
    plain = Buffer.concat([plain, pad]);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', c.clientWriteKey, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

    const fragment = Buffer.concat([iv, encrypted]);
    const header = Buffer.alloc(5);
    header.writeUInt8(contentType, 0);
    header.writeUInt16BE(this.version, 1);
    header.writeUInt16BE(fragment.length, 3);

    await this.tcp.write(Buffer.concat([header, fragment]));

    c.clientSeqNum = incSeq(seqNum);
    this.state = 'ENCRYPTED';
  }

  async readEncryptedRecord() {
    if (!this.cipher) {
      throw new Error('Cipher state not installed');
    }

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

    if (fragment.length < 16) {
      throw new Error('Encrypted fragment too short (no IV)');
    }

    const iv = fragment.subarray(0, 16);
    const ciphertext = fragment.subarray(16);

    const decipher = crypto.createDecipheriv('aes-128-cbc', c.serverWriteKey, iv);
    decipher.setAutoPadding(false);
    let plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    if (plain.length === 0) {
      throw new Error('Decrypted plaintext empty');
    }

    const padLen = plain[plain.length - 1];
    const totalPadLen = padLen + 1;
    if (totalPadLen > plain.length) {
      throw new Error('Invalid padding length');
    }
    plain = plain.subarray(0, plain.length - totalPadLen);

    if (plain.length < c.macLength) {
      throw new Error('Plaintext too short to contain record MAC');
    }

    const content = plain.subarray(0, plain.length - c.macLength);
    const macRecv = plain.subarray(plain.length - c.macLength);

    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(seqNum);
    const headerForMac = Buffer.alloc(5);
    headerForMac.writeUInt8(type, 0);
    headerForMac.writeUInt16BE(ver, 1);
    headerForMac.writeUInt16BE(content.length, 3);

    const macInput = Buffer.concat([seqBuf, headerForMac, content]);
    const macExpected = crypto.createHmac(c.macAlgorithm, c.serverWriteMacKey).update(macInput).digest();

    if (!crypto.timingSafeEqual(macRecv, macExpected)) {
      throw new Error('TLS MAC verification failed');
    }

    c.serverSeqNum = incSeq(seqNum);
    return { type, fragment: content };
  }
}

module.exports = {
  TlsRecordLayer,
};
