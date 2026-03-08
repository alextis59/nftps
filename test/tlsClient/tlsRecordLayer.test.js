const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { TlsRecordLayer } = require('../../src/tlsClient/tlsRecordLayer.js');

class FakeTcp {
  constructor(reads = []) {
    this.reads = [...reads];
    this.writes = [];
  }

  async readExactly() {
    if (this.reads.length === 0) {
      throw new Error('No read data queued');
    }
    return this.reads.shift();
  }

  async write(buf) {
    this.writes.push(buf);
  }
}

function makeCipher() {
  return {
    cipherAlgorithm: 'aes-128-cbc',
    blockSize: 16,
    ivLength: 16,
    clientWriteMacKey: Buffer.alloc(20, 0x01),
    serverWriteMacKey: Buffer.alloc(20, 0x02),
    clientWriteKey: Buffer.alloc(16, 0x03),
    serverWriteKey: Buffer.alloc(16, 0x04),
    clientSeqNum: 0n,
    serverSeqNum: 0n,
    macAlgorithm: 'sha1',
    macLength: 20,
  };
}

function makeCipher256() {
  return {
    cipherAlgorithm: 'aes-256-cbc',
    blockSize: 16,
    ivLength: 16,
    clientWriteMacKey: Buffer.alloc(32, 0x01),
    serverWriteMacKey: Buffer.alloc(32, 0x02),
    clientWriteKey: Buffer.alloc(32, 0x03),
    serverWriteKey: Buffer.alloc(32, 0x04),
    clientSeqNum: 0n,
    serverSeqNum: 0n,
    macAlgorithm: 'sha256',
    macLength: 32,
  };
}

test('writePlainRecord writes TLS header and fragment', async () => {
  const tcp = new FakeTcp();
  const layer = new TlsRecordLayer(tcp);

  const fragment = Buffer.from('abc');
  await layer.writePlainRecord(0x16, fragment);

  assert.strictEqual(tcp.writes.length, 1);
  const wire = tcp.writes[0];
  assert.strictEqual(wire.readUInt8(0), 0x16);
  assert.strictEqual(wire.readUInt16BE(1), layer.version);
  assert.strictEqual(wire.readUInt16BE(3), fragment.length);
  assert.deepStrictEqual(wire.subarray(5), fragment);
});

test('writePlainRecord validates state and input type', async () => {
  const layer = new TlsRecordLayer(new FakeTcp());
  layer.state = 'CLOSED';
  await assert.rejects(() => layer.writePlainRecord(0x16, Buffer.from('x')), /TLS connection closed/);

  layer.state = 'PLAIN';
  await assert.rejects(() => layer.writePlainRecord(0x16, 'x'), /TLS record fragment must be a Buffer/);
});

test('readPlainRecord validates TLS version', async () => {
  const badVersionHeader = Buffer.alloc(5);
  badVersionHeader.writeUInt8(0x16, 0);
  badVersionHeader.writeUInt16BE(0x0301, 1);
  badVersionHeader.writeUInt16BE(1, 3);

  const layer = new TlsRecordLayer(new FakeTcp([badVersionHeader, Buffer.from([0x00])]));
  await assert.rejects(() => layer.readPlainRecord(), /Unexpected TLS version/);
});

test('sendChangeCipherSpec requires cipher state', async () => {
  const tcp = new FakeTcp();
  const layer = new TlsRecordLayer(tcp);
  await assert.rejects(() => layer.sendChangeCipherSpec(), /Cipher state not installed/);
  assert.strictEqual(tcp.writes.length, 1, 'CCS record should be written before cipher check');

  layer.installCipher(makeCipher());
  await layer.sendChangeCipherSpec();
  assert.strictEqual(layer.state, 'ENCRYPTING');
});

test('writeEncryptedRecord validates prerequisites', async () => {
  const layer = new TlsRecordLayer(new FakeTcp());

  await assert.rejects(() => layer.writeEncryptedRecord(0x17, Buffer.from('x')), /Cipher state not installed/);

  layer.installCipher(makeCipher());
  await assert.rejects(
    () => layer.writeEncryptedRecord(0x17, Buffer.from('x')),
    /Cannot write encrypted record while not in ENCRYPTING\/ENCRYPTED state/,
  );

  layer.state = 'ENCRYPTING';
  await assert.rejects(() => layer.writeEncryptedRecord(0x17, 'x'), /TLS record fragment must be a Buffer/);
});

test('sendAlertCloseNotify uses plaintext and encrypted paths', async () => {
  const tcp = new FakeTcp();
  const layer = new TlsRecordLayer(tcp);

  await layer.sendAlertCloseNotify();
  assert.strictEqual(tcp.writes.length, 1);

  layer.installCipher(makeCipher());
  layer.state = 'ENCRYPTING';
  await layer.sendAlertCloseNotify();
  assert.strictEqual(tcp.writes.length, 2);
  assert.strictEqual(layer.state, 'ENCRYPTED');
});

test('writeEncryptedRecord supports configured AES-256 cipher state', async () => {
  const tcp = new FakeTcp();
  const layer = new TlsRecordLayer(tcp);
  layer.installCipher(makeCipher256());
  layer.state = 'ENCRYPTING';

  await layer.writeEncryptedRecord(0x17, Buffer.from('ping'));

  assert.strictEqual(tcp.writes.length, 1);
  const wire = tcp.writes[0];
  assert.strictEqual(wire.readUInt8(0), 0x17);
  assert.strictEqual(wire.readUInt16BE(1), layer.version);
  assert.ok(wire.readUInt16BE(3) > 16);
});

test('readEncryptedRecord validates version and fragment size', async () => {
  const badVersionHeader = Buffer.alloc(5);
  badVersionHeader.writeUInt8(0x17, 0);
  badVersionHeader.writeUInt16BE(0x0301, 1);
  badVersionHeader.writeUInt16BE(1, 3);

  const shortFragmentHeader = Buffer.alloc(5);
  shortFragmentHeader.writeUInt8(0x17, 0);
  shortFragmentHeader.writeUInt16BE(0x0303, 1);
  shortFragmentHeader.writeUInt16BE(8, 3);

  const layer1 = new TlsRecordLayer(new FakeTcp([badVersionHeader, Buffer.from([0x00])]));
  layer1.installCipher(makeCipher());
  await assert.rejects(() => layer1.readEncryptedRecord(), /Unexpected TLS version in encrypted record/);

  const layer2 = new TlsRecordLayer(new FakeTcp([shortFragmentHeader, Buffer.alloc(8)]));
  layer2.installCipher(makeCipher());
  await assert.rejects(() => layer2.readEncryptedRecord(), /Encrypted fragment too short/);
});

test('readEncryptedRecord rejects records with invalid CBC padding bytes', async () => {
  const cipher = makeCipher();
  const contentType = 0x17;
  const plaintext = Buffer.from('ping');

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(0n);
  const headerForMac = Buffer.alloc(5);
  headerForMac.writeUInt8(contentType, 0);
  headerForMac.writeUInt16BE(0x0303, 1);
  headerForMac.writeUInt16BE(plaintext.length, 3);
  const mac = crypto
    .createHmac(cipher.macAlgorithm, cipher.serverWriteMacKey)
    .update(Buffer.concat([seqBuf, headerForMac, plaintext]))
    .digest();

  const invalidPadding = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x07]);
  const plain = Buffer.concat([plaintext, mac, invalidPadding]);
  const iv = Buffer.alloc(16, 0x11);
  const enc = crypto.createCipheriv(cipher.cipherAlgorithm, cipher.serverWriteKey, iv);
  enc.setAutoPadding(false);
  const encrypted = Buffer.concat([enc.update(plain), enc.final()]);
  const fragment = Buffer.concat([iv, encrypted]);

  const header = Buffer.alloc(5);
  header.writeUInt8(contentType, 0);
  header.writeUInt16BE(0x0303, 1);
  header.writeUInt16BE(fragment.length, 3);

  const layer = new TlsRecordLayer(new FakeTcp([header, fragment]));
  layer.installCipher(cipher);
  await assert.rejects(() => layer.readEncryptedRecord(), /Invalid padding bytes/);
});
