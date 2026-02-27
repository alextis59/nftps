const test = require('node:test');
const assert = require('node:assert');
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
