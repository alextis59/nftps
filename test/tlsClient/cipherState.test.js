const test = require('node:test');
const assert = require('node:assert');
const { makeCipherStateFromKeyBlock } = require('../../src/tlsClient/cipherState.js');

test('makeCipherStateFromKeyBlock slices key material into expected fields', () => {
  const macKeyLength = 20;
  const requiredLength = macKeyLength * 2 + 16 + 16 + 16 + 16;
  const keyBlock = Buffer.alloc(requiredLength);
  for (let i = 0; i < keyBlock.length; i += 1) {
    keyBlock[i] = i;
  }

  const state = makeCipherStateFromKeyBlock(keyBlock);

  assert.strictEqual(state.clientWriteMacKey.length, 20);
  assert.strictEqual(state.serverWriteMacKey.length, 20);
  assert.strictEqual(state.clientWriteKey.length, 16);
  assert.strictEqual(state.serverWriteKey.length, 16);
  assert.strictEqual(state.clientWriteIV.length, 16);
  assert.strictEqual(state.serverWriteIV.length, 16);
  assert.strictEqual(state.macAlgorithm, 'sha1');
  assert.strictEqual(state.macLength, 20);
  assert.strictEqual(state.clientSeqNum, 0n);
  assert.strictEqual(state.serverSeqNum, 0n);

  assert.deepStrictEqual(state.clientWriteMacKey, keyBlock.subarray(0, 20));
  assert.deepStrictEqual(state.serverWriteKey, keyBlock.subarray(56, 72));
});

test('makeCipherStateFromKeyBlock supports cipher specs with 32-byte keys', () => {
  const cipherSpec = {
    cipherAlgorithm: 'aes-256-cbc',
    keyLength: 32,
    ivLength: 16,
    blockSize: 16,
    macAlgorithm: 'sha256',
    macKeyLength: 32,
    macLength: 32,
  };
  const requiredLength = cipherSpec.macKeyLength * 2 + cipherSpec.keyLength * 2 + cipherSpec.ivLength * 2;
  const keyBlock = Buffer.alloc(requiredLength, 0xab);

  const state = makeCipherStateFromKeyBlock(keyBlock, cipherSpec);

  assert.strictEqual(state.clientWriteMacKey.length, 32);
  assert.strictEqual(state.serverWriteMacKey.length, 32);
  assert.strictEqual(state.clientWriteKey.length, 32);
  assert.strictEqual(state.serverWriteKey.length, 32);
  assert.strictEqual(state.clientWriteIV.length, 16);
  assert.strictEqual(state.serverWriteIV.length, 16);
  assert.strictEqual(state.cipherAlgorithm, 'aes-256-cbc');
  assert.strictEqual(state.blockSize, 16);
  assert.strictEqual(state.ivLength, 16);
  assert.strictEqual(state.macAlgorithm, 'sha256');
  assert.strictEqual(state.macLength, 32);
});

test('makeCipherStateFromKeyBlock validates keyBlock and cipherSpec inputs', () => {
  assert.throws(() => makeCipherStateFromKeyBlock('not-a-buffer'), /keyBlock must be a Buffer/);
  assert.throws(() => makeCipherStateFromKeyBlock(Buffer.alloc(1), null), /cipherSpec must be an object/);
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 0, macAlgorithm: 'sha1', macLength: 20 }),
    /macKeyLength must be a positive integer/,
  );
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 20, macAlgorithm: '', macLength: 20 }),
    /macAlgorithm must be a non-empty string/,
  );
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 20, macAlgorithm: 'sha1', macLength: 0 }),
    /macLength must be a positive integer/,
  );
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 20, macAlgorithm: 'sha1', macLength: 20, keyLength: 0 }),
    /keyLength must be a positive integer/,
  );
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 20, macAlgorithm: 'sha1', macLength: 20, ivLength: 0 }),
    /ivLength must be a positive integer/,
  );
  assert.throws(
    () => makeCipherStateFromKeyBlock(Buffer.alloc(80), { macKeyLength: 20, macAlgorithm: 'sha1', macLength: 20, blockSize: 0 }),
    /blockSize must be a positive integer/,
  );
  assert.throws(
    () =>
      makeCipherStateFromKeyBlock(Buffer.alloc(80), {
        macKeyLength: 20,
        macAlgorithm: 'sha1',
        macLength: 20,
        cipherAlgorithm: '',
      }),
    /cipherAlgorithm must be a non-empty string/,
  );
});

test('makeCipherStateFromKeyBlock rejects short key blocks', () => {
  const short = Buffer.alloc(10);
  assert.throws(() => makeCipherStateFromKeyBlock(short), /keyBlock must be at least/);
});
