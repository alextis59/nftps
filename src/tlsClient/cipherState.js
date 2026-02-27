const { CIPHER_SPECS, TLS_RSA_WITH_AES_128_CBC_SHA } = require('./constants.js');

/**
 * Slice the TLS key block into MAC keys, encryption keys, and IVs.
 */
function makeCipherStateFromKeyBlock(keyBlock, cipherSpec = CIPHER_SPECS[TLS_RSA_WITH_AES_128_CBC_SHA]) {
  if (!Buffer.isBuffer(keyBlock)) {
    throw new TypeError('keyBlock must be a Buffer');
  }
  if (!cipherSpec || typeof cipherSpec !== 'object') {
    throw new TypeError('cipherSpec must be an object');
  }

  const {
    macKeyLength,
    macAlgorithm,
    macLength,
    keyLength = 16,
    ivLength = 16,
    blockSize = 16,
    cipherAlgorithm = 'aes-128-cbc',
  } = cipherSpec;
  if (!Number.isInteger(macKeyLength) || macKeyLength <= 0) {
    throw new TypeError('cipherSpec.macKeyLength must be a positive integer');
  }
  if (typeof macAlgorithm !== 'string' || macAlgorithm.length === 0) {
    throw new TypeError('cipherSpec.macAlgorithm must be a non-empty string');
  }
  if (!Number.isInteger(macLength) || macLength <= 0) {
    throw new TypeError('cipherSpec.macLength must be a positive integer');
  }
  if (!Number.isInteger(keyLength) || keyLength <= 0) {
    throw new TypeError('cipherSpec.keyLength must be a positive integer');
  }
  if (!Number.isInteger(ivLength) || ivLength <= 0) {
    throw new TypeError('cipherSpec.ivLength must be a positive integer');
  }
  if (!Number.isInteger(blockSize) || blockSize <= 0) {
    throw new TypeError('cipherSpec.blockSize must be a positive integer');
  }
  if (typeof cipherAlgorithm !== 'string' || cipherAlgorithm.length === 0) {
    throw new TypeError('cipherSpec.cipherAlgorithm must be a non-empty string');
  }

  const REQUIRED = macKeyLength * 2 + keyLength * 2 + ivLength * 2;
  if (keyBlock.length < REQUIRED) {
    throw new Error(`keyBlock must be at least ${REQUIRED} bytes`);
  }

  let offset = 0;
  const clientWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const serverWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const clientWriteKey = keyBlock.subarray(offset, (offset += keyLength));
  const serverWriteKey = keyBlock.subarray(offset, (offset += keyLength));
  const clientWriteIV = keyBlock.subarray(offset, (offset += ivLength));
  const serverWriteIV = keyBlock.subarray(offset, (offset += ivLength));

  return {
    clientWriteMacKey,
    serverWriteMacKey,
    clientWriteKey,
    serverWriteKey,
    clientWriteIV,
    serverWriteIV,
    cipherAlgorithm,
    blockSize,
    ivLength,
    macAlgorithm,
    macLength,
    clientSeqNum: 0n,
    serverSeqNum: 0n,
  };
}

module.exports = {
  makeCipherStateFromKeyBlock,
};
