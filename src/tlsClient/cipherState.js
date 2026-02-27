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

  const { macKeyLength, macAlgorithm, macLength } = cipherSpec;
  if (!Number.isInteger(macKeyLength) || macKeyLength <= 0) {
    throw new TypeError('cipherSpec.macKeyLength must be a positive integer');
  }
  if (typeof macAlgorithm !== 'string' || macAlgorithm.length === 0) {
    throw new TypeError('cipherSpec.macAlgorithm must be a non-empty string');
  }
  if (!Number.isInteger(macLength) || macLength <= 0) {
    throw new TypeError('cipherSpec.macLength must be a positive integer');
  }

  const REQUIRED = macKeyLength * 2 + 16 + 16 + 16 + 16;
  if (keyBlock.length < REQUIRED) {
    throw new Error(`keyBlock must be at least ${REQUIRED} bytes`);
  }

  let offset = 0;
  const clientWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const serverWriteMacKey = keyBlock.subarray(offset, (offset += macKeyLength));
  const clientWriteKey = keyBlock.subarray(offset, (offset += 16));
  const serverWriteKey = keyBlock.subarray(offset, (offset += 16));
  const clientWriteIV = keyBlock.subarray(offset, (offset += 16));
  const serverWriteIV = keyBlock.subarray(offset, (offset += 16));

  return {
    clientWriteMacKey,
    serverWriteMacKey,
    clientWriteKey,
    serverWriteKey,
    clientWriteIV,
    serverWriteIV,
    macAlgorithm,
    macLength,
    clientSeqNum: 0n,
    serverSeqNum: 0n,
  };
}

module.exports = {
  makeCipherStateFromKeyBlock,
};
