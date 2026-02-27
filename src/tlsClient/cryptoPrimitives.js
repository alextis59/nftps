const crypto = require('node:crypto');
const { TLS_VERSION_1_2 } = require('./constants.js');

function incSeq(num) {
  return BigInt(num) + 1n;
}

function tls12Prf(secret, label, seed, length) {
  const labelBytes = Buffer.from(label, 'ascii');
  const fullSeed = Buffer.concat([labelBytes, seed]);

  function pHash(secretBytes, seedBytes, outLen) {
    let A = seedBytes;
    let out = Buffer.alloc(0);

    while (out.length < outLen) {
      A = crypto.createHmac('sha256', secretBytes).update(A).digest();
      const chunk = crypto
        .createHmac('sha256', secretBytes)
        .update(A)
        .update(seedBytes)
        .digest();
      out = Buffer.concat([out, chunk]);
    }

    return out.subarray(0, outLen);
  }

  return pHash(secret, fullSeed, length);
}

function computeFinishedVerifyData(masterSecret, handshakeTranscript, label) {
  const hash = crypto.createHash('sha256').update(handshakeTranscript).digest();
  return tls12Prf(masterSecret, label, hash, 12);
}

function deriveMasterSecret(preMasterSecret, clientRandom, serverRandom) {
  const seed = Buffer.concat([clientRandom, serverRandom]);
  return tls12Prf(preMasterSecret, 'master secret', seed, 48);
}

function deriveKeyBlock(masterSecret, serverRandom, clientRandom, length) {
  const seed = Buffer.concat([serverRandom, clientRandom]);
  return tls12Prf(masterSecret, 'key expansion', seed, length);
}

function buildPreMasterSecret() {
  const pms = Buffer.alloc(48);
  pms.writeUInt16BE(TLS_VERSION_1_2, 0);
  crypto.randomBytes(46).copy(pms, 2);
  return pms;
}

function encryptPreMasterSecret(preMasterSecret, serverCertPem) {
  const publicKey = crypto.createPublicKey(serverCertPem);
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    preMasterSecret,
  );
}

module.exports = {
  incSeq,
  tls12Prf,
  computeFinishedVerifyData,
  deriveMasterSecret,
  deriveKeyBlock,
  buildPreMasterSecret,
  encryptPreMasterSecret,
};
