const crypto = require('node:crypto');
const { TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256 } = require('./constants.js');
const { computeFinishedVerifyData } = require('./cryptoPrimitives.js');

function buildExtension(type, data) {
  const ext = Buffer.alloc(4 + data.length);
  ext.writeUInt16BE(type, 0);
  ext.writeUInt16BE(data.length, 2);
  data.copy(ext, 4);
  return ext;
}

function buildClientHello(hostname) {
  const clientRandom = Buffer.alloc(32);
  clientRandom.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  crypto.randomBytes(28).copy(clientRandom, 4);

  const sessionId = Buffer.from([0x00]);

  const offeredCipherSuites = [TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA];
  const cipherSuites = Buffer.alloc(2 + offeredCipherSuites.length * 2);
  cipherSuites.writeUInt16BE(offeredCipherSuites.length * 2, 0);
  for (let i = 0; i < offeredCipherSuites.length; i += 1) {
    cipherSuites.writeUInt16BE(offeredCipherSuites[i], 2 + i * 2);
  }

  const compressionMethods = Buffer.from([0x01, 0x00]);

  const hostBuf = Buffer.from(hostname, 'ascii');
  const serverNameListLen = 1 + 2 + hostBuf.length;
  const sniData = Buffer.alloc(2 + serverNameListLen);
  sniData.writeUInt16BE(serverNameListLen, 0);
  sniData.writeUInt8(0x00, 2);
  sniData.writeUInt16BE(hostBuf.length, 3);
  hostBuf.copy(sniData, 5);

  // signature_algorithms (TLS 1.2)
  // Keep the list short: rsa_pkcs1_sha256 and rsa_pkcs1_sha1.
  const sigAlgsData = Buffer.alloc(2 + 4);
  sigAlgsData.writeUInt16BE(4, 0);
  sigAlgsData.writeUInt8(0x04, 2);
  sigAlgsData.writeUInt8(0x01, 3);
  sigAlgsData.writeUInt8(0x02, 4);
  sigAlgsData.writeUInt8(0x01, 5);

  const extBlocks = [buildExtension(0x0000, sniData), buildExtension(0x000d, sigAlgsData)];
  const extPayload = Buffer.concat(extBlocks);
  const extensions = Buffer.alloc(2 + extPayload.length);
  extensions.writeUInt16BE(extPayload.length, 0);
  extPayload.copy(extensions, 2);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    clientRandom,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions,
  ]);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x01, 0);
  header.writeUIntBE(body.length, 1, 3);

  const handshake = Buffer.concat([header, body]);

  return { clientRandom, handshake };
}

function parseServerHello(body) {
  let offset = 0;

  const version = body.readUInt16BE(offset);
  offset += 2;

  const random = body.subarray(offset, offset + 32);
  if (random.length !== 32) {
    throw new Error('Invalid ServerHello.random length');
  }
  offset += 32;

  const sessionIdLen = body.readUInt8(offset);
  offset += 1;
  const sessionId = body.subarray(offset, offset + sessionIdLen);
  offset += sessionIdLen;

  const cipherSuite = body.readUInt16BE(offset);
  offset += 2;
  const compression = body.readUInt8(offset);
  offset += 1;

  const extensions = new Map();
  if (offset < body.length) {
    const extensionsLen = body.readUInt16BE(offset);
    offset += 2;
    const end = offset + extensionsLen;
    if (end > body.length) {
      throw new Error('Invalid ServerHello.extensions length');
    }

    while (offset + 4 <= end) {
      const extType = body.readUInt16BE(offset);
      offset += 2;
      const extLen = body.readUInt16BE(offset);
      offset += 2;
      const extData = body.subarray(offset, offset + extLen);
      offset += extLen;
      extensions.set(extType, extData);
    }
  }

  return { version, random, sessionId, cipherSuite, compression, extensions };
}

function parseCertificate(body) {
  if (body.length < 3) {
    throw new Error('Certificate message too short');
  }

  let offset = 0;
  const totalLen = body.readUIntBE(offset, 3);
  offset += 3;
  const end = offset + totalLen;
  if (end > body.length) {
    throw new Error('Invalid total certificate length');
  }

  const certs = [];
  while (offset + 3 <= end) {
    const certLen = body.readUIntBE(offset, 3);
    offset += 3;
    const cert = body.subarray(offset, offset + certLen);
    offset += certLen;
    certs.push(cert);
  }

  if (certs.length === 0) {
    throw new Error('Empty certificate chain');
  }

  return certs;
}

function buildClientKeyExchange(encryptedPms) {
  const body = Buffer.alloc(2 + encryptedPms.length);
  body.writeUInt16BE(encryptedPms.length, 0);
  encryptedPms.copy(body, 2);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x10, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildClientCertificate(chainDer) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Client certificate chain cannot be empty when building Certificate message');
  }

  const certEntries = chainDer.map((cert) => {
    if (!Buffer.isBuffer(cert)) {
      throw new TypeError('Certificate entries must be Buffers');
    }
    const len = Buffer.alloc(3);
    len.writeUIntBE(cert.length, 0, 3);
    return Buffer.concat([len, cert]);
  });

  const concatenated = Buffer.concat(certEntries);
  const bodyLen = Buffer.alloc(3);
  bodyLen.writeUIntBE(concatenated.length, 0, 3);
  const body = Buffer.concat([bodyLen, concatenated]);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x0b, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildCertificateVerify(privateKeyPem, handshakeTranscript) {
  if (!privateKeyPem) {
    throw new Error('Private key required to build CertificateVerify');
  }

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(Buffer.concat(handshakeTranscript));
  const signature = signer.sign(privateKeyPem);

  const body = Buffer.alloc(4 + signature.length);
  body.writeUInt8(0x04, 0); // sha256
  body.writeUInt8(0x01, 1); // rsa
  body.writeUInt16BE(signature.length, 2);
  signature.copy(body, 4);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x0f, 0);
  header.writeUIntBE(body.length, 1, 3);

  return Buffer.concat([header, body]);
}

function buildFinished(masterSecret, handshakeTranscript, forClient) {
  const label = forClient ? 'client finished' : 'server finished';
  const verifyData = computeFinishedVerifyData(masterSecret, handshakeTranscript, label);

  const header = Buffer.alloc(4);
  header.writeUInt8(0x14, 0);
  header.writeUIntBE(verifyData.length, 1, 3);

  return Buffer.concat([header, verifyData]);
}

function parseFinishedHandshake(fragment) {
  if (fragment.length < 4) {
    throw new Error('Finished handshake too short');
  }

  const msgType = fragment.readUInt8(0);
  if (msgType !== 0x14) {
    throw new Error(`Unexpected handshake type ${msgType} in Finished message`);
  }

  const length = fragment.readUIntBE(1, 3);
  const body = fragment.subarray(4, 4 + length);
  if (body.length !== length) {
    throw new Error('Incomplete Finished verify_data');
  }

  return { verifyData: body };
}

function parseCertificateRequest(body) {
  let offset = 0;

  if (body.length < 1) {
    throw new Error('CertificateRequest too short');
  }

  const certTypesLen = body.readUInt8(offset);
  offset += 1;
  const certTypes = [...body.subarray(offset, offset + certTypesLen)];
  offset += certTypesLen;

  if (offset + 2 > body.length) {
    throw new Error('CertificateRequest missing signature_algorithms length');
  }

  const sigAlgosLen = body.readUInt16BE(offset);
  offset += 2;
  const sigAlgosEnd = offset + sigAlgosLen;
  if (sigAlgosEnd > body.length) {
    throw new Error('Invalid signature_algorithms length in CertificateRequest');
  }

  const signatureAlgorithms = [];
  while (offset + 1 < sigAlgosEnd) {
    const hash = body.readUInt8(offset);
    const signature = body.readUInt8(offset + 1);
    signatureAlgorithms.push({ hash, signature });
    offset += 2;
  }

  if (offset !== sigAlgosEnd) {
    throw new Error('Trailing bytes in CertificateRequest signature_algorithms');
  }

  if (offset + 2 > body.length) {
    throw new Error('CertificateRequest missing distinguished_names length');
  }

  const namesLen = body.readUInt16BE(offset);
  offset += 2;
  const namesEnd = offset + namesLen;
  if (namesEnd > body.length) {
    throw new Error('Invalid distinguished_names length in CertificateRequest');
  }

  // Skip distinguished names; we don't need them for the test scenarios
  offset = namesEnd;

  return { certTypes, signatureAlgorithms };
}

module.exports = {
  buildClientHello,
  parseServerHello,
  parseCertificate,
  buildClientKeyExchange,
  buildClientCertificate,
  buildCertificateVerify,
  buildFinished,
  parseFinishedHandshake,
  parseCertificateRequest,
};
