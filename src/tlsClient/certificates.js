const crypto = require('node:crypto');
const tls = require('node:tls');

function derToPem(der, label) {
  const base64 = der.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function pemToDer(pem, label) {
  const text = Buffer.isBuffer(pem) ? pem.toString('utf8') : String(pem);
  const sanitized = text
    .replace(`-----BEGIN ${label}-----`, '')
    .replace(`-----END ${label}-----`, '')
    .replace(/\s+/g, '');
  return Buffer.from(sanitized, 'base64');
}

function extractCertificatePemBlocks(value, fieldName) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value)) {
    throw new TypeError(`${fieldName} must be a string or Buffer`);
  }

  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!matches || matches.length === 0) {
    throw new Error(`${fieldName} must contain at least one CERTIFICATE block`);
  }

  return matches;
}

function parsePemCertificateChain(certPem) {
  if (certPem === undefined) return [];

  const matches = extractCertificatePemBlocks(certPem, 'clientCert');
  return matches.map((block) => pemToDer(block, 'CERTIFICATE'));
}

function parseCaCertificates(ca) {
  if (ca === undefined) {
    return undefined;
  }

  const entries = Array.isArray(ca) ? ca : [ca];
  const certs = [];
  for (const entry of entries) {
    const certBlocks = extractCertificatePemBlocks(entry, 'ca');
    for (const block of certBlocks) {
      certs.push(new crypto.X509Certificate(block));
    }
  }
  return certs;
}

let cachedDefaultCaCertificates;
function getDefaultCaCertificates() {
  if (!cachedDefaultCaCertificates) {
    cachedDefaultCaCertificates = tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem));
  }
  return cachedDefaultCaCertificates;
}

function assertCertificateTimeValid(cert, context) {
  const now = new Date();
  if (now < cert.validFromDate || now > cert.validToDate) {
    throw new Error(
      `${context} certificate is not valid at ${now.toISOString()} (${cert.validFromDate.toISOString()} - ${cert.validToDate.toISOString()})`,
    );
  }
}

function isSignedBy(certificate, issuer) {
  try {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function normalizeServerIdentityResult(hostname, leaf, checkServerIdentity) {
  if (!hostname) {
    return;
  }

  const legacyCert = leaf.toLegacyObject();
  legacyCert.raw = leaf.raw;
  const maybeError = checkServerIdentity(hostname, legacyCert);
  if (maybeError instanceof Error) {
    throw maybeError;
  }
}

function verifyServerCertificateChain({
  chainDer,
  hostname,
  caCertificates,
  checkServerIdentity = tls.checkServerIdentity,
}) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Server did not present a certificate chain');
  }

  const presented = chainDer.map((der) => new crypto.X509Certificate(der));
  const leaf = presented[0];
  normalizeServerIdentityResult(hostname, leaf, checkServerIdentity);

  const trustStore = caCertificates === undefined ? getDefaultCaCertificates() : caCertificates;
  if (!Array.isArray(trustStore) || trustStore.length === 0) {
    throw new Error('No trusted CA certificates available for server validation');
  }

  const trustedFingerprints = new Set(trustStore.map((cert) => cert.fingerprint256));
  const visited = new Set();
  let current = leaf;

  while (true) {
    assertCertificateTimeValid(current, 'Server');
    if (trustedFingerprints.has(current.fingerprint256)) {
      return;
    }

    visited.add(current.fingerprint256);

    const issuerFromPresented = presented.find(
      (candidate) =>
        candidate.ca === true &&
        !visited.has(candidate.fingerprint256) &&
        candidate.fingerprint256 !== current.fingerprint256 &&
        isSignedBy(current, candidate),
    );

    if (issuerFromPresented) {
      current = issuerFromPresented;
      continue;
    }

    const issuerFromTrustStore = trustStore.find((candidate) => isSignedBy(current, candidate));
    if (issuerFromTrustStore) {
      assertCertificateTimeValid(issuerFromTrustStore, 'Trusted CA');
      return;
    }

    throw new Error('Server certificate chain is not signed by a trusted CA');
  }
}

function parseServerCertificate(serverCertDer) {
  if (!Buffer.isBuffer(serverCertDer)) {
    throw new TypeError('server certificate must be a Buffer');
  }
  return derToPem(serverCertDer, 'CERTIFICATE');
}

function extractLegacyPublicServerCert(chainDer) {
  if (!Array.isArray(chainDer) || chainDer.length === 0) {
    throw new Error('Server certificate chain is empty');
  }

  return parseServerCertificate(chainDer[0]);
}

function parsePrivateKey(keyPem) {
  if (keyPem === undefined) return undefined;
  if (typeof keyPem !== 'string' && !Buffer.isBuffer(keyPem)) {
    throw new TypeError('clientKey must be a string or Buffer');
  }
  return Buffer.isBuffer(keyPem) ? keyPem.toString('utf8') : keyPem;
}

function ensureClientCertificateMatchesKey(clientCertChain, clientPrivateKey) {
  if (clientCertChain.length === 0 || !clientPrivateKey) {
    return;
  }

  const leafCert = new crypto.X509Certificate(derToPem(clientCertChain[0], 'CERTIFICATE'));
  const key = crypto.createPrivateKey(clientPrivateKey);
  if (!leafCert.checkPrivateKey(key)) {
    throw new Error('clientCert and clientKey do not match');
  }
}

function ensureClientAuthMaterial(clientCertChain, clientPrivateKey) {
  if (clientCertChain.length > 0 && !clientPrivateKey) {
    throw new Error('clientKey is required when clientCert is provided');
  }
  if (clientPrivateKey && clientCertChain.length === 0) {
    throw new Error('clientCert is required when clientKey is provided');
  }
  ensureClientCertificateMatchesKey(clientCertChain, clientPrivateKey);
}

module.exports = {
  parsePemCertificateChain,
  parsePrivateKey,
  parseCaCertificates,
  verifyServerCertificateChain,
  parseServerCertificate,
  extractLegacyPublicServerCert,
  ensureClientAuthMaterial,
};
