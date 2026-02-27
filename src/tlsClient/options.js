const tls = require('node:tls');
const {
  CIPHER_SPECS,
  SUPPORTED_CIPHER_SUITES,
  OPENSSL_CIPHER_NAME_TO_SUITE,
  TLS_VERSION_1_2,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
} = require('./constants.js');
const { parsePemCertificateChain, parsePrivateKey, parseCaCertificates } = require('./certificates.js');

const TLS_VERSION_BY_NAME = {
  TLSv1: 0x0301,
  'TLSv1.1': 0x0302,
  'TLSv1.2': TLS_VERSION_1_2,
  'TLSv1.3': 0x0304,
};
const SUPPORTED_TLS_VERSION_NAMES = Object.keys(TLS_VERSION_BY_NAME);

function validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity }) {
  if (typeof rejectUnauthorized !== 'boolean') {
    throw new TypeError('rejectUnauthorized must be a boolean');
  }

  if (checkServerIdentity !== undefined && typeof checkServerIdentity !== 'function') {
    throw new TypeError('checkServerIdentity must be a function');
  }
}

function parseCipherSuites(cipherSuites) {
  if (cipherSuites === undefined) {
    return [...SUPPORTED_CIPHER_SUITES];
  }

  if (!Array.isArray(cipherSuites) || cipherSuites.length === 0) {
    throw new TypeError('cipherSuites must be a non-empty array');
  }

  const seen = new Set();
  const parsed = [];
  for (const suite of cipherSuites) {
    if (!Number.isInteger(suite) || suite < 0 || suite > 0xffff) {
      throw new TypeError('cipherSuites entries must be 16-bit integers');
    }
    if (!CIPHER_SPECS[suite]) {
      throw new TypeError(`Unsupported cipher suite 0x${suite.toString(16).padStart(4, '0')}`);
    }
    if (!seen.has(suite)) {
      seen.add(suite);
      parsed.push(suite);
    }
  }

  return parsed;
}

function parseCompressionMethods(compressionMethods) {
  if (compressionMethods === undefined) {
    return [...DEFAULT_COMPRESSION_METHODS];
  }

  if (!Array.isArray(compressionMethods) || compressionMethods.length === 0) {
    throw new TypeError('compressionMethods must be a non-empty array');
  }

  const seen = new Set();
  const parsed = [];
  for (const method of compressionMethods) {
    if (!Number.isInteger(method) || method < 0 || method > 0xff) {
      throw new TypeError('compressionMethods entries must be 8-bit integers');
    }
    if (!seen.has(method)) {
      seen.add(method);
      parsed.push(method);
    }
  }

  return parsed;
}

function parseCiphers(ciphers) {
  if (ciphers === undefined) {
    return undefined;
  }

  if (typeof ciphers !== 'string' || ciphers.trim().length === 0) {
    throw new TypeError('ciphers must be a non-empty string');
  }

  const names = ciphers
    .split(':')
    .map((value) => value.trim())
    .filter(Boolean);
  if (names.length === 0) {
    throw new TypeError('ciphers must include at least one cipher name');
  }

  const seen = new Set();
  const suites = [];
  for (const name of names) {
    const suite = OPENSSL_CIPHER_NAME_TO_SUITE[name];
    if (!suite) {
      throw new TypeError(`Unsupported cipher name "${name}"`);
    }
    if (!seen.has(suite)) {
      seen.add(suite);
      suites.push(suite);
    }
  }

  return suites;
}

function parseSignatureAlgorithms(signatureAlgorithms) {
  if (signatureAlgorithms === undefined || signatureAlgorithms === true) {
    return DEFAULT_SIGNATURE_ALGORITHMS.map(({ hash, signature }) => ({ hash, signature }));
  }

  if (signatureAlgorithms === false) {
    return null;
  }

  if (!Array.isArray(signatureAlgorithms) || signatureAlgorithms.length === 0) {
    throw new TypeError('extensions.signatureAlgorithms must be false, true, or a non-empty array');
  }

  return signatureAlgorithms.map((entry) => {
    if (!entry || typeof entry !== 'object') {
      throw new TypeError('extensions.signatureAlgorithms entries must be objects');
    }

    const { hash, signature } = entry;
    if (!Number.isInteger(hash) || hash < 0 || hash > 0xff) {
      throw new TypeError('extensions.signatureAlgorithms[].hash must be an 8-bit integer');
    }
    if (!Number.isInteger(signature) || signature < 0 || signature > 0xff) {
      throw new TypeError('extensions.signatureAlgorithms[].signature must be an 8-bit integer');
    }

    return { hash, signature };
  });
}

function parseExtraExtensions(extra) {
  if (extra === undefined) {
    return [];
  }

  if (!Array.isArray(extra)) {
    throw new TypeError('extensions.extra must be an array');
  }

  return extra.map((entry) => {
    if (!entry || typeof entry !== 'object') {
      throw new TypeError('extensions.extra entries must be objects');
    }

    const { type, data } = entry;
    if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
      throw new TypeError('extensions.extra[].type must be a 16-bit integer');
    }

    if (!Buffer.isBuffer(data) && !(data instanceof Uint8Array)) {
      throw new TypeError('extensions.extra[].data must be a Buffer or Uint8Array');
    }

    return { type, data: Buffer.from(data) };
  });
}

function parseClientHelloExtensions(extensions) {
  if (extensions === undefined) {
    return {
      serverName: true,
      signatureAlgorithms: parseSignatureAlgorithms(undefined),
      extra: [],
    };
  }

  if (!extensions || typeof extensions !== 'object' || Array.isArray(extensions)) {
    throw new TypeError('extensions must be an object');
  }

  const { serverName = true, signatureAlgorithms, extra } = extensions;
  if (typeof serverName !== 'boolean') {
    throw new TypeError('extensions.serverName must be a boolean');
  }

  const parsedSignatureAlgorithms = parseSignatureAlgorithms(signatureAlgorithms);
  const parsedExtra = parseExtraExtensions(extra);

  const reservedTypes = new Set();
  if (serverName) {
    reservedTypes.add(0x0000);
  }
  if (parsedSignatureAlgorithms) {
    reservedTypes.add(0x000d);
  }
  for (const entry of parsedExtra) {
    if (reservedTypes.has(entry.type)) {
      throw new TypeError(`Duplicate extension type 0x${entry.type.toString(16).padStart(4, '0')}`);
    }
    reservedTypes.add(entry.type);
  }

  return {
    serverName,
    signatureAlgorithms: parsedSignatureAlgorithms,
    extra: parsedExtra,
  };
}

function parseVersion(version, fieldName) {
  if (version === undefined) {
    return undefined;
  }

  if (typeof version !== 'string') {
    throw new TypeError(`${fieldName} must be a string`);
  }

  const code = TLS_VERSION_BY_NAME[version];
  if (!code) {
    throw new TypeError(`${fieldName} must be one of: ${SUPPORTED_TLS_VERSION_NAMES.join(', ')}`);
  }

  return { name: version, code };
}

function parseTlsVersionRange(minVersion, maxVersion) {
  const min = parseVersion(minVersion, 'minVersion') || { name: 'TLSv1.2', code: TLS_VERSION_1_2 };
  const max = parseVersion(maxVersion, 'maxVersion') || { name: 'TLSv1.2', code: TLS_VERSION_1_2 };

  if (min.code > max.code) {
    throw new TypeError('minVersion cannot be greater than maxVersion');
  }

  if (TLS_VERSION_1_2 < min.code || TLS_VERSION_1_2 > max.code) {
    throw new TypeError('This TLS client only supports TLSv1.2; minVersion/maxVersion must include TLSv1.2');
  }

  return {
    minVersion: min.name,
    maxVersion: max.name,
    minVersionCode: min.code,
    maxVersionCode: max.code,
  };
}

function parseConnectionOptions({
  servername,
  clientCert,
  clientKey,
  ca,
  rejectUnauthorized = true,
  checkServerIdentity,
  cipherSuites,
  ciphers,
  minVersion,
  maxVersion,
  compressionMethods,
  extensions,
}) {
  validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity });
  if (cipherSuites !== undefined && ciphers !== undefined) {
    throw new TypeError('Provide either cipherSuites or ciphers, not both');
  }

  const parsedCipherSuites = cipherSuites === undefined ? parseCiphers(ciphers) : parseCipherSuites(cipherSuites);
  const parsedVersions = parseTlsVersionRange(minVersion, maxVersion);
  const parsedCompressionMethods = parseCompressionMethods(compressionMethods);
  const parsedExtensions = parseClientHelloExtensions(extensions);

  return {
    servername,
    clientCertChain: parsePemCertificateChain(clientCert),
    clientPrivateKey: parsePrivateKey(clientKey),
    caCertificates: parseCaCertificates(ca),
    rejectUnauthorized,
    checkServerIdentity: checkServerIdentity || tls.checkServerIdentity,
    cipherSuites: parsedCipherSuites || [...SUPPORTED_CIPHER_SUITES],
    compressionMethods: parsedCompressionMethods,
    extensions: parsedExtensions,
    ...parsedVersions,
  };
}

function ensureServerName(servername) {
  if (typeof servername !== 'string' || servername.length === 0) {
    throw new TypeError('servername must be a non-empty string');
  }
}

function ensureSocketConnected(socket) {
  if (!socket || typeof socket.write !== 'function') {
    throw new TypeError('fromExistingSocket requires an active socket');
  }
}

function ensureHostAndPort(host, port) {
  if (typeof host !== 'string' || host.length === 0) {
    throw new TypeError('host must be a non-empty string');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('port must be an integer between 1 and 65535');
  }
}

function defaultVerboseLogger(message) {
  console.log(message);
}

function formatVerboseBuffer(buffer) {
  const text = buffer.toString('utf8').replace(/[\r\n]/g, '\\n');
  const preview = text.length > 80 ? `${text.slice(0, 80)}…` : text;
  return JSON.stringify(preview);
}

module.exports = {
  parseConnectionOptions,
  ensureServerName,
  ensureSocketConnected,
  ensureHostAndPort,
  defaultVerboseLogger,
  formatVerboseBuffer,
  parseCipherSuites,
  parseCompressionMethods,
  parseCiphers,
  parseClientHelloExtensions,
  parseTlsVersionRange,
};
