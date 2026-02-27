const tls = require('node:tls');
const { parsePemCertificateChain, parsePrivateKey, parseCaCertificates } = require('./certificates.js');

function validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity }) {
  if (typeof rejectUnauthorized !== 'boolean') {
    throw new TypeError('rejectUnauthorized must be a boolean');
  }

  if (checkServerIdentity !== undefined && typeof checkServerIdentity !== 'function') {
    throw new TypeError('checkServerIdentity must be a function');
  }
}

function parseConnectionOptions({
  servername,
  clientCert,
  clientKey,
  ca,
  rejectUnauthorized = true,
  checkServerIdentity,
}) {
  validateServerAuthOptions({ rejectUnauthorized, checkServerIdentity });

  return {
    servername,
    clientCertChain: parsePemCertificateChain(clientCert),
    clientPrivateKey: parsePrivateKey(clientKey),
    caCertificates: parseCaCertificates(ca),
    rejectUnauthorized,
    checkServerIdentity: checkServerIdentity || tls.checkServerIdentity,
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
};
