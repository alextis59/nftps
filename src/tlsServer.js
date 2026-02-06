const tls = require('node:tls');

/**
 * Spin up a simple TLS server for test scenarios.
 *
 * The server listens on 127.0.0.1 with an ephemeral port. It resolves once the
 * listener is active and returns helpers for closing the server when tests
 * finish.
 *
 * @param {{
 *   key: Buffer|string,
 *   cert: Buffer|string,
 *   requestCert?: boolean,
 *   ca?: Array<Buffer|string>,
 *   rejectUnauthorized?: boolean,
 * }} credentials
 * @param {(socket: tls.TLSSocket) => void} [onConnection]
 * @returns {Promise<{server: tls.Server, port: number, close: () => Promise<void>}>}
 */
function createTestTlsServer(credentials = {}, onConnection = () => {}) {
  if (typeof onConnection !== 'function') {
    throw new TypeError('TLS server onConnection handler must be a function');
  }

  if (!credentials || typeof credentials !== 'object') {
    throw new TypeError('TLS server requires a credentials object');
  }

  const {
    key,
    cert,
    requestCert = false,
    ca = undefined,
    rejectUnauthorized = false,
  } = credentials;

  if (!isKeyMaterial(key)) {
    throw new TypeError('TLS server requires a private key');
  }

  if (!isKeyMaterial(cert)) {
    throw new TypeError('TLS server requires a certificate');
  }

  if (typeof requestCert !== 'boolean') {
    throw new TypeError('TLS server requestCert flag must be a boolean');
  }

  if (ca !== undefined) {
    if (!Array.isArray(ca) || !ca.every(isKeyMaterial)) {
      throw new TypeError('TLS server ca must be an array of certificates');
    }
  }

  if (typeof rejectUnauthorized !== 'boolean') {
    throw new TypeError('TLS server rejectUnauthorized flag must be a boolean');
  }

  return new Promise((resolve, reject) => {
    let server;
    try {
      server = tls.createServer({ key, cert, requestCert, ca, rejectUnauthorized }, (socket) => {
        onConnection(socket);
      });
    } catch (err) {
      reject(err);
      return;
    }

    const removeErrorListener = () => server.removeListener('error', handleError);

    const handleError = (err) => {
      removeErrorListener();
      reject(err);
    };

    server.once('error', handleError);

    server.listen(0, '127.0.0.1', () => {
      removeErrorListener();

      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unable to determine listening address for TLS test server'));
        return;
      }

      resolve({
        server,
        port: address.port,
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((closeError) => {
              if (closeError) {
                closeReject(closeError);
                return;
              }

              closeResolve();
            });
          }),
      });
    });
  });
}

function isKeyMaterial(value) {
  return typeof value === 'string' || Buffer.isBuffer(value);
}

module.exports = {
  createTestTlsServer,
};
