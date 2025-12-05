import tls from 'node:tls';

/**
 * Spin up a simple TLS server for test scenarios.
 *
 * The server listens on 127.0.0.1 with an ephemeral port. It resolves once the
 * listener is active and returns helpers for closing the server when tests
 * finish.
 *
 * @param {{key: Buffer|string, cert: Buffer|string, requestCert?: boolean}} credentials
 * @param {(socket: tls.TLSSocket) => void} [onConnection]
 * @returns {Promise<{server: tls.Server, port: number, close: () => Promise<void>}>}
 */
export function createTestTlsServer(credentials, onConnection = () => {}) {
  const { key, cert, requestCert = false } = credentials;

  return new Promise((resolve, reject) => {
    let server;
    try {
      server = tls.createServer({ key, cert, requestCert }, (socket) => {
        onConnection(socket);
      });
    } catch (err) {
      reject(err);
      return;
    }

    server.once('error', (err) => reject(err));

    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unable to determine listening address for TLS test server'));
        return;
      }

      resolve({
        server,
        port: address.port,
        close: () =>
          new Promise((closeResolve) => {
            server.close(() => closeResolve());
          }),
      });
    });
  });
}
