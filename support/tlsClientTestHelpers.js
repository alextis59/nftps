const { createTestTlsServer, TlsClient } = require('../src/index.js');
const { loadCertificateFixtures } = require('./testCertFixtures.js');

async function createEchoTlsServer(credentials) {
  return createTestTlsServer(credentials, (socket) => {
    socket.on('data', (chunk) => socket.write(chunk));
  });
}

module.exports = {
  createTestTlsServer,
  TlsClient,
  loadCertificateFixtures,
  createEchoTlsServer,
};
