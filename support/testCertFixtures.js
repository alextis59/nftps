const path = require('node:path');
const { readFile } = require('node:fs/promises');

const baseDir = path.join(__dirname, '../test/fixtures/pki');

async function readPem(filename) {
  return readFile(path.join(baseDir, filename), 'utf8');
}

async function loadCertificateFixtures() {
  const [
    caCert,
    wrongCaCert,
    serverKey,
    serverCert,
    clientKey,
    clientCert,
  ] = await Promise.all([
    readPem('ca.crt'),
    readPem('wrong-ca.crt'),
    readPem('server.key'),
    readPem('server.crt'),
    readPem('client.key'),
    readPem('client.crt'),
  ]);

  return {
    caCert,
    wrongCaCert,
    serverKey,
    serverCert,
    clientKey,
    clientCert,
  };
}

module.exports = {
  loadCertificateFixtures,
};
