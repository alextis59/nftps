const { TcpStream } = require('./tcpStream.js');
const { TLS_VERSION_1_2 } = require('./constants.js');
const { makeCipherStateFromKeyBlock } = require('./cipherState.js');
const { TlsRecordLayer } = require('./tlsRecordLayer.js');
const { TlsClient } = require('./TlsClient.js');

module.exports = {
  TcpStream,
  TLS_VERSION_1_2,
  makeCipherStateFromKeyBlock,
  TlsRecordLayer,
  TlsClient,
};
