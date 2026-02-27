const { TcpStream } = require('./tcpStream.js');
const {
  TLS_VERSION_1_2,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  SUPPORTED_CIPHER_SUITES,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
  CIPHER_SUITE_TO_OPENSSL_NAME,
  OPENSSL_CIPHER_NAME_TO_SUITE,
} = require('./constants.js');
const { makeCipherStateFromKeyBlock } = require('./cipherState.js');
const { TlsRecordLayer } = require('./tlsRecordLayer.js');
const { TlsClient } = require('./TlsClient.js');

module.exports = {
  TcpStream,
  TLS_VERSION_1_2,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  SUPPORTED_CIPHER_SUITES,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
  CIPHER_SUITE_TO_OPENSSL_NAME,
  OPENSSL_CIPHER_NAME_TO_SUITE,
  makeCipherStateFromKeyBlock,
  TlsRecordLayer,
  TlsClient,
};
