const { createTestTlsServer } = require('./tlsServer.js');
const {
  TcpStream,
  TLS_VERSION_1_2,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  SUPPORTED_CIPHER_SUITES,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
  CIPHER_SUITE_TO_OPENSSL_NAME,
  OPENSSL_CIPHER_NAME_TO_SUITE,
  TlsRecordLayer,
  TlsClient,
  makeCipherStateFromKeyBlock,
} = require('./tlsClient.js');
const { FtpsClient } = require('./ftpsClient.js');

module.exports = {
  createTestTlsServer,
  TcpStream,
  TLS_VERSION_1_2,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  SUPPORTED_CIPHER_SUITES,
  DEFAULT_COMPRESSION_METHODS,
  DEFAULT_SIGNATURE_ALGORITHMS,
  CIPHER_SUITE_TO_OPENSSL_NAME,
  OPENSSL_CIPHER_NAME_TO_SUITE,
  TlsRecordLayer,
  TlsClient,
  makeCipherStateFromKeyBlock,
  FtpsClient,
};
