const TLS_VERSION_1_2 = 0x0303;
const TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
const TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c;

const CIPHER_SPECS = {
  [TLS_RSA_WITH_AES_128_CBC_SHA]: {
    macAlgorithm: 'sha1',
    macKeyLength: 20,
    macLength: 20,
  },
  [TLS_RSA_WITH_AES_128_CBC_SHA256]: {
    macAlgorithm: 'sha256',
    macKeyLength: 32,
    macLength: 32,
  },
};

module.exports = {
  TLS_VERSION_1_2,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  CIPHER_SPECS,
};
