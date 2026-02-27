const test = require('node:test');
const assert = require('node:assert');
const { createTestTlsServer } = require('../../support/tlsClientTestHelpers.js');

test('server rejects malformed tls options', () => {
  assert.throws(() => createTestTlsServer({ key: undefined, cert: undefined }), /private key/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: undefined }), /certificate/);
  assert.throws(() => createTestTlsServer(null), /credentials object/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert', requestCert: 'true' }), /requestCert flag must be a boolean/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert', ca: 'not-array' }), /ca must be an array/);
  assert.throws(
    () => createTestTlsServer({ key: 'key', cert: 'cert', rejectUnauthorized: 'true' }),
    /rejectUnauthorized flag must be a boolean/,
  );
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert', ciphers: 123 }), /ciphers must be a string/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert', minVersion: 12 }), /minVersion must be a string/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert', maxVersion: 12 }), /maxVersion must be a string/);
  assert.throws(() => createTestTlsServer({ key: 'key', cert: 'cert' }, 'not-fn'), /onConnection handler must be a function/);
});
