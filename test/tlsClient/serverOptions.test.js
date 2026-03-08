const test = require('node:test');
const assert = require('node:assert');
const tls = require('node:tls');
const { EventEmitter } = require('node:events');
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

test('server creation rejects when tls.createServer throws synchronously', async (t) => {
  const originalCreateServer = tls.createServer;

  t.after(() => {
    tls.createServer = originalCreateServer;
  });

  tls.createServer = () => {
    throw new Error('createServer failed');
  };

  await assert.rejects(
    () => createTestTlsServer({ key: 'key', cert: 'cert' }),
    /createServer failed/,
  );
});

test('server creation rejects when the listening address cannot be determined', async (t) => {
  const originalCreateServer = tls.createServer;

  t.after(() => {
    tls.createServer = originalCreateServer;
  });

  tls.createServer = () => {
    const server = new EventEmitter();
    server.listen = (_port, _host, callback) => callback();
    server.address = () => 'pipe';
    server.removeListener = server.removeListener.bind(server);
    server.once = server.once.bind(server);
    return server;
  };

  await assert.rejects(
    () => createTestTlsServer({ key: 'key', cert: 'cert' }),
    /Unable to determine listening address for TLS test server/,
  );
});

test('server creation rejects listen-time errors before startup completes', async (t) => {
  const originalCreateServer = tls.createServer;

  t.after(() => {
    tls.createServer = originalCreateServer;
  });

  tls.createServer = () => {
    const server = new EventEmitter();
    server.listen = () => {
      queueMicrotask(() => server.emit('error', new Error('listen failed')));
    };
    server.address = () => ({ port: 12345 });
    server.removeListener = server.removeListener.bind(server);
    server.once = server.once.bind(server);
    return server;
  };

  await assert.rejects(
    () => createTestTlsServer({ key: 'key', cert: 'cert' }),
    /listen failed/,
  );
});

test('server close helper rejects close errors', async (t) => {
  const originalCreateServer = tls.createServer;

  t.after(() => {
    tls.createServer = originalCreateServer;
  });

  tls.createServer = () => {
    const server = new EventEmitter();
    server.listen = (_port, _host, callback) => callback();
    server.address = () => ({ port: 12345 });
    server.close = (callback) => callback(new Error('close failed'));
    server.removeListener = server.removeListener.bind(server);
    server.once = server.once.bind(server);
    return server;
  };

  const created = await createTestTlsServer({ key: 'key', cert: 'cert' });
  await assert.rejects(
    () => created.close(),
    /close failed/,
  );
});
