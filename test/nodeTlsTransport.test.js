const test = require('node:test');
const assert = require('node:assert');
const tls = require('node:tls');
const { EventEmitter } = require('node:events');

const { NodeTlsTransport } = require('../src/nodeTlsTransport.js');

class FakeRawSocket extends EventEmitter {
  constructor() {
    super();
    this.destroyed = false;
    this.destroyCalls = 0;
  }

  destroy() {
    this.destroyed = true;
    this.destroyCalls += 1;
  }
}

class FakeTlsSocket extends EventEmitter {
  constructor({ authorized = false, authorizationError = null } = {}) {
    super();
    this.authorized = authorized;
    this.authorizationError = authorizationError;
    this.destroyed = false;
    this.writeError = null;
    this.writeCalls = [];
    this.endCalls = 0;
    this.destroyCalls = 0;
    this.endBehavior = 'close';
  }

  write(data, callback) {
    this.writeCalls.push(Buffer.from(data));
    callback(this.writeError);
  }

  end() {
    this.endCalls += 1;
    this.destroyed = true;
    if (this.endBehavior === 'error') {
      this.emit('error', new Error('end failed'));
      return;
    }
    this.emit('close');
  }

  destroy() {
    this.destroyCalls += 1;
    this.destroyed = true;
    this.emit('close');
  }
}

test('NodeTlsTransport.fromExistingSocket forwards defined options and returns a transport', async (t) => {
  const rawSocket = new FakeRawSocket();
  const tlsSocket = new FakeTlsSocket({ authorized: true });
  const originalConnect = tls.connect;
  let capturedOptions;

  t.after(() => {
    tls.connect = originalConnect;
  });

  tls.connect = (options) => {
    capturedOptions = options;
    process.nextTick(() => tlsSocket.emit('secureConnect'));
    return tlsSocket;
  };

  const checkServerIdentity = () => undefined;
  const transport = await NodeTlsTransport.fromExistingSocket(rawSocket, {
    servername: 'localhost',
    clientCert: 'client-cert',
    clientKey: 'client-key',
    ca: ['ca-cert'],
    rejectUnauthorized: false,
    checkServerIdentity,
    ciphers: 'TLS_AES_128_GCM_SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
  });

  assert.strictEqual(capturedOptions.socket, rawSocket);
  assert.strictEqual(capturedOptions.servername, 'localhost');
  assert.strictEqual(capturedOptions.cert, 'client-cert');
  assert.strictEqual(capturedOptions.key, 'client-key');
  assert.deepStrictEqual(capturedOptions.ca, ['ca-cert']);
  assert.strictEqual(capturedOptions.rejectUnauthorized, false);
  assert.strictEqual(capturedOptions.checkServerIdentity, checkServerIdentity);
  assert.strictEqual(capturedOptions.ciphers, 'TLS_AES_128_GCM_SHA256');
  assert.strictEqual(capturedOptions.minVersion, 'TLSv1.2');
  assert.strictEqual(capturedOptions.maxVersion, 'TLSv1.3');
  assert.strictEqual(transport.implementation, 'node');
  assert.strictEqual(transport.authorized, true);
});

test('NodeTlsTransport.fromExistingSocket destroys sockets on handshake failure', async (t) => {
  const rawSocket = new FakeRawSocket();
  const tlsSocket = new FakeTlsSocket();
  const originalConnect = tls.connect;

  t.after(() => {
    tls.connect = originalConnect;
  });

  tls.connect = () => {
    process.nextTick(() => tlsSocket.emit('error', new Error('handshake failed')));
    return tlsSocket;
  };

  await assert.rejects(
    () => NodeTlsTransport.fromExistingSocket(rawSocket, { servername: 'localhost' }),
    /handshake failed/,
  );
  assert.strictEqual(tlsSocket.destroyCalls, 1);
  assert.strictEqual(rawSocket.destroyCalls, 1);
});

test('NodeTlsTransport.readApplicationData supports buffered reads and waiter delivery', async () => {
  const transport = new NodeTlsTransport(new FakeRawSocket(), new FakeTlsSocket());

  transport.tlsSocket.emit('data', Buffer.from('first'));
  assert.strictEqual((await transport.readApplicationData()).toString('utf8'), 'first');

  const waiting = transport.readApplicationData();
  transport.tlsSocket.emit('data', Buffer.from('second'));
  assert.strictEqual((await waiting).toString('utf8'), 'second');
});

test('NodeTlsTransport.readApplicationData rejects on socket end and on subsequent reads', async () => {
  const transport = new NodeTlsTransport(new FakeRawSocket(), new FakeTlsSocket());

  const waiting = transport.readApplicationData();
  transport.tlsSocket.emit('end');
  await assert.rejects(waiting, /TLS socket closed while waiting for application data/);
  await assert.rejects(
    () => transport.readApplicationData(),
    /TLS socket closed while waiting for application data/,
  );
});

test('NodeTlsTransport.readApplicationData rejects on socket error and rethrows the stored error', async () => {
  const transport = new NodeTlsTransport(new FakeRawSocket(), new FakeTlsSocket());
  const expectedError = new Error('stream broke');

  const waiting = transport.readApplicationData();
  transport.tlsSocket.emit('error', expectedError);
  await assert.rejects(waiting, /stream broke/);
  await assert.rejects(() => transport.readApplicationData(), /stream broke/);
});

test('NodeTlsTransport.sendApplicationData propagates write callback errors', async () => {
  const tlsSocket = new FakeTlsSocket();
  tlsSocket.writeError = new Error('write failed');
  const transport = new NodeTlsTransport(new FakeRawSocket(), tlsSocket);

  await assert.rejects(
    () => transport.sendApplicationData(Buffer.from('payload')),
    /write failed/,
  );
});

test('NodeTlsTransport.shutdownToPlain rejects unsupported downgrade attempts', async () => {
  const transport = new NodeTlsTransport(new FakeRawSocket(), new FakeTlsSocket());

  await assert.rejects(
    () => transport.shutdownToPlain(),
    /cannot downgrade to plain TCP/i,
  );
});

test('NodeTlsTransport.close detaches listeners when the TLS socket is already destroyed', async () => {
  const tlsSocket = new FakeTlsSocket();
  const transport = new NodeTlsTransport(new FakeRawSocket(), tlsSocket);
  tlsSocket.destroyed = true;

  await transport.close();

  assert.strictEqual(tlsSocket.listenerCount('data'), 0);
  assert.strictEqual(tlsSocket.listenerCount('end'), 0);
  assert.strictEqual(tlsSocket.listenerCount('close'), 0);
  assert.strictEqual(tlsSocket.listenerCount('error'), 0);
});

test('NodeTlsTransport.close uses end by default and destroy when sendCloseNotify is false', async () => {
  const notifySocket = new FakeTlsSocket();
  const notifyTransport = new NodeTlsTransport(new FakeRawSocket(), notifySocket);

  await notifyTransport.close();
  assert.strictEqual(notifySocket.endCalls, 1);
  assert.strictEqual(notifySocket.destroyCalls, 0);

  const abortSocket = new FakeTlsSocket();
  const abortTransport = new NodeTlsTransport(new FakeRawSocket(), abortSocket);

  await abortTransport.close({ sendCloseNotify: false });
  assert.strictEqual(abortSocket.endCalls, 0);
  assert.strictEqual(abortSocket.destroyCalls, 1);
});

test('NodeTlsTransport.close resolves on TLS socket error and detaches listeners', async () => {
  const tlsSocket = new FakeTlsSocket();
  tlsSocket.endBehavior = 'error';
  const transport = new NodeTlsTransport(new FakeRawSocket(), tlsSocket);

  await transport.close();

  assert.strictEqual(tlsSocket.endCalls, 1);
  assert.strictEqual(tlsSocket.listenerCount('data'), 0);
  assert.strictEqual(tlsSocket.listenerCount('end'), 0);
  assert.strictEqual(tlsSocket.listenerCount('close'), 0);
  assert.strictEqual(tlsSocket.listenerCount('error'), 0);
});
