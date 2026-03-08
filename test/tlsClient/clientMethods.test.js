const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');

const { TlsClient } = require('../../src/index.js');

class FakeSocket extends EventEmitter {
  write(_buf, callback) {
    if (callback) {
      callback();
    }
  }

  destroy() {
    this.destroyed = true;
  }
}

function createClient(options = {}) {
  const socket = new FakeSocket();
  const client = new TlsClient(socket, 'localhost', options);
  let detached = false;

  client.tcp = {
    detach() {
      detached = true;
    },
  };

  return {
    client,
    socket,
    wasDetached: () => detached,
  };
}

test('TlsClient constructor initializes default client hello extensions', () => {
  const { client } = createClient();

  assert.strictEqual(client.extensions.serverName, true);
  assert.ok(Array.isArray(client.extensions.signatureAlgorithms));
  assert.ok(client.extensions.signatureAlgorithms.length > 0);
  assert.deepStrictEqual(client.extensions.extra, []);
});

test('TlsClient.readHandshakeMessage reassembles fragmented records and preserves buffered remainder', async () => {
  const { client } = createClient();
  const firstMessage = Buffer.from([0x02, 0x00, 0x00, 0x01, 0xaa]);
  const secondMessage = Buffer.from([0x0e, 0x00, 0x00, 0x00]);
  const records = [
    { type: 0x16, fragment: firstMessage.subarray(0, 2) },
    { type: 0x16, fragment: Buffer.concat([firstMessage.subarray(2), secondMessage]) },
  ];
  let reads = 0;

  client.recordLayer = {
    readPlainRecord: async () => {
      reads += 1;
      return records.shift();
    },
  };

  const first = await client.readHandshakeMessage(false);
  const second = await client.readHandshakeMessage(false);

  assert.ok(first.raw.equals(firstMessage));
  assert.ok(second.raw.equals(secondMessage));
  assert.strictEqual(reads, 2);
});

test('TlsClient.readHandshakeMessage rejects unexpected record types during initial and continuation reads', async () => {
  const initial = createClient().client;
  initial.recordLayer = {
    readPlainRecord: async () => ({ type: 0x17, fragment: Buffer.from([0xaa]) }),
  };
  await assert.rejects(
    () => initial.readHandshakeMessage(false),
    /Expected Handshake record, got type 23/,
  );

  const continuation = createClient().client;
  continuation.recordLayer = {
    readPlainRecord: async () => continuation.recordLayer.records.shift(),
    records: [
      { type: 0x16, fragment: Buffer.from([0x02, 0x00, 0x00, 0x02]) },
      { type: 0x17, fragment: Buffer.from([0xaa, 0xbb]) },
    ],
  };
  await assert.rejects(
    () => continuation.readHandshakeMessage(false),
    /Expected Handshake record, got type 23/,
  );
});

test('TlsClient.readApplicationData rejects non-application records', async () => {
  const { client } = createClient();
  client.recordLayer = {
    readEncryptedRecord: async () => ({ type: 0x16, fragment: Buffer.alloc(0) }),
  };

  await assert.rejects(
    () => client.readApplicationData(),
    /Expected ApplicationData, got record type 22/,
  );
});

test('TlsClient.shutdownToPlain detaches immediately when already closed', async () => {
  const { client, socket, wasDetached } = createClient();
  client.recordLayer = { state: 'CLOSED' };

  const downgraded = await client.shutdownToPlain();

  assert.strictEqual(downgraded, socket);
  assert.strictEqual(wasDetached(), true);
});

test('TlsClient.shutdownToPlain ignores non-alert records until peer close_notify arrives', async () => {
  const { client, socket, wasDetached } = createClient();
  let sentCloseNotify = 0;
  client.recordLayer = {
    state: 'ENCRYPTED',
    sendAlertCloseNotify: async () => {
      sentCloseNotify += 1;
    },
    readEncryptedRecord: async () => client.recordLayer.records.shift(),
    records: [
      { type: 0x17, fragment: Buffer.from('payload') },
      { type: 0x15, fragment: Buffer.from([0x01, 0x00]) },
    ],
  };

  const downgraded = await client.shutdownToPlain();

  assert.strictEqual(downgraded, socket);
  assert.strictEqual(sentCloseNotify, 1);
  assert.strictEqual(wasDetached(), true);
  assert.strictEqual(client.recordLayer.state, 'CLOSED');
});

test('TlsClient.shutdownToPlain rejects malformed and fatal peer alerts', async () => {
  const malformed = createClient().client;
  malformed.recordLayer = {
    state: 'ENCRYPTED',
    sendAlertCloseNotify: async () => {},
    readEncryptedRecord: async () => ({ type: 0x15, fragment: Buffer.from([0x01]) }),
  };
  await assert.rejects(
    () => malformed.shutdownToPlain(),
    /Received malformed TLS alert while waiting for close_notify/,
  );

  const fatal = createClient().client;
  fatal.recordLayer = {
    state: 'ENCRYPTED',
    sendAlertCloseNotify: async () => {},
    readEncryptedRecord: async () => fatal.recordLayer.records.shift(),
    records: [
      { type: 0x17, fragment: Buffer.from('ignored') },
      { type: 0x15, fragment: Buffer.from([0x02, 0x28]) },
    ],
  };
  await assert.rejects(
    () => fatal.shutdownToPlain(),
    /Received fatal TLS alert 0x28 during shutdown/,
  );
});

test('TlsClient.shutdownToPlain validates timeoutMs before waiting for peer alerts', async () => {
  const { client } = createClient();
  client.recordLayer = {
    state: 'ENCRYPTED',
    sendAlertCloseNotify: async () => {},
    readEncryptedRecord: async () => new Promise(() => {}),
  };

  await assert.rejects(
    () => client.shutdownToPlain({ timeoutMs: 0 }),
    /timeoutMs must be a positive number/,
  );
});
