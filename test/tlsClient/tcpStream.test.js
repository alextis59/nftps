const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { TcpStream } = require('../../src/tlsClient/tcpStream.js');

class FakeSocket extends EventEmitter {
  write(buf, cb) {
    this.lastWrite = buf;
    cb();
  }
}

class RaceSocket extends FakeSocket {
  injected = false;

  armBufferedRace() {
    if (this.injected) {
      return;
    }

    this.injected = true;
    this.emit('data', Buffer.from('ping'));
  }

  once(event, listener) {
    if (event === 'data' && !this.injected) {
      this.injected = true;
      this.emit('data', Buffer.from('ping'));
    }

    return super.once(event, listener);
  }
}

test('TcpStream.readExactly validates length and supports zero', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  await assert.rejects(() => stream.readExactly(-1), /non-negative integer/);
  await assert.rejects(() => stream.readExactly(1.5), /non-negative integer/);

  const zero = await stream.readExactly(0);
  assert.strictEqual(zero.length, 0);
});

test('TcpStream.readExactly consumes buffered bytes in order', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  socket.emit('data', Buffer.from('hello'));

  const first = await stream.readExactly(2);
  const second = await stream.readExactly(3);

  assert.strictEqual(first.toString('utf8'), 'he');
  assert.strictEqual(second.toString('utf8'), 'llo');
});

test('TcpStream.readExactly waits for data and rejects on close', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  const pending = stream.readExactly(4);
  setImmediate(() => socket.emit('data', Buffer.from('ping')));
  const received = await pending;
  assert.strictEqual(received.toString('utf8'), 'ping');

  const waiting = stream.readExactly(1);
  setImmediate(() => socket.emit('close'));
  await assert.rejects(waiting, /Socket closed while waiting for TLS record bytes/);
});

test('TcpStream.readExactly rejects on socket error and on reads after end', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);
  const expectedError = new Error('socket broke');

  const waiting = stream.readExactly(1);
  setImmediate(() => socket.emit('error', expectedError));
  await assert.rejects(waiting, /socket broke/);
  await assert.rejects(() => stream.readExactly(1), /socket broke/);

  const endedSocket = new FakeSocket();
  const endedStream = new TcpStream(endedSocket);
  endedSocket.emit('end');
  await assert.rejects(() => endedStream.readExactly(1), /Socket closed while waiting for TLS record bytes/);
});

test('TcpStream.write validates input and propagates write errors', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  await assert.rejects(() => stream.write('not-buffer'), /TcpStream.write expects a Buffer/);

  await stream.write(Buffer.from('ok'));
  assert.strictEqual(socket.lastWrite.toString('utf8'), 'ok');

  socket.write = (_buf, cb) => cb(new Error('boom'));
  await assert.rejects(() => stream.write(Buffer.from('x')), /boom/);
});

test('TcpStream.readExactly resolves when bytes are buffered during waiter setup', async () => {
  const socket = new RaceSocket();
  const stream = new TcpStream(socket);

  const pending = stream.readExactly(4);
  if (!socket.injected) {
    socket.armBufferedRace();
  }

  let timer;
  try {
    const received = await Promise.race([
      pending,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Timed out waiting for buffered bytes')), 100);
      }),
    ]);
    assert.strictEqual(received.toString('utf8'), 'ping');
  } finally {
    clearTimeout(timer);
  }
});

test('TcpStream.detach stops buffering future data', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  stream.detach();
  socket.emit('data', Buffer.from('x'));

  const waiting = stream.readExactly(1);
  setImmediate(() => socket.emit('close'));
  await assert.rejects(waiting, /Socket closed while waiting for TLS record bytes/);
});

test('TcpStream ignores duplicate close notifications after ending once', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  const waiting = stream.readExactly(1);
  socket.emit('close');
  socket.emit('end');

  await assert.rejects(waiting, /Socket closed while waiting for TLS record bytes/);
  await assert.rejects(() => stream.readExactly(1), /Socket closed while waiting for TLS record bytes/);
});
