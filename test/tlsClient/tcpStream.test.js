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

test('TcpStream.write validates input and propagates write errors', async () => {
  const socket = new FakeSocket();
  const stream = new TcpStream(socket);

  await assert.rejects(() => stream.write('not-buffer'), /TcpStream.write expects a Buffer/);

  await stream.write(Buffer.from('ok'));
  assert.strictEqual(socket.lastWrite.toString('utf8'), 'ok');

  socket.write = (_buf, cb) => cb(new Error('boom'));
  await assert.rejects(() => stream.write(Buffer.from('x')), /boom/);
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
