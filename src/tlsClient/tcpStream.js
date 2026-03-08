/**
 * Minimal buffered TCP helper used by the TLS record layer to read exact byte
 * counts off a socket.
 */
class TcpStream {
  #buffer = Buffer.alloc(0);
  #waiters = [];
  #ended = false;
  #error = null;
  #onData;
  #onClose;
  #onError;

  /**
   * @param {import('node:net').Socket} socket
   */
  constructor(socket) {
    this.socket = socket;
    this.#onData = (chunk) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.resolve();
      }
    };
    this.#onClose = () => {
      if (this.#ended) {
        return;
      }

      this.#ended = true;
      const err = new Error('Socket closed while waiting for TLS record bytes');
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.reject(err);
      }
    };
    this.#onError = (err) => {
      this.#error = err;
      const waiters = this.#waiters;
      this.#waiters = [];
      for (const waiter of waiters) {
        waiter.reject(err);
      }
    };
    socket.on('data', this.#onData);
    socket.on('end', this.#onClose);
    socket.on('close', this.#onClose);
    socket.on('error', this.#onError);
  }

  /**
   * Read exactly `n` bytes from the underlying socket, buffering as needed.
   * @param {number} n
   * @returns {Promise<Buffer>}
   */
  async readExactly(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw new TypeError('readExactly requires a non-negative integer length');
    }

    if (n === 0) {
      return Buffer.alloc(0);
    }

    while (this.#buffer.length < n) {
      if (this.#error) {
        throw this.#error;
      }
      if (this.#ended) {
        throw new Error('Socket closed while waiting for TLS record bytes');
      }

      await new Promise((resolve, reject) => {
        this.#waiters.push({ resolve, reject });
      });
    }

    const out = this.#buffer.subarray(0, n);
    this.#buffer = this.#buffer.subarray(n);
    return out;
  }

  /**
   * Write a buffer to the underlying socket.
   * @param {Buffer} buf
   */
  async write(buf) {
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('TcpStream.write expects a Buffer');
    }

    await new Promise((resolve, reject) => {
      this.socket.write(buf, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  detach() {
    if (this.#onData) {
      this.socket.off('data', this.#onData);
      this.#onData = null;
    }
  }
}

module.exports = {
  TcpStream,
};
