/**
 * Minimal buffered TCP helper used by the TLS record layer to read exact byte
 * counts off a socket.
 */
class TcpStream {
  #buffer = Buffer.alloc(0);
  #onData;

  /**
   * @param {import('node:net').Socket} socket
   */
  constructor(socket) {
    this.socket = socket;
    this.#onData = (chunk) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
    };
    socket.on('data', this.#onData);
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
      await new Promise((resolve, reject) => {
        const cleanup = () => {
          this.socket.off('error', onError);
          this.socket.off('end', onClose);
          this.socket.off('close', onClose);
          this.socket.off('data', onData);
        };
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const onClose = () => {
          cleanup();
          reject(new Error('Socket closed while waiting for TLS record bytes'));
        };
        const onData = () => {
          cleanup();
          resolve();
        };

        this.socket.once('error', onError);
        this.socket.once('end', onClose);
        this.socket.once('close', onClose);
        this.socket.once('data', onData);
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
