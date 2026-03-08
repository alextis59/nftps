const tls = require('node:tls');
const { once } = require('node:events');

class BufferedApplicationStream {
  #chunks = [];
  #waiters = [];
  #ended = false;
  #error = null;
  #onData;
  #onClose;
  #onError;

  constructor(socket) {
    this.socket = socket;
    this.#onData = (chunk) => {
      if (this.#waiters.length > 0) {
        const waiter = this.#waiters.shift();
        waiter.resolve(chunk);
        return;
      }

      this.#chunks.push(chunk);
    };
    this.#onClose = () => {
      if (this.#ended) {
        return;
      }

      this.#ended = true;
      const err = new Error('TLS socket closed while waiting for application data');
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

  async read() {
    if (this.#chunks.length > 0) {
      return this.#chunks.shift();
    }

    if (this.#error) {
      throw this.#error;
    }

    if (this.#ended) {
      throw new Error('TLS socket closed while waiting for application data');
    }

    return await new Promise((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }

  detach() {
    if (this.#onData) {
      this.socket.off('data', this.#onData);
      this.#onData = null;
    }
    if (this.#onClose) {
      this.socket.off('end', this.#onClose);
      this.socket.off('close', this.#onClose);
      this.#onClose = null;
    }
    if (this.#onError) {
      this.socket.off('error', this.#onError);
      this.#onError = null;
    }
  }
}

class NodeTlsTransport {
  constructor(rawSocket, tlsSocket) {
    this.socket = rawSocket;
    this.tlsSocket = tlsSocket;
    this.authorized = tlsSocket.authorized;
    this.authorizationError = tlsSocket.authorizationError || null;
    this.implementation = 'node';
    this.applicationStream = new BufferedApplicationStream(tlsSocket);
  }

  static async fromExistingSocket(
    socket,
    {
      servername,
      clientCert,
      clientKey,
      ca,
      rejectUnauthorized = true,
      checkServerIdentity,
      ciphers,
      minVersion,
      maxVersion,
    } = {},
  ) {
    const connectOptions = {
      socket,
      servername,
      rejectUnauthorized,
    };
    if (clientCert !== undefined) {
      connectOptions.cert = clientCert;
    }
    if (clientKey !== undefined) {
      connectOptions.key = clientKey;
    }
    if (ca !== undefined) {
      connectOptions.ca = ca;
    }
    if (checkServerIdentity !== undefined) {
      connectOptions.checkServerIdentity = checkServerIdentity;
    }
    if (ciphers !== undefined) {
      connectOptions.ciphers = ciphers;
    }
    if (minVersion !== undefined) {
      connectOptions.minVersion = minVersion;
    }
    if (maxVersion !== undefined) {
      connectOptions.maxVersion = maxVersion;
    }

    const tlsSocket = tls.connect(connectOptions);

    try {
      await once(tlsSocket, 'secureConnect');
      return new NodeTlsTransport(socket, tlsSocket);
    } catch (err) {
      tlsSocket.destroy();
      if (socket && !socket.destroyed) {
        socket.destroy();
      }
      throw err;
    }
  }

  async sendApplicationData(data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    await new Promise((resolve, reject) => {
      this.tlsSocket.write(buffer, (err) => (err ? reject(err) : resolve()));
    });
  }

  async readApplicationData() {
    return await this.applicationStream.read();
  }

  async shutdownToPlain() {
    throw new Error(
      'Node TLS transport cannot downgrade to plain TCP on the same socket; pass { downgrade: false } or use TLSv1.2',
    );
  }

  async close({ sendCloseNotify = true } = {}) {
    if (!this.tlsSocket || this.tlsSocket.destroyed) {
      this.applicationStream.detach();
      return;
    }

    await new Promise((resolve) => {
      const handleClose = () => {
        this.tlsSocket.off('error', handleError);
        resolve();
      };
      const handleError = () => {
        this.tlsSocket.off('close', handleClose);
        resolve();
      };

      this.tlsSocket.once('close', handleClose);
      this.tlsSocket.once('error', handleError);

      if (sendCloseNotify) {
        this.tlsSocket.end();
      } else {
        this.tlsSocket.destroy();
      }
    });

    this.applicationStream.detach();
  }
}

module.exports = {
  NodeTlsTransport,
};
