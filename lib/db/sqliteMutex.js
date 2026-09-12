/**
 * Promise-based FIFO Mutex for serializing SQLite operations.
 */
export class Mutex {
  constructor() {
    this._tail = Promise.resolve();
  }

  acquire() {
    const prev = this._tail;
    let release;
    this._tail = new Promise((resolve) => {
      let released = false;
      release = () => {
        if (released) return;
        released = true;
        resolve();
      };
    });
    return prev.then(() => release);
  }
}

/**
 * Dedicated client returned by pool/adapter connect() to represent a transaction connection.
 */
export class SqliteClient {
  constructor(db, releaseLock, queryFn) {
    this.db = db;
    this._releaseLock = releaseLock;
    this._queryFn = queryFn;
  }

  async query(queryOrText, maybeValues) {
    if (typeof this._queryFn === "function") return this._queryFn(this.db, queryOrText, maybeValues);
    if (typeof this.db?.query === "function") return this.db.query(queryOrText, maybeValues);
    throw new Error("SqliteClient has no query function or db.query method");
  }

  release() {
    if (this._releaseLock) {
      this._releaseLock();
      this._releaseLock = null;
    }
  }
}

export default Mutex;
