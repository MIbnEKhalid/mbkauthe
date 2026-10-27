export class Mutex {
  private _readers = 0;
  private _writerActive = false;
  private _writeQueue: Array<{ resolve: (release: () => void) => void }> = [];
  private _readQueue: Array<{ resolve: (release: () => void) => void }> = [];

  /**
   * Acquire exclusive write lock (aliased to acquire() for 100% backwards compatibility)
   */
  acquire(): Promise<() => void> {
    return this.acquireWrite();
  }

  /**
   * Acquire exclusive write lock
   */
  acquireWrite(): Promise<() => void> {
    if (!this._writerActive && this._readers === 0) {
      this._writerActive = true;
      let released = false;
      return Promise.resolve(() => {
        if (released) return;
        released = true;
        this._writerActive = false;
        this._drain();
      });
    }

    return new Promise<() => void>((resolve) => {
      this._writeQueue.push({ resolve });
    });
  }

  /**
   * Acquire shared read lock (concurrent readers allowed)
   */
  acquireRead(): Promise<() => void> {
    if (!this._writerActive && this._writeQueue.length === 0) {
      this._readers++;
      let released = false;
      return Promise.resolve(() => {
        if (released) return;
        released = true;
        this._readers--;
        this._drain();
      });
    }

    return new Promise<() => void>((resolve) => {
      this._readQueue.push({ resolve });
    });
  }

  private _drain(): void {
    if (this._readers === 0 && !this._writerActive && this._writeQueue.length > 0) {
      const nextWriter = this._writeQueue.shift()!;
      this._writerActive = true;
      let released = false;
      nextWriter.resolve(() => {
        if (released) return;
        released = true;
        this._writerActive = false;
        this._drain();
      });
      return;
    }

    if (!this._writerActive && this._writeQueue.length === 0 && this._readQueue.length > 0) {
      const readersToWake = this._readQueue.splice(0, this._readQueue.length);
      this._readers += readersToWake.length;
      for (const r of readersToWake) {
        let released = false;
        r.resolve(() => {
          if (released) return;
          released = true;
          this._readers--;
          this._drain();
        });
      }
    }
  }
}

export class SqliteClient {
  public db: any;
  private _releaseLock: (() => void) | null;
  private _queryFn: ((db: any, queryOrText: any, maybeValues?: any[]) => Promise<any>) | null;

  constructor(db: any, releaseLock: (() => void) | null, queryFn: ((db: any, queryOrText: any, maybeValues?: any[]) => Promise<any>) | null) {
    this.db = db;
    this._releaseLock = releaseLock;
    this._queryFn = queryFn;
  }

  async query<T = any>(queryOrText: any, maybeValues?: any[]): Promise<any> {
    if (typeof this._queryFn === "function") return this._queryFn(this.db, queryOrText, maybeValues);
    if (typeof this.db?.query === "function") return this.db.query(queryOrText, maybeValues);
    throw new Error("SqliteClient has no query function or db.query method");
  }

  release(): void {
    if (this._releaseLock) {
      this._releaseLock();
      this._releaseLock = null;
    }
  }
}

export default Mutex;
