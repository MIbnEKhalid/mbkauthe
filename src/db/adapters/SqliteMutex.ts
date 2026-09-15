export class Mutex {
  private _tail: Promise<void>;

  constructor() {
    this._tail = Promise.resolve();
  }

  acquire(): Promise<() => void> {
    const prev = this._tail;
    let release!: () => void;
    this._tail = new Promise<void>((resolve) => {
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
