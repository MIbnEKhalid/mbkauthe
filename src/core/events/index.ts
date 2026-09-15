import { EventEmitter } from "node:events";
import type { AuthEventMap, AuthEventName, AuthEventListener } from "./types.js";
import { createLogger } from "../../utils/logger.js";

const debug = createLogger("mbkauthe:events");

/**
 * Strongly typed Domain Event Emitter for MBKAuthe
 */
export class AuthEventEmitter {
  private emitter = new EventEmitter();

  constructor() {
    // Set max listeners to high value for multiple consumer integrations
    this.emitter.setMaxListeners(100);
  }

  /**
   * Subscribe to a typed auth event
   */
  on<K extends AuthEventName>(event: K, listener: AuthEventListener<K>): this {
    this.emitter.on(event, (payload: AuthEventMap[K]) => {
      try {
        const res = listener(payload);
        if (res instanceof Promise) {
          res.catch((err) => {
            debug("Async event handler error for %s: %s", event, err?.message || err);
          });
        }
      } catch (err: any) {
        debug("Sync event handler error for %s: %s", event, err?.message || err);
      }
    });
    return this;
  }

  /**
   * Subscribe to a typed auth event once
   */
  once<K extends AuthEventName>(event: K, listener: AuthEventListener<K>): this {
    this.emitter.once(event, (payload: AuthEventMap[K]) => {
      try {
        const res = listener(payload);
        if (res instanceof Promise) {
          res.catch((err) => {
            debug("Async event handler error for %s: %s", event, err?.message || err);
          });
        }
      } catch (err: any) {
        debug("Sync event handler error for %s: %s", event, err?.message || err);
      }
    });
    return this;
  }

  /**
   * Remove a listener
   */
  off<K extends AuthEventName>(event: K, listener: AuthEventListener<K>): this {
    this.emitter.off(event, listener as any);
    return this;
  }

  /**
   * Emit a typed auth event
   */
  emit<K extends AuthEventName>(event: K, payload: AuthEventMap[K]): boolean {
    debug("Emitted event %s: %o", event, payload);
    return this.emitter.emit(event, payload);
  }

  /**
   * Remove all listeners for testing or shutdown
   */
  removeAllListeners(event?: AuthEventName): this {
    this.emitter.removeAllListeners(event);
    return this;
  }
}

/** Global singleton domain event bus */
export const authEvents = new AuthEventEmitter();

/** Convenience helper to dispatch auth events */
export function emitAuthEvent<K extends AuthEventName>(event: K, payload: Omit<AuthEventMap[K], "timestamp"> & { timestamp?: Date }): void {
  const fullPayload = {
    ...payload,
    timestamp: payload.timestamp ?? new Date(),
  } as AuthEventMap[K];
  authEvents.emit(event, fullPayload);
}

export * from "./types.js";
