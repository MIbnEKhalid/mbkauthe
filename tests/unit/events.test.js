import { describe, test, expect, vi } from "vitest";
import { AuthEventEmitter, authEvents, emitAuthEvent } from "../../dist/index.js";

describe("Domain Event Bus (AuthEventEmitter)", () => {
  test("subscribes and emits typed events synchronously and asynchronously", async () => {
    const emitter = new AuthEventEmitter();
    const mockListener = vi.fn();

    emitter.on("auth:login:success", mockListener);

    emitter.emit("auth:login:success", {
      userId: 42,
      username: "testuser",
      ip: "127.0.0.1",
      timestamp: new Date(),
    });

    expect(mockListener).toHaveBeenCalledTimes(1);
    expect(mockListener).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 42,
        username: "testuser",
        ip: "127.0.0.1",
      })
    );
  });

  test("once listener fires only once", () => {
    const emitter = new AuthEventEmitter();
    const mockListener = vi.fn();

    emitter.once("auth:logout", mockListener);

    emitter.emit("auth:logout", { userId: 1, timestamp: new Date() });
    emitter.emit("auth:logout", { userId: 1, timestamp: new Date() });

    expect(mockListener).toHaveBeenCalledTimes(1);
  });

  test("emitAuthEvent helper automatically populates timestamp", () => {
    const mockListener = vi.fn();
    authEvents.on("auth:token:created", mockListener);

    emitAuthEvent("auth:token:created", {
      tokenId: 123,
      userId: "testuser",
      name: "CLI Token",
      scopes: ["read:data"],
    });

    expect(mockListener).toHaveBeenCalled();
    const callArg = mockListener.mock.calls[0][0];
    expect(callArg.tokenId).toBe(123);
    expect(callArg.timestamp).toBeInstanceOf(Date);

    authEvents.removeAllListeners("auth:token:created");
  });
});
