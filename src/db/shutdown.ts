const registeredTargets = new Set<any>();
let handlersInstalled = false;

export function registerGracefulShutdown(targets: any, options: { signals?: string[]; timeoutMs?: number; onShutdown?: (() => Promise<void> | void) | null } = {}) {
  const { signals = ["SIGINT", "SIGTERM"], timeoutMs = 5000, onShutdown = null } = options;

  let targetList: any[] = [];
  if (Array.isArray(targets)) {
    targetList = targets;
  } else if (targets && (typeof targets.end === "function" || typeof targets.close === "function")) {
    targetList = [targets];
  } else if (typeof targets === "object" && targets !== null) {
    targetList = Object.values(targets);
  } else if (targets) {
    targetList = [targets];
  }

  for (const t of targetList) {
    if (t && (typeof t.end === "function" || typeof t.close === "function")) {
      registeredTargets.add(t);
    }
  }

  if (!handlersInstalled && typeof process !== "undefined" && typeof process.once === "function") {
    handlersInstalled = true;
    for (const sig of signals) {
      process.once(sig as NodeJS.Signals, async () => {
        console.log(`\n[database] Received ${sig}, closing database connections gracefully...`);
        const timer = setTimeout(() => {
          console.warn("[database] Graceful shutdown timed out; forcing process exit.");
          process.exit(1);
        }, timeoutMs);

        try {
          await closeAllConnections();
          if (typeof onShutdown === "function") await onShutdown();
          clearTimeout(timer);
          process.exit(0);
        } catch (err: any) {
          console.error("[database] Error during graceful shutdown:", err.message);
          clearTimeout(timer);
          process.exit(1);
        }
      });
    }
  }

  return closeAllConnections;
}

export async function closeAllConnections(): Promise<void> {
  const targets = Array.from(registeredTargets);
  registeredTargets.clear();

  await Promise.all(
    targets.map(async (target) => {
      try {
        if (typeof target.end === "function") await target.end();
        else if (typeof target.close === "function") await target.close();
      } catch (err: any) {
        console.error("[database] Failed to close database connection:", err.message);
      }
    })
  );
}

export default registerGracefulShutdown;
