const registeredTargets = new Set();
let handlersInstalled = false;

/**
 * Register one or more database pools or adapters for graceful shutdown.
 * Automatically hooks process signals (SIGINT, SIGTERM) to drain connections cleanly.
 *
 * @param {object|object[]} targets - pool, adapter, or array/object of pools/adapters
 * @param {object} [options]
 * @param {string[]} [options.signals=["SIGINT", "SIGTERM"]] - process signals to listen to
 * @param {number} [options.timeoutMs=5000] - timeout before forced exit
 * @param {Function} [options.onShutdown] - optional callback run after all connections close
 * @returns {() => Promise<void>} shutdown function that can also be called programmatically
 */
export function registerGracefulShutdown(targets, options = {}) {
  const {
    signals = ["SIGINT", "SIGTERM"],
    timeoutMs = 5000,
    onShutdown = null,
  } = options;

  let targetList = [];
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
      process.once(sig, async () => {
        console.log(`\n[database] Received ${sig}, closing database connections gracefully...`);
        const timer = setTimeout(() => {
          console.warn("[database] Graceful shutdown timed out; forcing process exit.");
          process.exit(1);
        }, timeoutMs);

        try {
          await closeAllConnections();
          if (typeof onShutdown === "function") {
            await onShutdown();
          }
          clearTimeout(timer);
          process.exit(0);
        } catch (err) {
          console.error("[database] Error during graceful shutdown:", err.message);
          clearTimeout(timer);
          process.exit(1);
        }
      });
    }
  }

  return closeAllConnections;
}

/**
 * Programmatically close all registered database connections and clear the registry.
 * Useful for test suite teardowns and controlled application stops.
 *
 * @returns {Promise<void>}
 */
export async function closeAllConnections() {
  const targets = Array.from(registeredTargets);
  registeredTargets.clear();

  await Promise.all(
    targets.map(async (target) => {
      try {
        if (typeof target.end === "function") {
          await target.end();
        } else if (typeof target.close === "function") {
          await target.close();
        }
      } catch (err) {
        console.error("[database] Failed to close database connection:", err.message);
      }
    })
  );
}

export default registerGracefulShutdown;
