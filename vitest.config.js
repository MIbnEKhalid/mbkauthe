import { defineConfig } from "vitest/config";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.js"],
    exclude: ["node_modules", "dist", ".git"],
    testTimeout: 15_000,
    hookTimeout: 30_000,
    pool: "forks",
    singleFork: true,
    coverage: {
      provider: "v8",
      include: ["lib/**/*.js"],
      reporter: ["text", "html", "lcov"],
      reportsDirectory: "./coverage",
    },
    deps: {
      external: ["better-sqlite3"],
    },
  },
  resolve: {
    alias: {
      "#pool.js": path.resolve(__dirname, "lib/pool.js"),
      "#response.js": path.resolve(__dirname, "lib/utils/response.js"),
      "#config.js": path.resolve(__dirname, "lib/config/index.js"),
      "#cookies.js": path.resolve(__dirname, "lib/config/cookies.js"),
    },
  },
});
