import { describe, it, expect } from "vitest";
import { getAuthHealthReport } from "../../src/diagnostics/health.js";

describe("Health Diagnostics", () => {
  it("generates a valid health report structure", async () => {
    const report = await getAuthHealthReport();
    expect(report).toBeDefined();
    expect(["healthy", "degraded", "unhealthy"]).toContain(report.status);
    expect(typeof report.version).toBe("string");
    expect(typeof report.dialect).toBe("string");
    expect(typeof report.uptimeSeconds).toBe("number");
    expect(report.database).toBeDefined();
    expect(report.config).toBeDefined();
    expect(typeof report.timestamp).toBe("string");
  });
});
