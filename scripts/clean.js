import fs from "fs";
import path from "path";

const distPath = path.resolve("dist");
if (fs.existsSync(distPath)) {
  fs.rmSync(distPath, { recursive: true, force: true });
  console.log("Cleaned dist/ directory.");
}
