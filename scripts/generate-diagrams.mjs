import { execSync } from "child_process";
import fs from "fs";
import path from "path";

const mmdDir = path.resolve("docs/diagrams/mmd");
const imagesDir = path.resolve("docs/diagrams/images");
const configFile = path.resolve("scripts/mermaid-config.json");

if (!fs.existsSync(imagesDir)) {
  fs.mkdirSync(imagesDir, { recursive: true });
}

const files = fs.readdirSync(mmdDir).filter(f => f.endsWith(".mmd"));

console.log(`Found ${files.length} Mermaid diagram definitions in ${mmdDir}`);

for (const file of files) {
  const baseName = path.basename(file, ".mmd");
  const inputPath = path.join(mmdDir, file);
  const svgPath = path.join(imagesDir, `${baseName}.svg`);

  console.log(`[Rendering SVG] ${file} -> images/${baseName}.svg`);

  try {
    execSync(
      `npx -y @mermaid-js/mermaid-cli -i "${inputPath}" -o "${svgPath}" -c "${configFile}" -w 2800 -b white`,
      { stdio: "inherit" }
    );
  } catch (err) {
    console.error(`Failed to generate SVG for ${file}:`, err);
  }
}

console.log("All vector SVG diagrams generated successfully in docs/diagrams/images/!");
