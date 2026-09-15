import fs from "fs/promises";
import path from "path";
import { minify } from "terser";

const BANNER = `/**
 * MBKAuthe — Unified Authentication & Authorization Framework for MBK Ecosystem
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 * Source: https://github.com/MIbnEKhalid/mbkauthe
 */
`;

async function getFiles(dir, ext) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await getFiles(fullPath, ext)));
    } else if (entry.isFile() && fullPath.endsWith(ext)) {
      files.push(fullPath);
    }
  }
  return files;
}

function minifyDtsContent(content, isIndexDts = false) {
  // Remove single line comments
  let text = content.replace(/(^|[^\\])\/\/.*$/gm, "$1");
  // Remove block comments
  text = text.replace(/\/\*[\s\S]*?\*\//g, "");
  // Normalize newlines and trim each line
  text = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join("\n");

  // Collapse spaces around symbols safely
  text = text
    .replace(/\s*([;{},|&?:=><])\s*/g, "$1")
    .replace(/export\s+/g, "export ")
    .replace(/import\s+/g, "import ")
    .replace(/from\s+/g, "from ")
    .replace(/type\s+/g, "type ")
    .replace(/interface\s+/g, "interface ")
    .replace(/declare\s+/g, "declare ")
    .replace(/class\s+/g, "class ")
    .replace(/function\s+/g, "function ")
    .replace(/const\s+/g, "const ")
    .replace(/let\s+/g, "let ")
    .replace(/var\s+/g, "var ")
    .replace(/enum\s+/g, "enum ")
    .replace(/namespace\s+/g, "namespace ")
    .replace(/abstract\s+/g, "abstract ")
    .replace(/readonly\s+/g, "readonly ")
    .replace(/as\s+/g, "as ")
    .replace(/default\s+/g, "default ")
    .replace(/extends\s+/g, "extends ")
    .replace(/implements\s+/g, "implements ")
    .replace(/keyof\s+/g, "keyof ")
    .replace(/typeof\s+/g, "typeof ")
    .replace(/in\s+/g, "in ")
    .replace(/is\s+/g, "is ");

  if (isIndexDts) {
    text = BANNER + text;
  }
  return text;
}

async function runMinify() {
  const distDir = path.resolve("dist");
  try {
    const jsFiles = await getFiles(distDir, ".js");
    console.log(`Minifying ${jsFiles.length} .js files in dist/...`);
    for (const file of jsFiles) {
      const code = await fs.readFile(file, "utf8");
      const result = await minify(code, {
        module: true,
        compress: {
          passes: 2,
          drop_debugger: true,
        },
        mangle: {
          toplevel: false,
        },
        format: {
          comments: false,
        },
      });
      let output = result.code || code;
      if (file.endsWith(path.join("dist", "index.js")) || file.endsWith("dist/index.js")) {
        output = BANNER + output;
      }
      await fs.writeFile(file, output, "utf8");
    }

    const dtsFiles = await getFiles(distDir, ".d.ts");
    console.log(`Minifying ${dtsFiles.length} .d.ts files in dist/...`);
    for (const file of dtsFiles) {
      const isIndexDts = file.endsWith(path.join("dist", "index.d.ts")) || file.endsWith("dist/index.d.ts");
      const content = await fs.readFile(file, "utf8");
      const minifiedDts = minifyDtsContent(content, isIndexDts);
      await fs.writeFile(file, minifiedDts, "utf8");
    }

    console.log("Minification of .js and .d.ts complete.");
  } catch (err) {
    console.error("Error during minification:", err);
    process.exit(1);
  }
}

runMinify();
