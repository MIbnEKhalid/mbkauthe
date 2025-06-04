import express from "express";
import fetch from 'node-fetch';
import { createRequire } from "module";
import fs from "fs";
import path from "path";
import { marked } from "marked";
import * as cheerio from 'cheerio';

const require = createRequire(import.meta.url);
const packageJson = require("../package.json");

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

const router = express.Router();

router.get(["/mbkauthe/login"], (req, res) => {
  return res.render("loginmbkauthe", {
    layout: false,
    customURL: mbkautheVar.loginRedirectURL || '/home',
    userLoggedIn: !!req.session?.user,
    UserName: req.session?.user?.username || ''
  });
});

async function getLatestVersion() {
  try {
    const response = await fetch('https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/main/package.json');
    if (!response.ok) {
      throw new Error(`GitHub API responded with status ${response.status}`);
    }
    const latestPackageJson = await response.json();
    return latestPackageJson.version;
  } catch (error) {
    console.error('Error fetching latest version from GitHub:', error);
    return null;
  }
}

async function getPackageLock() {
  const packageLockPath = path.resolve(process.cwd(), "package-lock.json");

  return new Promise((resolve, reject) => {
    fs.readFile(packageLockPath, "utf8", (err, data) => {
      if (err) {
        console.error("Error reading package-lock.json:", err);
        return reject({ success: false, message: "Failed to read package-lock.json" });
      }
      try {
        const packageLock = JSON.parse(data);
        const mbkautheData = {
          name: 'mbkauthe',
          version: packageLock.packages['node_modules/mbkauthe']?.version || packageJson.version,
          resolved: packageLock.packages['node_modules/mbkauthe']?.resolved || '',
          integrity: packageLock.packages['node_modules/mbkauthe']?.integrity || '',
          license: packageLock.packages['node_modules/mbkauthe']?.license || packageJson.license,
          dependencies: packageLock.packages['node_modules/mbkauthe']?.dependencies || {}
        };
        const rootDependency = packageLock.dependencies?.mbkauthe || {};
        resolve({ mbkautheData, rootDependency });
      } catch (parseError) {
        console.error("Error parsing package-lock.json:", parseError);
        reject("Error parsing package-lock.json");
      }
    });
  });
}

function formatJson(json) {
  if (typeof json === 'string') {
    try {
      json = JSON.parse(json);
    } catch (e) {
      return json;
    }
  }

  // First stringify with proper indentation
  let jsonString = JSON.stringify(json, null, 2);

  // Escape HTML special characters EXCEPT for our span tags
  jsonString = jsonString
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Now apply syntax highlighting (after escaping)
  jsonString = jsonString
    // Highlight keys
    .replace(/"([^"]+)":/g, '"<span style="color: #2b6cb0;">$1</span>":')
    // Highlight string values
    .replace(/:\s*"([^"]+)"/g, ': "<span style="color: #38a169;">$1</span>"')
    // Highlight numbers
    .replace(/: (\d+)/g, ': <span style="color: #dd6b20;">$1</span>')
    // Highlight booleans and null
    .replace(/: (true|false|null)/g, ': <span style="color: #805ad5;">$1</span>');

  return jsonString;
}

router.get(["/mbkauthe/info", "/mbkauthe/i"], async (_, res) => {
  let pkgl = {};
  let latestVersion;

  try {
    pkgl = await getPackageLock();
    latestVersion = await getLatestVersion();
    //latestVersion = "Under Development"; // Placeholder for the latest version
  } catch (err) {
    console.error("Error fetching package-lock.json:", err);
    pkgl = { error: "Failed to fetch package-lock.json" };
  }

  try {
    res.status(200).send(`
    <html>
    <head>
      <title>Version and Configuration Information</title>
      <style>
        :root {
          --bg-color: #121212;
          --card-bg: #1e1e1e;
          --text-color: #e0e0e0;
          --text-secondary: #a0a0a0;
          --primary: #bb86fc;
          --primary-dark: #3700b3;
          --secondary: #03dac6;
          --border-color: #333;
          --success: #4caf50;
          --warning: #ff9800;
          --error: #f44336;
          --key-color: #bb86fc;
          --string-color: #03dac6;
          --number-color: #ff7043;
          --boolean-color: #7986cb;
        }

        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 20px;
          background-color: var(--bg-color);
          color: var(--text-color);
        }

        .container {
          max-width: 1000px;
          margin: 0 auto;
          padding: 20px;
          background: var(--card-bg);
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }

        h1 {
          color: var(--primary);
          text-align: center;
          margin-bottom: 30px;
          padding-bottom: 10px;
          border-bottom: 1px solid var(--border-color);
          font-weight: bold;
          letter-spacing: 1px;
        }

        .info-section {
          margin-bottom: 25px;
          padding: 20px;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background-color: rgba(30, 30, 30, 0.7);
          transition: all 0.3s ease;
        }

        .info-section:hover {
          border-color: var(--primary);
          box-shadow: 0 0 0 1px var(--primary);
        }

        .info-section h2 {
          color: var(--primary);
          border-bottom: 2px solid var(--primary-dark);
          padding-bottom: 8px;
          margin-top: 0;
          margin-bottom: 15px;
          font-size: 1.2em;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .info-row {
          display: flex;
          margin-bottom: 10px;
          padding-bottom: 10px;
          border-bottom: 1px solid var(--border-color);
        }

        .info-label {
          font-weight: 600;
          color: var(--text-secondary);
          min-width: 220px;
          font-size: 0.95em;
        }

        .info-value {
          flex: 1;
          word-break: break-word;
          color: var(--text-color);
        }

        .json-container {
          background: #252525;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          padding: 12px;
          margin-top: 10px;
          max-height: 400px;
          overflow: auto;
          font-family: 'Fira Code', 'Consolas', 'Monaco', monospace;
          font-size: 0.85em;
          white-space: pre-wrap;
          position: relative;
        }

        .json-container pre {
          margin: 0;
          font-family: inherit;
        }

        .json-container .key {
          color: var(--key-color);
        }

        .json-container .string {
          color: var(--string-color);
        }

        .json-container .number {
          color: var(--number-color);
        }

        .json-container .boolean {
          color: var(--boolean-color);
        }

        .json-container .null {
          color: var(--boolean-color);
          opacity: 0.7;
        }

        .version-status {
          display: inline-block;
          padding: 3px 10px;
          border-radius: 12px;
          font-size: 0.8em;
          font-weight: 600;
          margin-left: 10px;
        }

        .version-up-to-date {
          background: rgba(76, 175, 80, 0.2);
          color: var(--success);
          border: 1px solid var(--success);
        }

        .version-outdated {
          background: rgba(244, 67, 54, 0.2);
          color: var(--error);
          border: 1px solid var(--error);
        }

        .version-fetch-error {
          background: rgba(255, 152, 0, 0.2);
          color: var(--warning);
          border: 1px solid var(--warning);
        }

        .copy-btn {
          background: var(--primary-dark);
          color: white;
          border: none;
          padding: 5px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 0.8em;
          transition: all 0.2s ease;
          display: flex;
          align-items: center;
          gap: 5px;
        }

        .copy-btn:hover {
          background: var(--primary);
          transform: translateY(-1px);
        }

        .copy-btn:active {
          transform: translateY(0);
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
          width: 8px;
          height: 8px;
        }

        ::-webkit-scrollbar-track {
          background: #2d2d2d;
          border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb {
          background: #555;
          border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
          background: var(--primary);
        }

        /* Tooltip for copy button */
        .tooltip {
          position: relative;
          display: inline-block;
        }

        .tooltip .tooltiptext {
          visibility: hidden;
          width: 120px;
          background-color: #333;
          color: #fff;
          text-align: center;
          border-radius: 6px;
          padding: 5px;
          position: absolute;
          z-index: 1;
          bottom: 125%;
          left: 50%;
          margin-left: -60px;
          opacity: 0;
          transition: opacity 0.3s;
          font-size: 0.8em;
        }

        .tooltip:hover .tooltiptext {
          visibility: visible;
          opacity: 1;
        }
      </style>
      <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    </head>

    <body>
      <div class="container">
        <h1>Version and Configuration Dashboard</h1>

        <div class="info-section">
          <h2>Version Information</h2>
          <div class="info-row">
            <div class="info-label">Current Version:</div>
            <div class="info-value">${packageJson.version}</div>
          </div>
          <div class="info-row">
            <div class="info-label">Latest Version:</div>
            <div class="info-value">
              ${latestVersion || 'Could not fetch latest version'}
              ${latestVersion ? `
              <span class="version-status ${packageJson.version === latestVersion ? 'version-up-to-date' : 'version-outdated'}">
                ${packageJson.version === latestVersion ? 'Up to date' : 'Update available'}
              </span>
              ` : `
              <span class="version-status version-fetch-error">
                Fetch error
              </span>
              `}
            </div>
          </div>
        </div>

        <div class="info-section">
          <h2>Configuration Information</h2>
          <div class="info-row">
            <div class="info-label">APP_NAME:</div>
            <div class="info-value">${mbkautheVar.APP_NAME}</div>
          </div>
          <div class="info-row">
            <div class="info-label">RECAPTCHA_Enabled:</div>
            <div class="info-value">${mbkautheVar.RECAPTCHA_Enabled}</div>
          </div>
          <div class="info-row">
            <div class="info-label">MBKAUTH_TWO_FA_ENABLE:</div>
            <div class="info-value">${mbkautheVar.MBKAUTH_TWO_FA_ENABLE}</div>
          </div>
          <div class="info-row">
            <div class="info-label">COOKIE_EXPIRE_TIME:</div>
            <div class="info-value">${mbkautheVar.COOKIE_EXPIRE_TIME} Days</div>
          </div>
          <div class="info-row">
            <div class="info-label">IS_DEPLOYED:</div>
            <div class="info-value">${mbkautheVar.IS_DEPLOYED}</div>
          </div>
          <div class="info-row">
            <div class="info-label">DOMAIN:</div>
            <div class="info-value">${mbkautheVar.DOMAIN}</div>
          </div>
        </div>

        <div class="info-section">
          <h2>
            Package Information
            <button class="copy-btn tooltip" onclick="copyToClipboard('package-json')">
              <span class="tooltiptext">Copy to clipboard</span>
              Copy JSON
            </button>
          </h2>
          <div id="package-json" class="json-container"><pre>${JSON.stringify(packageJson, null, 2)}</pre></div>
        </div>

        <div class="info-section">
          <h2>
            Package Lock
            <button class="copy-btn tooltip" onclick="copyToClipboard('package-lock')">
              <span class="tooltiptext">Copy to clipboard</span>
              Copy JSON
            </button>
          </h2>
          <div id="package-lock" class="json-container"><pre>${JSON.stringify(pkgl, null, 2)}</pre></div>
        </div>
      </div>

      <script>
        document.addEventListener('DOMContentLoaded', function() {
          // Apply syntax highlighting to all JSON containers
          const jsonContainers = document.querySelectorAll('.json-container pre');
          jsonContainers.forEach(container => {
            container.innerHTML = syntaxHighlight(container.textContent);
          });
        });

        function syntaxHighlight(json) {
          if (typeof json !== 'string') {
            json = JSON.stringify(json, null, 2);
          }
          
          // Escape HTML
          json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
          
          // Apply syntax highlighting
          return json.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, 
            function(match) {
              let cls = 'number';
              if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                  cls = 'key';
                } else {
                  cls = 'string';
                }
              } else if (/true|false/.test(match)) {
                cls = 'boolean';
              } else if (/null/.test(match)) {
                cls = 'null';
              }
              return '<span class="' + cls + '">' + match + '</span>';
            }
          );
        }

        function copyToClipboard(elementId) {
          const element = document.getElementById(elementId);
          const text = element.textContent;
          navigator.clipboard.writeText(text).then(() => {
            const btn = element.parentElement.querySelector('.copy-btn');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="tooltiptext">Copied!</span>✓ Copied';
            setTimeout(() => {
              btn.innerHTML = '<span class="tooltiptext">Copy to clipboard</span>' + originalText.replace('✓ Copied', 'Copy JSON');
            }, 2000);
          }).catch(err => {
            console.error('Failed to copy text: ', err);
          });
        }
      </script>
    </body>
  </html>
        `);
  } catch (err) {
    console.error("Error fetching version information:", err);
    res.status(500).send(`
            <html>
                <head>
                    <title>Error</title>
                </head>
                <body>
                    <h1>Error</h1>
                    <p>Failed to fetch version information. Please try again later.</p>
                </body>
            </html>
        `);
  }
});

export { getLatestVersion };
export default router;