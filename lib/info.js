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
    //    latestVersion = await getLatestVersion();
    latestVersion = "Under Development"; // Placeholder for the latest version
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
const DOCUMENTATION_TITLE = "Project Documentation";
const CACHE_TTL = 3600000; // 1 hour in milliseconds

// Cache for the rendered HTML
let cachedHtml = null;
let cacheTimestamp = 0;

router.get(["/mbkauthe/"], async (_, res) => {
  try {
    // Check cache first
    const now = Date.now();
    if (cachedHtml && (now - cacheTimestamp) < CACHE_TTL) {
      return res.send(cachedHtml);
    }

    // Read and process file
    let readmePath;
    if (process.env.test === "true") {
      readmePath = path.join(process.cwd(), "README.md");
    }
    else {
      readmePath = path.join(process.cwd(), "./node_modules/mbkauthe/README.md");
    }
    const data = await fs.promises.readFile(readmePath, "utf8");

    // Convert markdown to HTML
    let html = marked(data, {
      breaks: true,
      gfm: true,
      smartypants: true
    });

    // Process HTML with cheerio
    const $ = cheerio.load(html);

    // Add IDs to headers for anchor links
    $('h1, h2, h3, h4, h5, h6').each(function () {
      const id = $(this).text()
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w-]+/g, '');
      $(this).attr('id', id);
      $(this).addClass('header-anchor');
    });

    // Fix table of contents links and add icons
    $('a[href^="#"]').each(function () {
      const href = $(this).attr('href');
      const id = href.substring(1)
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w-]+/g, '');
      $(this).attr('href', `#${id}`);
      $(this).addClass('toc-link');
    });

    // Add copy buttons to code blocks
    $('pre').each(function () {
      const $pre = $(this);
      const $button = $(`<button class="copy-button" aria-label="Copy code">📋</button>`);
      $pre.prepend($button);
    });

    // Create the full HTML response
    const htmlContent = generateFullHtml($.html());

    // Update cache
    cachedHtml = htmlContent;
    cacheTimestamp = now;

    res.send(htmlContent);
  } catch (err) {
    console.error("Error processing documentation:", err);
    res.status(500).send(generateErrorHtml());
  }
});

function generateFullHtml(contentHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Project documentation generated from README.md">
  <title>${DOCUMENTATION_TITLE}</title>
  <style>
    :root {
      --primary-color: #bb86fc;
      --primary-dark: #9a67ea;
      --secondary-color: #03dac6;
      --secondary-dark: #018786;
      --background-dark: #121212;
      --background-darker: #1e1e1e;
      --background-light: #2d2d2d;
      --text-primary: #e0e0e0;
      --text-secondary: #a0a0a0;
      --error-color: #cf6679;
      --success-color: #4caf50;
    }
    
    body {
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 0;
      background-color: var(--background-dark);
      color: var(--text-primary);
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .header-anchor {
      position: relative;
      padding-left: 1.5rem;
    }
    
    .header-anchor::before {
      content: "#";
      position: absolute;
      left: 0;
      color: var(--text-secondary);
      opacity: 0;
      transition: opacity 0.2s;
    }
    
    .header-anchor:hover::before {
      opacity: 1;
    }
    
    pre {
      position: relative;
      background: var(--background-darker);
      padding: 1.5rem;
      border-radius: 8px;
      overflow-x: auto;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }
    
    .copy-button {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      background: var(--background-light);
      color: var(--text-primary);
      border: none;
      border-radius: 4px;
      padding: 0.25rem 0.5rem;
      cursor: pointer;
      opacity: 0;
      transition: opacity 0.2s, background 0.2s;
    }
    
    pre:hover .copy-button {
      opacity: 1;
    }
    
    .copy-button:hover {
      background: var(--primary-color);
      color: var(--background-dark);
    }
    
    .copy-button.copied {
      background: var(--success-color);
      color: white;
    }
    
    code {
      font-family: 'Fira Code', 'Courier New', monospace;
      background: var(--background-darker);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      color: var(--secondary-color);
      font-size: 0.9em;
      word-wrap: break-word;
    }
    
    h1, h2, h3, h4, h5, h6 {
      color: var(--primary-color);
      margin-top: 1.8em;
      margin-bottom: 0.8em;
      scroll-margin-top: 1em;
    }
    
    h1 { 
      font-size: 2.4rem;
      border-bottom: 2px solid var(--primary-color);
      padding-bottom: 0.5rem;
    }
    
    h2 { font-size: 2rem; }
    h3 { font-size: 1.6rem; }
    
    a {
      color: var(--secondary-color);
      text-decoration: none;
      transition: color 0.2s;
    }
    
    a:hover {
      color: var(--primary-color);
      text-decoration: underline;
    }
    
    .toc-link {
      display: inline-block;
      padding: 0.2rem 0;
    }
    
    .toc-link::before {
      content: "→ ";
      opacity: 0;
      transition: opacity 0.2s;
    }
    
    .toc-link:hover::before {
      opacity: 1;
    }
    
    blockquote {
      border-left: 4px solid var(--primary-color);
      padding-left: 1.5rem;
      margin-left: 0;
      color: var(--text-secondary);
      font-style: italic;
      background: rgba(187, 134, 252, 0.05);
      border-radius: 0 4px 4px 0;
      padding: 1rem;
    }
    
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 1.5rem 0;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    th, td {
      border: 1px solid #444;
      padding: 0.75rem;
      text-align: left;
    }
    
    th {
      background-color: var(--background-darker);
      font-weight: 600;
    }
    
    tr:nth-child(even) {
      background-color: rgba(255, 255, 255, 0.05);
    }
    
    tr:hover {
      background-color: rgba(187, 134, 252, 0.1);
    }
    
    img {
      max-width: 100%;
      height: auto;
      border-radius: 8px;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    hr {
      border: none;
      height: 1px;
      background-color: #444;
      margin: 2rem 0;
    }
    
    /* Dark mode toggle */
    .theme-toggle {
      position: fixed;
      bottom: 1rem;
      right: 1rem;
      background: var(--background-light);
      border: none;
      border-radius: 50%;
      width: 3rem;
      height: 3rem;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
      z-index: 100;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
      body {
        padding: 1rem;
      }
      
      h1 {
        font-size: 2rem;
      }
      
      h2 {
        font-size: 1.7rem;
      }
      
      pre {
        padding: 1rem;
        font-size: 0.9em;
      }
    }
    
    /* Print styles */
    @media print {
      body {
        background-color: white;
        color: black;
        padding: 0;
      }
      
      a {
        color: #0066cc;
      }
      
      pre, code {
        background-color: #f5f5f5;
        color: #333;
      }
    }
  </style>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Fira+Code&display=swap" rel="stylesheet">
</head>
<body>
<a href="/mbkauthe/info/" class="toc-link">mbkauthe Info</a>
  <main>
    ${contentHtml}
  </main>
  
  <button class="theme-toggle" aria-label="Toggle theme">🌓</button>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // Smooth scrolling for TOC links
      document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
          e.preventDefault();
          const targetId = this.getAttribute('href');
          const targetElement = document.querySelector(targetId);
          
          if (targetElement) {
            targetElement.scrollIntoView({
              behavior: 'smooth',
              block: 'start'
            });
            
            // Update URL without page jump
            history.pushState(null, null, targetId);
          }
        });
      });
      
      // Copy button functionality
      document.querySelectorAll('.copy-button').forEach(button => {
        button.addEventListener('click', function() {
          const pre = this.parentElement;
          const code = pre.querySelector('code') || pre;
          const range = document.createRange();
          range.selectNode(code);
          window.getSelection().removeAllRanges();
          window.getSelection().addRange(range);
          
          try {
            const successful = document.execCommand('copy');
            if (successful) {
              this.textContent = '✓ Copied!';
              this.classList.add('copied');
              setTimeout(() => {
                this.textContent = '📋';
                this.classList.remove('copied');
              }, 2000);
            }
          } catch (err) {
            console.error('Failed to copy:', err);
          }
          
          window.getSelection().removeAllRanges();
        });
      });
      
      // Highlight current section in view
      const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.5
      };
      
      const observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          const id = entry.target.getAttribute('id');
          if (entry.isIntersecting) {
            document.querySelectorAll('a[href="#' + id + '"]').forEach(function(link) {
              link.style.fontWeight = '600';
              link.style.color = 'var(--primary-color)';
            });
          } else {
            document.querySelectorAll('a[href="#' + id + '"]').forEach(function(link) {
              link.style.fontWeight = '';
              link.style.color = '';
            });
          }
        });
      }, observerOptions);
      
      document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(function(heading) {
        if (heading.id) {
          observer.observe(heading);
        }
      });
      
      // Theme toggle functionality
      const themeToggle = document.querySelector('.theme-toggle');
      themeToggle.addEventListener('click', function() {
        document.body.classList.toggle('light-theme');
        const isLight = document.body.classList.contains('light-theme');
        this.textContent = isLight ? '🌙' : '🌓';
        localStorage.setItem('themePreference', isLight ? 'light' : 'dark');
      });
      
      // Load saved theme preference
      const savedTheme = localStorage.getItem('themePreference');
      if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        themeToggle.textContent = '🌙';
      }
    });
  </script>
</body>
</html>`;
}

function generateErrorHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error Loading Documentation</title>
</head>
<body>
  <h1>Error Loading Documentation</h1>
  <p>Failed to load README.md file. Please try again later.</p>
  <p>If the problem persists, contact your system administrator.</p>
  <a href="/">Return to Home</a>
  <div class="error-details">
    Error: ${err.message || 'Unknown error'}
  </div>
</body>
</html>`;
}

export default router;