import express from "express";
import fetch from 'node-fetch';

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const packageJson = require("../package.json");
import fs from "fs";
import path from "path";

import dotenv from "dotenv";
dotenv.config();
const mbkautheVar = JSON.parse(process.env.mbkautheVar);

const router = express.Router();

// Return package.json data of mbkauthe
router.get("/mbkauthe/package", async (_, res) => {
  try {
    const response = await fetch("https://mbkauthe.mbktechstudio.com/mbkauthe/package");
    const latestPackageData = await response.json();
    res.status(200).send(`
        <html>
          <head>
            <title>Package Information</title>
          </head>
          <body>
            <h1>Package Information</h1>
            <p><strong>Current Version:</strong> ${JSON.stringify(packageJson, null, 2)}</p>
            <p><strong>Latest Version:</strong> ${JSON.stringify(latestPackageData, null, 2)}</p>
          </body>
        </html>
      `);
  } catch (err) {
    res.status(200).send(`
        <html>
          <head>
            <title>Package Information</title>
          </head>
          <body>
            <h1>Package Information</h1>
            <p><strong>Current Version:</strong>  ${JSON.stringify(packageJson, null, 2)}</p>
            <p><strong>Latest Version:</strong> Failed to fetch latest package data, Erro:${err.message}</p>
          </body>
        </html>
      `);
  }
});

// Return version number of mbkauthe
router.get(["/mbkauthe/version", "/mbkauthe/v"], async (_, res) => {
  try {
    const response = await fetch("https://raw.githubusercontent.com/MIbnEKhalid/mbkauthe/refs/heads/main/package.json");
    const latestPackageData = await response.json();
    res.status(200).send(`
        <html>
          <head>
            <title>Version Information</title>
          </head>
          <body>
            <h1>Package Information</h1>
            <p><strong>Current Version:</strong> ${JSON.stringify(packageJson.version, null, 2)}</p>
            <p><strong>Latest Version:</strong> ${JSON.stringify(latestPackageData.version, null, 2)}</p>
          </body>
        </html>
      `);
  } catch (err) {
    res.status(200).send(`
        <html>
          <head>
            <title>Package Information</title>
          </head>
          <body>
            <h1>Package Information</h1>
            <p><strong>Current Version:</strong>  ${JSON.stringify(packageJson.version, null, 2)}</p>
            <p><strong>Latest Version:</strong> Failed to fetch latest package data, Erro:${err.message}</p>
          </body>
        </html>
      `);
  }
});

// Return package-lock.json data of mbkauthe from project the package is installed in
router.get("/mbkauthe/package-lock", (_, res) => {
  console.log("Request for package-lock.json received");
  const packageLockPath = path.resolve(process.cwd(), "package-lock.json");
  fs.readFile(packageLockPath, "utf8", (err, data) => {
    if (err) {
      console.error("Error reading package-lock.json:", err);
      return res.status(500).json({ success: false, message: "Failed to read package-lock.json" });
    }
    try {
      const packageLock = JSON.parse(data);
      const mbkautheData = {
        name: 'mbkauthe',
        version: packageLock.packages['node_modules/mbkauthe'].version,
        resolved: packageLock.packages['node_modules/mbkauthe'].resolved,
        integrity: packageLock.packages['node_modules/mbkauthe'].integrity,
        license: packageLock.packages['node_modules/mbkauthe'].license,
        dependencies: packageLock.packages['node_modules/mbkauthe'].dependencies
      };
      const rootDependency = packageLock.packages[''].dependencies.mbkauthe;
      console.log('mbkauthe package data:', mbkautheData);
      console.log('Root dependency version:', rootDependency);
      res.status(200).json({ mbkautheData, rootDependency });
    } catch (parseError) {
      console.error("Error parsing package-lock.json:", parseError);
      res.status(500).json({ success: false, message: "Failed to parse package-lock.json" });
    }
  });
});

// Return version number of mbkauthe
router.get(["/mbkauthe", "/mbkauthe/info", "/mbkauthe/i"], async (_, res) => {
  try {
    res.status(200).send(`
        <html>
        <head>
          <title>Version and Configuration Information</title>
          <style>
          body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
          }
          h1 {
            color: #333;
          }
          p {
            margin: 5px 0;
          }
          a {
            display: block;
            margin: 10px 0;
            color: #007BFF;
            text-decoration: none;
          }
          a:hover {
            text-decoration: underline;
          }
          .info-section {
            margin-bottom: 20px;
          }
          </style>
        </head>
        <body>
          <h1>Version and Configuration Information</h1>
          <div class="info-section">
          <h2>Current Version</h2>
          <p><strong>Version:</strong> ${JSON.stringify(packageJson.version, null, 2)}</p>
          </div>
          <div class="info-section">
          <h2>Configuration Information</h2>
          <p><strong>APP_NAME:</strong> ${mbkautheVar.APP_NAME}</p>
          <p><strong>RECAPTCHA_Enabled:</strong> ${mbkautheVar.RECAPTCHA_Enabled}</p>
          <p><strong>MBKAUTH_TWO_FA_ENABLE:</strong> ${mbkautheVar.MBKAUTH_TWO_FA_ENABLE}</p>
          <p><strong>COOKIE_EXPIRE_TIME:</strong> ${mbkautheVar.COOKIE_EXPIRE_TIME} Days</p>
          <p><strong>IS_DEPLOYED:</strong> ${mbkautheVar.IS_DEPLOYED}</p>
          <p><strong>DOMAIN:</strong> ${mbkautheVar.DOMAIN}</p>
          </div>
          <div class="info-section">
          <h2>Useful Links</h2>
          <a href="/mbkauthe/package">View mbkauthe package.json</a>
          <a href="/mbkauthe/package-lock">View mbkauthe version info from installed project package-lock.json</a>
          <a href="/mbkauthe/version">View Current and Latest Package Version</a>
          </div>
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

export default router;