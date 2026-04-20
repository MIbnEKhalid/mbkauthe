import express from "express";
import { renderError } from "#response.js";
import { dblogin } from "#pool.js";
import { getQueryCount, getQueryLog, resetQueryCount, resetQueryLog } from "../utils/dbQueryLogger.js";
import { mbkautheVar } from "#config.js";
import rateLimit from 'express-rate-limit';

const router = express.Router();

const isDbLogsEnabled = () => process.env.env === "dev" && process.env.dbLogs === "true";

// Rate limiter for info/test routes
const LogLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 50,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => {
    return !!req.session.user;
  },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false
  }
});

// DB stats API (JSON)
router.get(["/db.json"], LogLimit, async (req, res) => {
  try {
    const isDev = isDbLogsEnabled();
    const queryLimit = Number(req.query.limit) || 50;

    if (!isDev) {
      return res.status(403).json({
        success: false,
        message: "DB logs are disabled.",
        isDev,
        queryCount: 0,
        queryLimit,
        queryLog: []
      });
    }

    const queryCount = typeof getQueryCount === 'function' ? getQueryCount() : (typeof dblogin.getQueryCount === 'function' ? dblogin.getQueryCount() : 0);
    const queryLog = typeof getQueryLog === 'function' ? getQueryLog({ limit: queryLimit }) : (typeof dblogin.getQueryLog === 'function' ? dblogin.getQueryLog({ limit: queryLimit }) : []);

    return res.json({ queryCount, queryLimit, queryLog, isDev });
  } catch (err) {
    console.error('[mbkauthe] /db.json route error:', err);
    return res.status(500).json({ success: false, message: 'Could not fetch DB stats.' });
  }
});

// Dedicated reset API for DB logs and counters
router.post(["/db/reset"], LogLimit, async (req, res) => {
  try {
    const isDev = isDbLogsEnabled();
    if (!isDev) {
      return res.status(403).json({
        success: false,
        message: "DB logs are disabled.",
        isDev
      });
    }

    if (typeof resetQueryCount === 'function') resetQueryCount();
    else if (typeof dblogin.resetQueryCount === 'function') dblogin.resetQueryCount();

    if (typeof resetQueryLog === 'function') resetQueryLog();
    else if (typeof dblogin.resetQueryLog === 'function') dblogin.resetQueryLog();

    return res.json({ success: true, message: 'Query log and count have been reset.' });
  } catch (err) {
    console.error('[mbkauthe] /db/reset route error:', err);
    return res.status(500).json({ success: false, message: 'Could not reset DB stats.' });
  }
});

// DB stats page (HTML)
router.get(["/db"], LogLimit, async (req, res) => {
  try {
    const isDev = isDbLogsEnabled();
    const queryLimit = Number(req.query.limit) || 50;
    const resetDone = req.query.resetDone === '1';
    return res.render('pages/dbLogs.handlebars', {
      layout: false,
      appName: mbkautheVar.APP_NAME,
      queryLimit,
      resetDone,
      isDev,
      disabledMessage: isDev ? null : 'DB logs are disabled.'
    });
  } catch (err) {
    console.error('[mbkauthe] /db route error:', err);
    return renderError(res, req, {
      layout: false,
      code: 500,
      error: "Internal Server Error",
      message: "Could not fetch DB stats.",
      pagename: "DB Stats",
      page: "/mbkauthe/info",
    });
  }
});

export default router;