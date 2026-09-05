import express from "express";
import rateLimit from "express-rate-limit";
import { renderError } from "#response.js";
import { dblogin } from "#pool.js";
import { getQueryCount, getQueryLog, resetQueryCount, resetQueryLog } from "../utils/dbQueryLogger.js";
import { mbkautheVar } from "#config.js";

const router = express.Router();

const isDbLogsEnabled = () => process.env.env === "dev" && process.env.dbLogs === "true";

const clampLimit = (value, fallback = 50, max = 500) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 1 ? Math.min(max, Math.floor(parsed)) : fallback;
};

const normalizeStringFilter = (value) => (typeof value === "string" ? value.trim() : "");

const parseSuccessFilter = (value) => {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  return null;
};

const getRawQueryLog = () => (typeof getQueryLog === "function" ? getQueryLog() : (typeof dblogin.getQueryLog === "function" ? dblogin.getQueryLog() : []));

const filterQueryLog = (queryLog, filters) => {
  const poolName = normalizeStringFilter(filters.pool);
  const username = normalizeStringFilter(filters.username).toLowerCase();
  const url = normalizeStringFilter(filters.url).toLowerCase();
  const success = parseSuccessFilter(filters.success);

  return queryLog.filter((entry) => {
    if (poolName && (entry?.pool?.name || "") !== poolName) return false;
    if (username && !String(entry?.request?.username || entry?.request?.user_id || "").toLowerCase().includes(username)) return false;
    if (url && !String(entry?.request?.url || "").toLowerCase().includes(url)) return false;
    if (success !== null && Boolean(entry?.success) !== success) return false;
    return true;
  });
};

const sortQueryLogNewestFirst = (queryLog) =>
  [...queryLog].sort((a, b) => (Date.parse(b?.time || "") || 0) - (Date.parse(a?.time || "") || 0));

const average = (numbers) => (numbers.length ? numbers.reduce((sum, value) => sum + value, 0) / numbers.length : 0);

const buildSummary = (queryLog) => {
  const durations = queryLog.map((e) => Number(e?.durationMs)).filter(Number.isFinite);
  const executionDurations = queryLog.map((e) => Number(e?.executionDurationMs)).filter(Number.isFinite);
  const waitDurations = queryLog.map((e) => Number(e?.poolWait?.waitMs)).filter(Number.isFinite);

  const slowestQueries = [...queryLog]
    .sort((a, b) => (Number(b?.durationMs) || 0) - (Number(a?.durationMs) || 0))
    .slice(0, 5)
    .map((e) => ({
      time: e.time,
      query: e.query,
      name: e.name,
      fingerprint: e.fingerprint,
      durationMs: e.durationMs,
      executionDurationMs: e.executionDurationMs,
      waitMs: e.poolWait?.waitMs || 0,
      success: e.success,
      request: e.request,
      pool: e.pool,
    }));

  const repeatedGroupsMap = new Map();
  for (const entry of queryLog) {
    const key = entry?.fingerprint || entry?.normalizedQuery || entry?.query;
    if (!key) continue;

    const existing = repeatedGroupsMap.get(key);
    if (existing) {
      existing.count += 1;
      existing.totalDurationMs += Number(entry?.durationMs) || 0;
      existing.totalExecutionDurationMs += Number(entry?.executionDurationMs) || 0;
      existing.totalWaitMs += Number(entry?.poolWait?.waitMs) || 0;
      existing.errorCount += entry?.success === false ? 1 : 0;
      if ((Date.parse(entry?.time || "") || 0) > (Date.parse(existing.lastSeen || "") || 0)) {
        existing.lastSeen = entry.time;
      }
      continue;
    }

    repeatedGroupsMap.set(key, {
      fingerprint: entry.fingerprint,
      normalizedQuery: entry.normalizedQuery,
      sampleQuery: entry.query,
      sampleName: entry.name,
      poolName: entry?.pool?.name || null,
      requestUrl: entry?.request?.url || null,
      count: 1,
      totalDurationMs: Number(entry?.durationMs) || 0,
      totalExecutionDurationMs: Number(entry?.executionDurationMs) || 0,
      totalWaitMs: Number(entry?.poolWait?.waitMs) || 0,
      errorCount: entry?.success === false ? 1 : 0,
      lastSeen: entry.time,
    });
  }

  const repeatedGroups = [...repeatedGroupsMap.values()]
    .filter((group) => group.count > 1)
    .sort((a, b) => b.count - a.count || b.totalDurationMs - a.totalDurationMs)
    .slice(0, 8)
    .map((g) => ({
      fingerprint: g.fingerprint,
      normalizedQuery: g.normalizedQuery,
      sampleQuery: g.sampleQuery,
      sampleName: g.sampleName,
      poolName: g.poolName,
      requestUrl: g.requestUrl,
      count: g.count,
      avgDurationMs: g.totalDurationMs / g.count,
      avgExecutionDurationMs: g.totalExecutionDurationMs / g.count,
      avgWaitMs: g.totalWaitMs / g.count,
      errorCount: g.errorCount,
      lastSeen: g.lastSeen,
    }));

  return {
    totalVisible: queryLog.length,
    avgDurationMs: average(durations),
    avgExecutionDurationMs: average(executionDurations),
    avgWaitMs: average(waitDurations),
    errorCount: queryLog.filter((e) => e?.success === false).length,
    pressuredQueries: queryLog.filter((e) => e?.poolWait?.hadPoolPressure).length,
    slowestQueries,
    repeatedGroups,
  };
};

const buildResponsePayload = (req) => {
  const queryCount = typeof getQueryCount === "function" ? getQueryCount() : (typeof dblogin.getQueryCount === "function" ? dblogin.getQueryCount() : 0);
  const queryLimit = clampLimit(req.query.limit);
  const filters = {
    pool: normalizeStringFilter(req.query.pool),
    username: normalizeStringFilter(req.query.username),
    url: normalizeStringFilter(req.query.url),
    success: parseSuccessFilter(req.query.success),
  };
  const filtered = filterQueryLog(getRawQueryLog(), filters);
  const ordered = sortQueryLogNewestFirst(filtered);
  const queryLog = ordered.slice(0, queryLimit);

  return {
    queryCount,
    queryLimit,
    filters,
    summary: buildSummary(queryLog),
    queryLog,
  };
};

const LogLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => Boolean(req.session?.user),
  validate: { trustProxy: false, xForwardedForHeader: false },
});

router.get(["/db.json"], LogLimit, async (req, res) => {
  try {
    const isDev = isDbLogsEnabled();
    const queryLimit = clampLimit(req.query.limit);

    if (!isDev) {
      return res.status(403).json({
        success: false,
        message: "DB logs are disabled.",
        isDev,
        queryCount: 0,
        queryLimit,
        filters: {
          pool: normalizeStringFilter(req.query.pool),
          username: normalizeStringFilter(req.query.username),
          url: normalizeStringFilter(req.query.url),
          success: parseSuccessFilter(req.query.success),
        },
        summary: {
          totalVisible: 0,
          avgDurationMs: 0,
          avgExecutionDurationMs: 0,
          avgWaitMs: 0,
          errorCount: 0,
          pressuredQueries: 0,
          slowestQueries: [],
          repeatedGroups: [],
        },
        queryLog: [],
      });
    }

    return res.json({ ...buildResponsePayload(req), isDev });
  } catch (err) {
    console.error("[mbkauthe] /db.json route error:", err);
    return res.status(500).json({ success: false, message: "Could not fetch DB stats." });
  }
});

router.post(["/db/reset"], LogLimit, async (req, res) => {
  try {
    if (!isDbLogsEnabled()) {
      return res.status(403).json({ success: false, message: "DB logs are disabled.", isDev: false });
    }

    if (typeof resetQueryCount === "function") resetQueryCount();
    else if (typeof dblogin.resetQueryCount === "function") dblogin.resetQueryCount();

    if (typeof resetQueryLog === "function") resetQueryLog();
    else if (typeof dblogin.resetQueryLog === "function") dblogin.resetQueryLog();

    return res.json({ success: true, message: "Query log and count have been reset." });
  } catch (err) {
    console.error("[mbkauthe] /db/reset route error:", err);
    return res.status(500).json({ success: false, message: "Could not reset DB stats." });
  }
});

router.get(["/db"], LogLimit, async (req, res) => {
  try {
    const isDev = isDbLogsEnabled();
    const queryLimit = clampLimit(req.query.limit);
    const resetDone = req.query.resetDone === "1";
    const successFilter = parseSuccessFilter(req.query.success);

    return res.render("pages/dbLogs.handlebars", {
      layout: false,
      appName: mbkautheVar.APP_NAME,
      queryLimit,
      resetDone,
      isDev,
      filters: {
        pool: normalizeStringFilter(req.query.pool),
        username: normalizeStringFilter(req.query.username),
        url: normalizeStringFilter(req.query.url),
        successAny: successFilter === null,
        successTrue: successFilter === true,
        successFalse: successFilter === false,
      },
      disabledMessage: isDev ? null : "DB logs are disabled.",
    });
  } catch (err) {
    console.error("[mbkauthe] /db route error:", err);
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
