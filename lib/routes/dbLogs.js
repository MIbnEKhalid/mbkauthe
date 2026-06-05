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
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }
  return Math.min(max, Math.floor(parsed));
};

const normalizeStringFilter = (value) => {
  if (typeof value !== "string") return "";
  return value.trim();
};

const parseSuccessFilter = (value) => {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  return null;
};

const getRawQueryLog = () => {
  if (typeof getQueryLog === "function") return getQueryLog();
  if (typeof dblogin.getQueryLog === "function") return dblogin.getQueryLog();
  return [];
};

const filterQueryLog = (queryLog, filters) => {
  const poolName = normalizeStringFilter(filters.pool);
  const username = normalizeStringFilter(filters.username).toLowerCase();
  const url = normalizeStringFilter(filters.url).toLowerCase();
  const success = parseSuccessFilter(filters.success);

  return queryLog.filter((entry) => {
    if (poolName && (entry?.pool?.name || "") !== poolName) {
      return false;
    }

    if (username) {
      const candidate = String(entry?.request?.username || entry?.request?.userId || "").toLowerCase();
      if (!candidate.includes(username)) {
        return false;
      }
    }

    if (url) {
      const candidateUrl = String(entry?.request?.url || "").toLowerCase();
      if (!candidateUrl.includes(url)) {
        return false;
      }
    }

    if (success !== null && Boolean(entry?.success) !== success) {
      return false;
    }

    return true;
  });
};

const sortQueryLogNewestFirst = (queryLog) =>
  [...queryLog].sort((a, b) => {
    const left = Date.parse(b?.time || "") || 0;
    const right = Date.parse(a?.time || "") || 0;
    return left - right;
  });

const average = (numbers) => {
  if (!numbers.length) return 0;
  return numbers.reduce((sum, value) => sum + value, 0) / numbers.length;
};

const buildSummary = (queryLog) => {
  const durations = queryLog
    .map((entry) => Number(entry?.durationMs))
    .filter((value) => Number.isFinite(value));
  const executionDurations = queryLog
    .map((entry) => Number(entry?.executionDurationMs))
    .filter((value) => Number.isFinite(value));
  const waitDurations = queryLog
    .map((entry) => Number(entry?.poolWait?.waitMs))
    .filter((value) => Number.isFinite(value));
  const errorCount = queryLog.filter((entry) => entry?.success === false).length;
  const pressuredQueries = queryLog.filter((entry) => entry?.poolWait?.hadPoolPressure).length;

  const slowestQueries = [...queryLog]
    .sort((a, b) => (Number(b?.durationMs) || 0) - (Number(a?.durationMs) || 0))
    .slice(0, 5)
    .map((entry) => ({
      time: entry.time,
      query: entry.query,
      name: entry.name,
      fingerprint: entry.fingerprint,
      durationMs: entry.durationMs,
      executionDurationMs: entry.executionDurationMs,
      waitMs: entry.poolWait?.waitMs || 0,
      success: entry.success,
      request: entry.request,
      pool: entry.pool,
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
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return b.totalDurationMs - a.totalDurationMs;
    })
    .slice(0, 8)
    .map((group) => ({
      fingerprint: group.fingerprint,
      normalizedQuery: group.normalizedQuery,
      sampleQuery: group.sampleQuery,
      sampleName: group.sampleName,
      poolName: group.poolName,
      requestUrl: group.requestUrl,
      count: group.count,
      avgDurationMs: group.totalDurationMs / group.count,
      avgExecutionDurationMs: group.totalExecutionDurationMs / group.count,
      avgWaitMs: group.totalWaitMs / group.count,
      errorCount: group.errorCount,
      lastSeen: group.lastSeen,
    }));

  return {
    totalVisible: queryLog.length,
    avgDurationMs: average(durations),
    avgExecutionDurationMs: average(executionDurations),
    avgWaitMs: average(waitDurations),
    errorCount,
    pressuredQueries,
    slowestQueries,
    repeatedGroups,
  };
};

const buildResponsePayload = (req) => {
  const queryCount = typeof getQueryCount === "function"
    ? getQueryCount()
    : typeof dblogin.getQueryCount === "function"
    ? dblogin.getQueryCount()
    : 0;
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
  const summary = buildSummary(queryLog);

  return {
    queryCount,
    queryLimit,
    filters: {
      pool: filters.pool,
      username: filters.username,
      url: filters.url,
      success: filters.success,
    },
    summary,
    queryLog,
  };
};

const LogLimit = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 50,
  message: { success: false, message: "Too many attempts, please try again later" },
  skip: (req) => {
    return !!req.session.user;
  },
  validate: {
    trustProxy: false,
    xForwardedForHeader: false,
  },
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
    const isDev = isDbLogsEnabled();
    if (!isDev) {
      return res.status(403).json({
        success: false,
        message: "DB logs are disabled.",
        isDev,
      });
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
