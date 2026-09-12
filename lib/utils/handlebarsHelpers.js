/**
 * MBKAuthe — Shared Handlebars Helpers
 */

import { hasPermission as mbkHasPermission } from "../permissions.js";

const isSuperAdminUser = (user, root) => {
  const role = user?.role || root?.role;
  return typeof role === "string" && role.trim().toLowerCase() === "superadmin";
};

const resolveUserContext = (context, options) => {
  const root = options?.data?.root || context;
  if (root?.sessionUser) return root.sessionUser;
  if (root?.user && typeof root.user === "object") return root.user;
  if (root?.role) return { role: root.role, roles: root.roles || [root.role], overrides: root.overrides || null };
  return null;
};

const checkPermHelper = (self, requiredPermission, options) => {
  const user = resolveUserContext(self, options);
  return isSuperAdminUser(user, options?.data?.root || self) || (Boolean(requiredPermission && user) && mbkHasPermission(user, requiredPermission));
};

export const commonHandlebarsHelpers = {
  // Permissions & Auth
  hasPerm: function (requiredPermission, options) { return checkPermHelper(this, requiredPermission, options); },
  hasPermission: function (requiredPermission, options) { return checkPermHelper(this, requiredPermission, options); },

  hasAnyPerm: function (...args) {
    const options = args.pop();
    const user = resolveUserContext(this, options);
    if (isSuperAdminUser(user, options?.data?.root || this)) return true;
    return Boolean(user) && args.some((perm) => typeof perm === "string" && mbkHasPermission(user, perm));
  },

  isSuperAdmin: function (options) {
    return isSuperAdminUser(resolveUserContext(this, options), options?.data?.root || this);
  },

  can: function (requiredPermission, options) {
    const allowed = checkPermHelper(this, requiredPermission, options);
    return options && typeof options.fn === "function" ? (allowed ? options.fn(this) : options.inverse(this)) : allowed;
  },

  // Comparisons & Logic
  eq: (a, b) => a === b || (a != null && b != null && String(a) === String(b)),
  neq: (a, b) => a !== b && (a == null || b == null || String(a) !== String(b)),
  or: (...args) => { args.pop(); return args.some(Boolean); },
  and: (...args) => { args.pop(); return args.every(Boolean); },
  not: (val) => !val,
  gt: (a, b) => Number(a) > Number(b),
  gte: (a, b) => Number(a) >= Number(b),
  lt: (a, b) => Number(a) < Number(b),
  lte: (a, b) => Number(a) <= Number(b),

  ifCond: function (v1, operator, v2, options) {
    if (!options || typeof options.fn !== "function") return "";
    const ops = {
      "==": v1 == v2, "===": v1 === v2, "!=": v1 != v2, "!==": v1 !== v2,
      "<": Number(v1) < Number(v2), "<=": Number(v1) <= Number(v2),
      ">": Number(v1) > Number(v2), ">=": Number(v1) >= Number(v2),
      "&&": Boolean(v1 && v2), "||": Boolean(v1 || v2),
    };
    const result = Boolean(ops[operator]);
    return result ? options.fn(this) : (options.inverse ? options.inverse(this) : "");
  },

  ifGt: function (a, b, options) {
    const [na, nb] = [Number(a), Number(b)];
    const isGreater = !isNaN(na) && !isNaN(nb) ? na > nb : a > b;
    return isGreater ? (options?.fn ? options.fn(this) : true) : (options?.inverse ? options.inverse(this) : false);
  },

  includes: (arr, val) => (Array.isArray(arr) ? arr.includes(val) : arr === val),
  in: (value, list) => Array.isArray(list) && list.includes(parseInt(value, 10) || value),
  startsWith: (str, prefix) => typeof str === "string" && str.startsWith(prefix),
  default: (value, defaultValue) => (value === undefined || value === null || value === "" || (typeof value === "number" && isNaN(value)) ? defaultValue : value),

  // Strings & Text
  trim: (str) => (str ? String(str).trim() : ""),
  truncate: (str, maxLen = 100) => {
    if (str == null) return "";
    const s = String(str);
    return s.length <= maxLen ? s : `${s.substring(0, maxLen)}...`;
  },
  truncateUrl: (str, maxLen = 45) => {
    if (!str || typeof str !== "string" || str.length <= maxLen) return str || "";
    return `${str.substring(0, Math.floor(maxLen * 0.6))}...${str.substring(str.length - Math.floor(maxLen * 0.3))}`;
  },
  slug: (str) => (str ? String(str).toLowerCase().replace(/\s+/g, "-") : ""),
  capitalize: (str) => (str ? String(str).charAt(0).toUpperCase() + String(str).slice(1) : ""),
  toLowerCase: (str) => (str ? String(str).toLowerCase() : ""),
  length: (val) => (val && typeof val.length === "number" ? val.length : 0),
  join: (arr, sep = ", ") => (Array.isArray(arr) ? arr.join(sep) : arr || ""),
  substr: (str, start, len) => (str == null ? "" : String(str).substr(start, len)),
  substring: (str, start, end) => (str == null ? "" : String(str).substring(start, end)),
  encodeURIComponent: (str) => encodeURIComponent(str || ""),

  // Numbers & Formatting
  formatNumber: (num) => {
    if (num == null || num === "") return "0";
    const n = Number(num);
    if (isNaN(n)) return "0";
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, "") + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
    return n.toLocaleString();
  },

  formatBytes: (bytes, decimals = 2) => {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  },

  formatDuration: (ms) => {
    const num = Number(ms);
    return isNaN(num) ? "Invalid duration" : `${num.toFixed(2)} ms`;
  },

  // Date & Time
  toISOString: (date) => (date ? (date instanceof Date ? date.toISOString() : new Date(date).toISOString()) : ""),
  formatDate: (dateString) => {
    if (!dateString) return "N/A";
    const d = new Date(dateString);
    return isNaN(d.getTime()) ? "N/A" : d.toLocaleString();
  },
  formatDateOnly: (dateString) => {
    if (!dateString) return "N/A";
    const d = new Date(dateString);
    return isNaN(d.getTime()) ? "N/A" : d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
  },
  formatTimestamp: (timestamp) => {
    if (!timestamp) return "";
    const d = new Date(timestamp);
    return isNaN(d.getTime()) ? "" : d.toLocaleString();
  },
  formatDateInput: (dateString) => {
    if (!dateString) return "";
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return "";
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  },
  formatDateTimeLocal: (dateString) => {
    if (!dateString) return "";
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  },

  timeAgo: (dateString) => {
    if (!dateString) return "";
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return "";
    const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 30) return "Just now";
    if (seconds < 60) return `${seconds}s ago`;

    const intervals = [
      ["year", 31536000], ["month", 2592000], ["week", 604800],
      ["day", 86400], ["hour", 3600], ["minute", 60]
    ];
    for (const [unit, secs] of intervals) {
      const interval = Math.floor(seconds / secs);
      if (interval >= 1) return interval === 1 ? `1 ${unit} ago` : `${interval} ${unit}s ago`;
    }
    return "Just now";
  },

  timeRemaining: (expire) => {
    if (!expire) return "";
    const expireDate = new Date(expire);
    if (isNaN(expireDate.getTime())) return "";
    const diffMs = expireDate - Date.now();
    if (diffMs <= 0) return "Expired";

    const diffDays = Math.floor(diffMs / 86400000);
    const diffHrs = Math.floor((diffMs % 86400000) / 3600000);
    const diffMins = Math.floor((diffMs % 3600000) / 60000);
    if (diffDays > 0) return `${diffDays}d ${diffHrs}h remaining`;
    if (diffHrs > 0) return `${diffHrs}h ${diffMins}m remaining`;
    return `${diffMins}m remaining`;
  },

  isExpired: (dateString) => {
    if (!dateString) return false;
    const date = new Date(dateString);
    return !isNaN(date.getTime()) && date.getTime() < Date.now();
  },

  isOverdue: (deadline, status) => {
    if (!deadline || status === "Completed" || status === "Cancelled") return false;
    const d = new Date(deadline);
    return !isNaN(d.getTime()) && d.getTime() < Date.now();
  },

  // JSON & Objects
  json: (obj) => JSON.stringify(obj, null, 2),
  jsonStringify: (context) => JSON.stringify(context),
  jsonParse: (str) => {
    if (!str) return {};
    try { return typeof str === "string" ? JSON.parse(str) : str; } catch { return {}; }
  },
  jsonIncludes: (jsonArray, value) => {
    if (!jsonArray) return false;
    try {
      const arr = Array.isArray(jsonArray) ? jsonArray : JSON.parse(jsonArray);
      return Array.isArray(arr) && arr.includes(value);
    } catch { return false; }
  },
  objectEntries: (obj) => (obj && typeof obj === "object" ? Object.entries(obj).map(([key, value]) => ({ key, value })) : []),
  array: (...args) => { args.pop(); return args; },
  index: (arr, idx) => (arr ? arr[idx] : null),

  // Math & Ranges
  add: (a, b) => Number(a) + Number(b),
  subtract: (a, b) => Number(a) - Number(b),
  multiply: (a, b) => Number(a) * Number(b),
  min: (a, b) => Math.min(Number(a), Number(b)),
  max: (a, b) => Math.max(Number(a), Number(b)),
  range: (start, end) => {
    const [s, e] = [Number(start), Number(end)];
    return isNaN(s) || isNaN(e) || e < s ? [] : Array.from({ length: e - s + 1 }, (_, i) => s + i);
  },
  validPageRange: (current, total, delta = 2) => {
    const [c, t, d] = [Number(current) || 1, Number(total) || 1, Number(delta) || 2];
    const start = Math.max(1, c - d);
    const end = Math.min(t, c + d);
    return Array.from({ length: end - start + 1 }, (_, i) => start + i);
  },
  for: function (from, to, block) {
    let accum = "";
    for (let i = from; i <= to; ++i) accum += block.fn(i);
    return accum;
  },

  // URL & Domain
  extractDomain: (urlString) => {
    try {
      if (!urlString) return "";
      return new URL(urlString.startsWith("http") ? urlString : `https://${urlString}`).hostname.replace(/^www\./, "");
    } catch { return urlString || ""; }
  },
  extractOriginalUrl: (shortUrlObj) => (typeof shortUrlObj === "object" && shortUrlObj?.original_url ? shortUrlObj.original_url : shortUrlObj),
  getCanonicalUrl: (req, path) => {
    if (!req) return path || "";
    return `${req.protocol || "https"}://${(typeof req.get === "function" ? req.get("host") : req.host) || "mbktech.org"}${path || ""}`;
  },
  conditionalEnv: (trueResult, falseResult) => (process.env.localenv ? trueResult : falseResult),

  // UI Badges & Metadata
  getInitials: (username) => {
    if (!username) return "?";
    const parts = String(username).split(/[._\s]/).filter(Boolean);
    return parts.length ? parts.map((p) => p.charAt(0)).join("").toUpperCase().slice(0, 2) : "?";
  },

  getRoleColor: (role) => ({ superadmin: "danger", admin: "warning", normaluser: "success", guest: "secondary" })[role?.toLowerCase()] || "secondary",

  getDeviceIcon: (ua) => {
    if (!ua) return "fas fa-question";
    if (/mobile/i.test(ua)) return "fas fa-mobile-alt";
    if (/tablet/i.test(ua)) return "fas fa-tablet-alt";
    return "fas fa-desktop";
  },

  getBrowser: (ua) => {
    if (!ua) return "Unknown";
    for (const name of ["Chrome", "Firefox", "Safari", "Edge", "Opera"]) {
      if (new RegExp(name, "i").test(ua)) return name;
    }
    return "Unknown Browser";
  },

  getOS: (ua) => {
    if (!ua) return "Unknown OS";
    if (/windows/i.test(ua)) return "Windows";
    if (/macintosh/i.test(ua)) return "MacOS";
    if (/linux/i.test(ua)) return "Linux";
    if (/android/i.test(ua)) return "Android";
    if (/iphone|ipad|ipod/i.test(ua)) return "iOS";
    return "Unknown OS";
  },

  actionTypeBadgeClass: (actionType) => {
    if (!actionType) return "action-default";
    const t = String(actionType).toLowerCase();
    if (t.includes("success") || t.includes("page view") || t === "page accessed" || t === "general success") return "action-success";
    if (t.includes("redirect")) return "action-redirect";
    if (t.includes("client error") || t.includes("not found") || t.includes("forbidden") || t.includes("unauthorized")) return "action-client";
    if (t.includes("server error") || t.includes("unavailable")) return "action-server";
    if (["login", "logout", "view", "create", "update", "delete"].includes(t)) return `action-${t}`;
    return "action-default";
  },

  section: function (name, options) {
    if (!this._sections) this._sections = {};
    if (options && typeof options.fn === "function") this._sections[name] = options.fn(this);
    return null;
  },
};

export const handlebarsHelpers = commonHandlebarsHelpers;
export default commonHandlebarsHelpers;
