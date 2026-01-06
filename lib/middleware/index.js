import session from "express-session";
import pgSession from "connect-pg-simple";
const PgSession = pgSession(session);
import { dblogin } from "../database/pool.js";
import { mbkautheVar } from "../config/index.js";
import { cachedCookieOptions, decryptSessionId, encryptSessionId } from "../config/cookies.js";

// Session configuration
export const sessionConfig = {
  store: new PgSession({
    pool: dblogin,
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: mbkautheVar.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    maxAge: mbkautheVar.COOKIE_EXPIRE_TIME * 24 * 60 * 60 * 1000,
    // Don't set domain in development/localhost to avoid cookie issues
    domain: (mbkautheVar.IS_DEPLOYED === 'true' && process.env.test !== 'dev') ? `.${mbkautheVar.DOMAIN}` : undefined,
    httpOnly: true,
    // Only use secure cookies in production with HTTPS
    secure: mbkautheVar.IS_DEPLOYED === 'true' && process.env.test !== 'dev',
    sameSite: 'lax',
    path: '/'
  },
  name: 'mbkauthe.sid'
};

// CORS middleware
export function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originUrl = new URL(origin);
      const allowedDomain = `.${mbkautheVar.DOMAIN}`;
      // Exact match or subdomain match
      if (originUrl.hostname === mbkautheVar.DOMAIN ||
        (originUrl.hostname.endsWith(allowedDomain) && originUrl.hostname.charAt(originUrl.hostname.length - allowedDomain.length - 1) !== '.')) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
    } catch (err) {
      // Invalid origin URL, skip CORS headers
    }
  }
  next();
}

// Session restoration middleware
export async function sessionRestorationMiddleware(req, res, next) {
  // Only restore session if not already present and sessionId cookie exists
  if (!req.session.user && req.cookies.sessionId) {
    // Decrypt the sessionId from cookie
    const sessionId = decryptSessionId(req.cookies.sessionId);

    // Early validation to avoid unnecessary processing (expect DB UUID id)
    if (!sessionId || typeof sessionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
      // Clear invalid cookie to prevent repeated attempts
      res.clearCookie('sessionId', {
        domain: mbkautheVar.IS_DEPLOYED === 'true' ? `.${mbkautheVar.DOMAIN}` : undefined,
        path: '/',
        httpOnly: true,
        secure: mbkautheVar.IS_DEPLOYED === 'true',
        sameSite: 'lax'
      });
      return next();
    }

    try {
      // Validate session by DB primary key id and join to user
      const query = `SELECT u.id, u."UserName", u."Active", u."Role", u."AllowedApps", s.expires_at
                     FROM "Sessions" s
                     JOIN "Users" u ON s."UserName" = u."UserName"
                     WHERE s.id = $1 LIMIT 1`;
      const result = await dblogin.query({ name: 'restore-user-session', text: query, values: [sessionId] });

      if (result.rows.length > 0) {
        const row = result.rows[0];

        // Reject expired sessions or inactive users
        if ((row.expires_at && new Date(row.expires_at) <= new Date()) || !row.Active) {
          // leave cookies cleared and don't restore session
        } else {
          const normalizedSessionId = String(sessionId);
          req.session.user = {
            id: row.id,
            username: row.UserName,
            role: row.Role,
            sessionId: normalizedSessionId,
            allowedApps: row.AllowedApps,
          };

          // Use cached FullName from client cookie when available to avoid extra DB queries
          if (req.cookies.fullName && typeof req.cookies.fullName === 'string') {
            req.session.user.fullname = req.cookies.fullName;
          } else {
            // Fallback: attempt to fetch FullName from Users to populate session
            try {
              const profileRes = await dblogin.query({
                name: 'restore-get-fullname',
                text: 'SELECT "FullName" FROM "Users" WHERE "UserName" = $1 LIMIT 1',
                values: [row.UserName]
              });
              if (profileRes.rows.length > 0 && profileRes.rows[0].FullName) {
                req.session.user.fullname = profileRes.rows[0].FullName;
              }
            } catch (profileErr) {
              console.error("[mbkauthe] Error fetching FullName during session restore:", profileErr);
            }
          }
        }
      }
    } catch (err) {
      console.error("[mbkauthe] Session restoration error:", err);
    }
  }
  next();
}

// Session cookie sync middleware
export function sessionCookieSyncMiddleware(req, res, next) {
  if (req.session && req.session.user) {
    // Decrypt existing cookie to compare with session
    const currentDecryptedId = decryptSessionId(req.cookies.sessionId);

    // Only set cookies if they're missing or different
    if (currentDecryptedId !== req.session.user.sessionId) {
      res.cookie("username", req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      res.cookie("fullName", req.session.user.fullname || req.session.user.username, { ...cachedCookieOptions, httpOnly: false });
      
      const encryptedSessionId = encryptSessionId(req.session.user.sessionId);
      if (encryptedSessionId) {
        res.cookie("sessionId", encryptedSessionId, cachedCookieOptions);
      }
    }
  }
  next();
}