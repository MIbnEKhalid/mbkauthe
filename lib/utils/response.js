import { mbkautheVar, packageJson } from "#config.js";

export function getUserContext(req) {
    const user = req?.session?.user || {};
    const isLoggedIn = Boolean(user.username);
    return {
        userLoggedIn: isLoggedIn,
        user_id: user.user_id || 'mbk_notfound',
        username: user.username || 'N/A',
        full_name: user.full_name || 'N/A',
        role: user.role || 'N/A',
        allowed_apps: Array.isArray(user.allowed_apps) ? user.allowed_apps : [],
    };
}

export function sanitizeErrorDetails(details) {
    if (!details) return null;
    let str = typeof details === 'string' ? details : (details.stack || details.message || (typeof details === 'object' ? JSON.stringify(details, null, 2) : String(details)));

    // Redact password & secret key-value pairs (JSON and query strings / config values)
    str = str.replace(/(["']?(?:password|passwd|pwd|secret|token|apiKey|api_key|clientSecret|client_secret|authHeader|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|main_secret_token|db_password|session_secret)["']?\s*[:=]\s*["']?)([^"',\s\r\n}]+)(["']?)/gi, '$1[REDACTED]$3');

    // Redact Authorization headers: Bearer, Basic
    str = str.replace(/(Bearer\s+)[A-Za-z0-9_\-\.]+/gi, '$1[REDACTED]');
    str = str.replace(/(Basic\s+)[A-Za-z0-9+/=]+/gi, '$1[REDACTED]');

    // Redact connection URIs with embedded passwords (e.g., postgres://user:pass@host)
    str = str.replace(/([a-zA-Z0-9+.-]+:\/\/[^:]+:)([^@\s]+)(@)/g, '$1[REDACTED]$3');

    // Redact session IDs and JWT tokens
    str = str.replace(/(sessionId|connect\.sid|session_id|jwt)=([^;\s&]+)/gi, '$1=[REDACTED]');

    // Redact PEM format Private Keys
    str = str.replace(/-----BEGIN[ A-Z_-]+KEY-----[\s\S]+?-----END[ A-Z_-]+KEY-----/g, '[REDACTED_PRIVATE_KEY]');

    return str;
}

export const renderError = (res, req, { code, error, message, page, pagename, details }) => {
    res.status(parseInt(code, 10));
    const sanitizedDetails = details !== undefined && details !== null ? sanitizeErrorDetails(details) : undefined;
    return res.render("Error/dError.handlebars", {
        layout: false,
        code,
        error,
        message,
        page,
        pagename,
        app: mbkautheVar.APP_NAME,
        version: packageJson.version,
        ...getUserContext(req),
        ...(sanitizedDetails !== undefined && { details: sanitizedDetails }),
    });
};

export async function renderPage(req, res, fileLocation, layout = true, data = {}) {
    return res.render(fileLocation, {
        ...data,
        ...getUserContext(req),
        ...(!layout && { layout: false }),
    });
}

export async function proxycall(req, res, url, method = 'GET', headerOption = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
        const sessionCookie = req.cookies?.session_id;
        const headers = { ...headerOption };
        if (sessionCookie && !headers.Cookie) headers.Cookie = `session_id=${sessionCookie}`;

        const isGetOrHead = ['GET', 'HEAD'].includes(method);
        const body = isGetOrHead ? undefined : (typeof req.body === 'string' || req.body instanceof Buffer ? req.body : JSON.stringify(req.body));
        if (body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';

        const response = await fetch(url, { method, headers, body, signal: controller.signal });
        response.headers.forEach((value, key) => res.setHeader(key, value));

        const isJson = response.headers.get('content-type')?.includes('application/json');
        const data = isJson ? await response.json() : await response.text();
        return res.status(response.status).send(data);
    } catch (err) {
        console.error('Proxy error:', err);
        return res.status(err.name === 'AbortError' ? 504 : 500).json({ error: 'Proxy request failed' });
    } finally {
        clearTimeout(timeout);
    }
}