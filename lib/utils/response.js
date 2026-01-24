import { mbkautheVar, packageJson } from "#config.js";

export function getUserContext(req) {
    const user = req?.session?.user || {};
    return {
        userLoggedIn: !!user.username,
        isuserlogin: !!user.username,
        username: user.username || 'N/A',
        fullname: user.fullname || 'N/A',
        role: user.role || 'N/A',
        allowedApps: Array.isArray(user.allowedApps) ? user.allowedApps : [],
    };
}

// Helper function to render error pages consistently
export const renderError = (res, req, { code, error, message, page, pagename, details }) => {
    res.status(parseInt(code, 10));
    const ctx = getUserContext(req);
    const renderData = {
        layout: false,
        code,
        error,
        message,
        page,
        pagename,
        app: mbkautheVar.APP_NAME,
        version: packageJson.version,
        ...ctx,
    };

    // Add optional parameters if provided
    if (details !== undefined) renderData.details = details;

    return res.render("Error/dError.handlebars", renderData);
};

export async function renderPage(req, res, fileLocation, layout = true, data = {}) {
    const ctx = getUserContext(req);
    const renderOptions = {
        ...data,
        ...ctx,
        ...(layout === false ? { layout: false } : {}),
    };
    return res.render(fileLocation, renderOptions);
}

export async function proxycall(req, res, url, method = 'GET', headerOption = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    try {
        const sessionCookie = req.cookies?.sessionId;

        const headers = { ...headerOption };

        if (sessionCookie && !headers.Cookie) {
            headers.Cookie = `sessionId=${sessionCookie}`;
        }

        const body = ['GET', 'HEAD'].includes(method) ? undefined : typeof req.body === 'string' || req.body instanceof Buffer ? req.body : JSON.stringify(req.body);

        if (body && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        const response = await fetch(url, { method, headers, body, signal: controller.signal });

        response.headers.forEach((value, key) => {
            res.setHeader(key, value);
        });

        const contentType = response.headers.get('content-type');
        const data = contentType?.includes('application/json') ? await response.json() : await response.text();

        return res.status(response.status).send(data);

    } catch (err) {
        console.error('Proxy error:', err);
        return res.status(err.name === 'AbortError' ? 504 : 500).json({ error: 'Proxy request failed' });
    } finally {
        clearTimeout(timeout);
    }
}