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