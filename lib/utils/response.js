import { mbkautheVar, packageJson } from "../config/index.js";

// Helper function to render error pages consistently
export const renderError = (res, req, { code, error, message, page, pagename, details }) => {
    res.status(parseInt(code, 10));
    const renderData = {
        layout: false,
        code,
        error,
        message,
        page,
        pagename,
        app: mbkautheVar.APP_NAME,
        version: packageJson.version,

        userLoggedIn: !!req.session?.user || false,
        username: req.session?.user?.username || "N/A",
        fullname: req.session?.user?.fullname || "N/A",
        role: req.session?.user?.role || "N/A",
        allowedApps: req.session?.user?.allowedApps || [],
    };

    // Add optional parameters if provided
    if (details !== undefined) renderData.details = details;

    return res.render("Error/dError.handlebars", renderData);
};