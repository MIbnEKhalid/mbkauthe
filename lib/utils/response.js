import { mbkautheVar, packageJson } from "../config/index.js";

// Helper function to render error pages consistently
export const renderError = (res, { code, error, message, page, pagename, details }) => {
    res.status(code);
    const renderData = {
        layout: false,
        code,
        error,
        message,
        page,
        pagename,
        app: mbkautheVar.APP_NAME,
        version: packageJson.version
    };

    // Add optional parameters if provided
    if (details !== undefined) renderData.details = details;

    return res.render("Error/dError.handlebars", renderData);
};
