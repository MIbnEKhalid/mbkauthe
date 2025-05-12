import { pool } from "./pool.js";

export const authapi = () => {
    return (req, res, next) => {
        const token = req.headers["authorization"];

        // Query to check if the token exists in UserAuthApiKey table
        const tokenQuery = 'SELECT * FROM "UserAuthApiKey" WHERE "key" = $1';
        pool.query(tokenQuery, [token], (err, result) => {
            if (err) {
                console.error("Database query error:", err);
                return res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }

            if (result.rows.length === 0) {
                console.log("Invalid token");
                return res
                    .status(401)
                    .json({ success: false, message: "The AuthApiToken Is InValid" });
            }

            const username = result.rows[0].username;

            // Query to check if the user exists and is active in Users table
            const userQuery =
                'SELECT * FROM "Users" WHERE "UserName" = $1 AND "Active" = true';
            pool.query(userQuery, [username], (err, userResult) => {
                if (username === "demo") {
                    console.log("Demo user is not allowed to access this endpoint");
                    return res.status(401).json({
                        success: false,
                        message: "Demo user is not allowed to access endpoints",
                    });
                }
                if (err) {
                    console.error("Database query error:", err);
                    return res
                        .status(500)
                        .json({ success: false, message: "Internal Server Error" });
                }

                if (userResult.rows.length === 0) {
                    console.log("User does not exist or is not active");
                    return res.status(401).json({
                        success: false,
                        message: "User does not exist or is not active",
                    });
                }

                console.log("Token and user are valid");
                next();
            });
        });
    };
};