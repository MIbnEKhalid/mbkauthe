import dotenv from "dotenv";
import createDebug from "debug";

dotenv.config();
createDebug.enable(process.env.DEBUG || "");

export const createLogger = (namespace = "") => createDebug(`mbkauthe${namespace ? `:${namespace}` : ""}`);
export const logDebug = createLogger();