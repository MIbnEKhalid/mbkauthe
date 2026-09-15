import dotenv from "dotenv";
import createDebug from "debug";

dotenv.config();

const debugPattern = process.env.DEBUG || process.env.debug || "";
if (debugPattern) {
  createDebug.enable(debugPattern);
}

export const createLogger = (namespace: string = "") => createDebug(`mbkauthe${namespace ? `:${namespace}` : ""}`);
export const logDebug = createLogger();

