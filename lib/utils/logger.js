import dotenv from "dotenv";
import createDebug from "debug";

dotenv.config();
createDebug.enable(process.env.DEBUG || "");

export const createLogger = (namespace = "") => {
  const suffix = namespace ? `:${namespace}` : "";
  return createDebug(`mbkauthe${suffix}`);
};

export const logDebug = createLogger();