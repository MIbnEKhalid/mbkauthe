import { createLogger as baseCreateLogger } from "mbkutils";
import type { Debugger } from "debug";

export const createLogger = (namespace: string = ""): Debugger => {
  return baseCreateLogger(namespace ? `authe:${namespace}` : "authe") as Debugger;
};

export const logDebug: Debugger = createLogger();