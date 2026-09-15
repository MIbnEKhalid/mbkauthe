/**
 * MBKAuthe custom error class
 */

import { getErrorByCode } from "./catalog.js";

export class MbkAuthError extends Error {
  public readonly statusCode: number;
  public readonly errorCode: number;
  public readonly hint?: string;
  public readonly details?: unknown;

  constructor(errorCode: number, statusCode: number = 400, details?: unknown) {
    const errorInfo = getErrorByCode(errorCode);
    super(errorInfo.message);
    this.name = "MbkAuthError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.hint = errorInfo.hint;
    this.details = details;
    Object.setPrototypeOf(this, MbkAuthError.prototype);
  }
}
