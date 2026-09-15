import type { Request, Response } from "express";
import {
  ACCOUNT_LIST_COOKIE,
  MAX_REMEMBERED_ACCOUNTS,
  parseSignedCookiePayload,
  createSignedCookiePayload,
  generateFingerprintFromUserAgent,
  encryptSessionId,
  decryptSessionId,
  cachedCookieOptions,
  cachedClearCookieOptions,
} from "../../config/cookies.js";

export const generateFingerprint = (req: Request) =>
  generateFingerprintFromUserAgent(String(req.headers?.["user-agent"] || ""));

const parseAccountList = (raw: string | undefined, req: Request) => {
  if (!raw) return [];
  try {
    const data = parseSignedCookiePayload(JSON.parse(raw));
    if (!data?.accounts || !data?.fingerprint || data.fingerprint !== generateFingerprint(req)) {
      if (data?.fingerprint) console.warn("[mbkauthe] Cookie fingerprint mismatch - possible cookie theft attempt");
      return [];
    }
    if (!Array.isArray(data.accounts)) return [];
    return data.accounts
      .filter((item: any) => item && typeof item === "object")
      .map(({ session_id, username, full_name, image }: any) => ({
        session_id: typeof session_id === "string" ? decryptSessionId(session_id) : null,
        username: typeof username === "string" ? username : null,
        full_name: typeof full_name === "string" ? full_name : null,
        image: typeof image === "string" ? image : null,
      }))
      .filter((item: any) => item.session_id && item.username)
      .slice(0, MAX_REMEMBERED_ACCOUNTS);
  } catch (error) {
    console.error("[mbkauthe] Error parsing account list:", error);
    return [];
  }
};

const writeAccountList = (res: Response, list: any[], req: Request) => {
  const cleaned = (Array.isArray(list) ? list.slice(0, MAX_REMEMBERED_ACCOUNTS) : [])
    .map((item: any) => ({
      session_id: item?.session_id ? encryptSessionId(item.session_id) : null,
      username: item?.username || null,
      full_name: item?.full_name || null,
      image: typeof item?.image === "string" && item.image.length <= 2048 ? item.image : null,
    }))
    .filter((i: any) => i.session_id && i.username);

  const signed = createSignedCookiePayload({ accounts: cleaned, fingerprint: generateFingerprint(req) });
  if (signed) {
    res.cookie(ACCOUNT_LIST_COOKIE, JSON.stringify(signed), cachedCookieOptions as any);
  } else {
    console.error("[mbkauthe] Failed to sign account list cookie");
  }
};

export const readAccountListFromCookie = (req: Request) => parseAccountList(req?.cookies?.[ACCOUNT_LIST_COOKIE], req);

export const upsertAccountListCookie = (req: Request, res: Response, entry: any) => {
  if (!entry?.session_id || !entry?.username) return;
  const current = readAccountListFromCookie(req).filter(
    (item: any) => item.session_id !== entry.session_id && item.username !== entry.username
  );
  writeAccountList(res, [{ session_id: entry.session_id, username: entry.username, full_name: entry.full_name || entry.username, image: entry.image || null }, ...current], req);
};

export const removeAccountFromCookie = (req: Request, res: Response, session_id: string) => {
  writeAccountList(res, readAccountListFromCookie(req).filter((item: any) => item.session_id !== session_id), req);
};

export const clearAccountListCookie = (res: Response) => {
  res.clearCookie(ACCOUNT_LIST_COOKIE, cachedClearCookieOptions as any);
};

export const clearSessionCookies = (res: Response): void => {
  ["mbkauthe.sid", "session_id", "full_name", "profile_image_url", "profile_image_user", "device_token", "last_login_method"]
    .forEach((cookie) => res.clearCookie(cookie, cachedClearCookieOptions as any));
};
