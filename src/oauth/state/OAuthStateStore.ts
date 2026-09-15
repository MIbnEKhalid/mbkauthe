/**
 * OAuth State & PKCE Store for MBKAuthe
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

import crypto from "node:crypto";
import type { OAuthStateData } from "../types.js";
import type { OAuthStateStore } from "../ports.js";

export interface StateStoreOptions {
  defaultTtlSeconds?: number;
  maxEntries?: number;
}

export class MemoryOAuthStateStore implements OAuthStateStore {
  private store = new Map<string, OAuthStateData>();
  private defaultTtlSeconds: number;
  private maxEntries: number;

  constructor(options: StateStoreOptions = {}) {
    this.defaultTtlSeconds = options.defaultTtlSeconds || 600; // 10 minutes default
    this.maxEntries = options.maxEntries || 10000;
  }

  /**
   * Generates a high-entropy random state string and associates state data with it.
   */
  async generateState(
    data: Omit<OAuthStateData, "state" | "createdAt" | "expiresAt">,
    ttlSeconds?: number
  ): Promise<string> {
    this.cleanupExpired();

    if (this.store.size >= this.maxEntries) {
      // Evict the oldest entry
      const oldestKey = this.store.keys().next().value;
      if (oldestKey) this.store.delete(oldestKey);
    }

    const state = crypto.randomBytes(32).toString("base64url");
    const now = Date.now();
    const ttl = (ttlSeconds ?? this.defaultTtlSeconds) * 1000;

    const stateData: OAuthStateData = {
      ...data,
      state,
      createdAt: now,
      expiresAt: now + ttl,
    };

    this.store.set(state, stateData);
    return state;
  }

  /**
   * Retrieves and permanently consumes (deletes) the state data (one-time use).
   * Returns null if state is missing, invalid, or expired.
   */
  async verifyAndConsumeState(state?: string | null): Promise<OAuthStateData | null> {
    if (!state || typeof state !== "string") return null;

    const stateData = this.store.get(state);
    if (!stateData) return null;

    // Immediately consume to prevent replay attacks
    this.store.delete(state);

    if (Date.now() > stateData.expiresAt) {
      return null; // Expired
    }

    return stateData;
  }

  /**
   * Generates RFC 7636 PKCE code_verifier and S256 code_challenge.
   */
  generatePkce(): { codeVerifier: string; codeChallenge: string; codeChallengeMethod: "S256" } {
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: "S256",
    };
  }

  /**
   * Generates a cryptographic nonce for OpenID Connect.
   */
  generateNonce(): string {
    return crypto.randomBytes(24).toString("base64url");
  }

  /**
   * Cleans up expired state entries.
   */
  private cleanupExpired(): void {
    const now = Date.now();
    for (const [key, value] of this.store.entries()) {
      if (now > value.expiresAt) {
        this.store.delete(key);
      }
    }
  }

  /**
   * Helper for tests to inspect store size.
   */
  get size(): number {
    return this.store.size;
  }

  /**
   * Clears the store.
   */
  clear(): void {
    this.store.clear();
  }
}

export const defaultOAuthStateStore = new MemoryOAuthStateStore();
