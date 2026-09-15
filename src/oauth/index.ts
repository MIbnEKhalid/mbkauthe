/**
 * MBKAuthe Provider-Neutral OAuth & OIDC Core Module
 * Framework-agnostic authentication engine.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

// Types & Ports
export * from "./types.js";
export * from "./ports.js";

// HTTP Client
export { OAuthHttpClient, OAuthHttpError, defaultOAuthHttpClient, type OAuthHttpRequestOptions } from "./http/OAuthHttpClient.js";

// State Store & PKCE
export { MemoryOAuthStateStore, defaultOAuthStateStore, type StateStoreOptions } from "./state/OAuthStateStore.js";

// Providers & Presets
export * from "./providers/index.js";

// Token Encryption
export { AesGcmTokenEncryptor, defaultTokenEncryptor } from "./crypto/tokenEncryption.js";

// Flow Service
export { OAuthFlowService, oAuthFlowService, type OAuthFlowServiceOptions } from "./OAuthFlowService.js";
