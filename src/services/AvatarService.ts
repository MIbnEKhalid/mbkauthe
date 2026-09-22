import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { authRepository } from "../db/repositories/AuthRepository.js";
import { isSafeFetchUrl } from "../http/utils/urlSafety.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface AvatarMetadata {
  imageUrl: string | null;
  etag: string;
  expiresAt: number;
}

export interface AvatarImageResult {
  buffer: Buffer;
  contentType: string;
  etag: string;
}

interface CachedImageBuffer {
  buffer: Buffer;
  contentType: string;
  etag: string;
  expiresAt: number;
}

const METADATA_TTL_MS = 5 * 60 * 1000; // 5 minutes
const IMAGE_BUFFER_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_BUFFER_CACHE_ITEMS = 100;

export class AvatarService {
  private metadataCache = new Map<string, AvatarMetadata>();
  private imageBufferCache = new Map<string, CachedImageBuffer>();
  private defaultAvatarBuffer: Buffer | null = null;

  private getDefaultBuffer(): Buffer {
    if (!this.defaultAvatarBuffer) {
      const p = path.join(__dirname, "..", "..", "public", "M.png");
      try {
        this.defaultAvatarBuffer = fs.readFileSync(p);
      } catch {
        // Fallback transparent 1x1 png if file missing
        this.defaultAvatarBuffer = Buffer.from(
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
          "base64"
        );
      }
    }
    return this.defaultAvatarBuffer;
  }

  private computeETag(username: string, imageUrl: string | null): string {
    const raw = `${username}:${imageUrl || "default"}`;
    const hash = crypto.createHash("md5").update(raw).digest("hex");
    return `W/"avatar-${hash}"`;
  }

  public warmCache(username: string, imageUrl: string | null): AvatarMetadata {
    const norm = username.trim().toLowerCase();
    const cleanUrl = imageUrl && imageUrl.trim() && imageUrl.trim() !== "default" ? imageUrl.trim() : null;
    const etag = this.computeETag(norm, cleanUrl);
    const meta: AvatarMetadata = {
      imageUrl: cleanUrl,
      etag,
      expiresAt: Date.now() + METADATA_TTL_MS,
    };
    this.metadataCache.set(norm, meta);
    return meta;
  }

  public async getAvatarMetadata(username: string): Promise<AvatarMetadata> {
    const norm = username.trim().toLowerCase();
    const cached = this.metadataCache.get(norm);
    if (cached && cached.expiresAt > Date.now()) {
      return cached;
    }

    let imageUrl: string | null = null;
    try {
      const row = await authRepository.getUserImageByUsername(norm, "get-user-avatar");
      if (row?.image && typeof row.image === "string" && row.image.trim() && row.image.trim() !== "default") {
        imageUrl = row.image.trim();
      }
    } catch (err) {
      console.warn(`[AvatarService] Failed to query user image for ${norm}:`, err);
    }

    return this.warmCache(norm, imageUrl);
  }

  public async getAvatarImage(username: string, metadata?: AvatarMetadata): Promise<AvatarImageResult> {
    const meta = metadata || (await this.getAvatarMetadata(username));
    const imageUrl = meta.imageUrl;

    if (!imageUrl || !isSafeFetchUrl(imageUrl)) {
      return {
        buffer: this.getDefaultBuffer(),
        contentType: "image/png",
        etag: meta.etag,
      };
    }

    const cachedBuf = this.imageBufferCache.get(imageUrl);
    if (cachedBuf && cachedBuf.expiresAt > Date.now()) {
      return {
        buffer: cachedBuf.buffer,
        contentType: cachedBuf.contentType,
        etag: meta.etag,
      };
    }

    try {
      const response = await fetch(imageUrl, {
        headers: { "User-Agent": "mbkauthe/1.0" },
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return {
          buffer: this.getDefaultBuffer(),
          contentType: "image/png",
          etag: meta.etag,
        };
      }

      const contentType = response.headers.get("content-type") || "image/jpeg";
      const buffer = Buffer.from(await response.arrayBuffer());

      if (this.imageBufferCache.size >= MAX_BUFFER_CACHE_ITEMS) {
        const oldestKey = this.imageBufferCache.keys().next().value;
        if (oldestKey) this.imageBufferCache.delete(oldestKey);
      }

      this.imageBufferCache.set(imageUrl, {
        buffer,
        contentType,
        etag: meta.etag,
        expiresAt: Date.now() + IMAGE_BUFFER_TTL_MS,
      });

      return {
        buffer,
        contentType,
        etag: meta.etag,
      };
    } catch {
      return {
        buffer: this.getDefaultBuffer(),
        contentType: "image/png",
        etag: meta.etag,
      };
    }
  }

  public invalidateAvatarCache(username: string): void {
    if (!username) return;
    const norm = username.trim().toLowerCase();
    const meta = this.metadataCache.get(norm);
    if (meta?.imageUrl) {
      this.imageBufferCache.delete(meta.imageUrl);
    }
    this.metadataCache.delete(norm);
  }

  public clearAvatarCache(): void {
    this.metadataCache.clear();
    this.imageBufferCache.clear();
  }
}

export const avatarService = new AvatarService();
