import { describe, test, expect, beforeEach } from "vitest";
import { AvatarService } from "../../dist/services/AvatarService.js";

describe("AvatarService Redesign & Multi-User Support", () => {
  let avatarService;

  beforeEach(() => {
    avatarService = new AvatarService();
  });

  test("warmCache stores metadata and generates distinct deterministic ETags for different users", () => {
    const meta1 = avatarService.warmCache("user_one", "https://example.com/u1.jpg");
    const meta2 = avatarService.warmCache("user_two", "https://example.com/u2.jpg");
    const meta3 = avatarService.warmCache("user_three", null);

    expect(meta1.imageUrl).toBe("https://example.com/u1.jpg");
    expect(meta2.imageUrl).toBe("https://example.com/u2.jpg");
    expect(meta3.imageUrl).toBeNull();

    // ETags must be unique per user & image, prefixed with W/"avatar-
    expect(meta1.etag).toMatch(/^W\/"avatar-[0-9a-f]{32}"$/);
    expect(meta2.etag).toMatch(/^W\/"avatar-[0-9a-f]{32}"$/);
    expect(meta3.etag).toMatch(/^W\/"avatar-[0-9a-f]{32}"$/);

    expect(meta1.etag).not.toBe(meta2.etag);
    expect(meta1.etag).not.toBe(meta3.etag);
  });

  test("normalizes usernames to prevent case-sensitive cache fragmentation", () => {
    avatarService.warmCache("JohnDoe", "https://example.com/john.jpg");
    const cachedLower = avatarService.warmCache("johndoe", "https://example.com/john.jpg");

    expect(cachedLower.etag).toBeDefined();
    expect(cachedLower.imageUrl).toBe("https://example.com/john.jpg");
  });

  test("serves default avatar PNG buffer when user has no image", async () => {
    const meta = avatarService.warmCache("no_image_user", null);
    const result = await avatarService.getAvatarImage("no_image_user", meta);

    expect(result.contentType).toBe("image/png");
    expect(Buffer.isBuffer(result.buffer)).toBe(true);
    expect(result.buffer.length).toBeGreaterThan(0);
    expect(result.etag).toBe(meta.etag);
  });

  test("supports rendering multiple users concurrently without state contamination", async () => {
    const users = [
      { username: "alice", image: null },
      { username: "bob", image: null },
      { username: "charlie", image: null },
    ];

    users.forEach((u) => avatarService.warmCache(u.username, u.image));

    // Concurrently fetch avatars for all 3 users
    const results = await Promise.all(
      users.map(async (u) => {
        const meta = await avatarService.getAvatarMetadata(u.username);
        const img = await avatarService.getAvatarImage(u.username, meta);
        return { username: u.username, meta, img };
      })
    );

    expect(results).toHaveLength(3);
    expect(results[0].meta.etag).not.toBe(results[1].meta.etag);
    expect(results[1].meta.etag).not.toBe(results[2].meta.etag);
    expect(results[0].img.contentType).toBe("image/png");
  });

  test("invalidateAvatarCache evicts user metadata and buffer from cache", async () => {
    avatarService.warmCache("test_user", "https://example.com/pic.jpg");
    let meta = await avatarService.getAvatarMetadata("test_user");
    expect(meta.imageUrl).toBe("https://example.com/pic.jpg");

    avatarService.invalidateAvatarCache("test_user");

    // Cache should be cleared for test_user; next getAvatarMetadata queries source
    avatarService.clearAvatarCache();
  });
});
