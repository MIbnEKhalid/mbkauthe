import { describe, it, expect, beforeEach, vi } from "vitest";
import { AuthResetService, setAuthEmailProvider, hashChallengeToken } from "../../src/services/AuthResetService.js";
import { AuthChallengeRepository } from "../../src/db/repositories/AuthChallengeRepository.js";
import { UserRepository } from "../../src/db/repositories/UserRepository.js";
import { verifyPassword } from "../../src/core/security/password.js";

describe("AuthResetService & Unified Challenge Flow", () => {
  let challengeRepo;
  let userRepo;
  let service;
  let mockUsers;
  let mockChallenges;

  beforeEach(() => {
    mockUsers = {
      testuser: {
        username: "testuser",
        email: "testuser@mbktech.org",
        password_hash: "",
        must_change_password: 0,
      },
    };

    mockChallenges = [];

    challengeRepo = {
      createChallenge: vi.fn(async (params) => {
        const row = {
          id: mockChallenges.length + 1,
          username: params.username,
          challenge_type: params.challenge_type,
          token_hash: params.token_hash,
          expires_at: params.expires_at,
          attempts: 0,
          max_attempts: params.max_attempts || 5,
          last_attempt_at: null,
          consumed_at: null,
          created_at: new Date(),
        };
        mockChallenges.push(row);
        return row;
      }),
      findActiveChallenge: vi.fn(async (username, type) => {
        return mockChallenges.filter(c => c.username === username && !c.consumed_at && (type ? c.challenge_type === type : true)).pop() || null;
      }),
      incrementAttempts: vi.fn(async (id) => {
        const c = mockChallenges.find(x => x.id === id);
        if (c) c.attempts++;
      }),
      markConsumed: vi.fn(async (id) => {
        const c = mockChallenges.find(x => x.id === id);
        if (c) c.consumed_at = new Date();
      }),
      clearChallengesForUser: vi.fn(async (username) => {
        mockChallenges = mockChallenges.filter(x => x.username !== username);
      }),
      getRecentAttemptCount: vi.fn(async () => 0),
    };

    userRepo = {
      findByUsernameOrEmail: vi.fn(async (id) => {
        return mockUsers[id] || (Object.values(mockUsers).find(u => u.email === id) || null);
      }),
      getUserByUsername: vi.fn(async (u) => mockUsers[u] || null),
      updatePassword: vi.fn(async (u, hash) => {
        if (mockUsers[u]) mockUsers[u].password_hash = hash;
      }),
      setMustChangePassword: vi.fn(async (u, val) => {
        if (mockUsers[u]) mockUsers[u].must_change_password = val ? 1 : 0;
      }),
      mustChangePassword: vi.fn(async (u) => Boolean(mockUsers[u]?.must_change_password)),
    };

    service = new AuthResetService(challengeRepo, userRepo);
  });

  describe("requestPasswordReset", () => {
    it("generates a unified challenge and invokes email provider when registered", async () => {
      const emailProvider = {
        sendResetLink: vi.fn().mockResolvedValue(undefined),
        sendOtpCode: vi.fn().mockResolvedValue(undefined),
      };
      setAuthEmailProvider(emailProvider);

      const result = await service.requestPasswordReset("testuser@mbktech.org", {
        origin: "https://auth.mbktech.org",
      });

      expect(result.success).toBe(true);
      expect(challengeRepo.createChallenge).toHaveBeenCalledOnce();
      expect(emailProvider.sendResetLink).toHaveBeenCalledOnce();

      const callArgs = emailProvider.sendResetLink.mock.calls[0];
      expect(callArgs[0]).toBe("testuser@mbktech.org");
      expect(callArgs[1]).toBe("testuser");
      expect(callArgs[2]).toContain("https://auth.mbktech.org/mbkauthe/reset-password?token=");

      setAuthEmailProvider(null);
    });

    it("generates 6-digit OTP code when challengeType is otp_code", async () => {
      const emailProvider = {
        sendResetLink: vi.fn(),
        sendOtpCode: vi.fn().mockResolvedValue(undefined),
      };
      setAuthEmailProvider(emailProvider);

      await service.requestPasswordReset("testuser", { challengeType: "otp_code" });

      expect(emailProvider.sendOtpCode).toHaveBeenCalledOnce();
      const [email, user, code] = emailProvider.sendOtpCode.mock.calls[0];
      expect(email).toBe("testuser@mbktech.org");
      expect(user).toBe("testuser");
      expect(code).toMatch(/^\d{6}$/);

      setAuthEmailProvider(null);
    });
  });

  describe("validateResetToken", () => {
    it("validates correct unexpired token", async () => {
      const rawToken = "my-secret-token-1234567890abcdef";
      mockChallenges.push({
        id: 1,
        username: "testuser",
        challenge_type: "reset_link",
        token_hash: hashChallengeToken(rawToken),
        expires_at: new Date(Date.now() + 60000),
        attempts: 0,
        max_attempts: 5,
        consumed_at: null,
      });

      const res = await service.validateResetToken("testuser", rawToken);
      expect(res.valid).toBe(true);
    });

    it("fails and increments attempts on incorrect token", async () => {
      const rawToken = "correct-token";
      mockChallenges.push({
        id: 1,
        username: "testuser",
        challenge_type: "reset_link",
        token_hash: hashChallengeToken(rawToken),
        expires_at: new Date(Date.now() + 60000),
        attempts: 0,
        max_attempts: 5,
        consumed_at: null,
      });

      const res = await service.validateResetToken("testuser", "wrong-token");
      expect(res.valid).toBe(false);
      expect(challengeRepo.incrementAttempts).toHaveBeenCalledWith(1);
    });
  });

  describe("resetPassword", () => {
    it("updates password hash, clears must_change_password, and marks challenge consumed", async () => {
      const rawToken = "reset-valid-token-123";
      mockChallenges.push({
        id: 1,
        username: "testuser",
        challenge_type: "reset_link",
        token_hash: hashChallengeToken(rawToken),
        expires_at: new Date(Date.now() + 60000),
        attempts: 0,
        max_attempts: 5,
        consumed_at: null,
      });

      const result = await service.resetPassword("testuser", rawToken, "NewSecurePassword123!");
      expect(result.success).toBe(true);
      expect(userRepo.updatePassword).toHaveBeenCalled();
      expect(userRepo.setMustChangePassword).toHaveBeenCalledWith("testuser", false);
      expect(challengeRepo.markConsumed).toHaveBeenCalledWith(1);
      expect(challengeRepo.clearChallengesForUser).toHaveBeenCalledWith("testuser");

      const isPwValid = await verifyPassword("NewSecurePassword123!", "testuser", mockUsers.testuser.password_hash);
      expect(isPwValid).toBe(true);
    });
  });

  describe("generateAdminOtp", () => {
    it("creates an admin OTP challenge, updates password_hash to OTP, and sets must_change_password = true", async () => {
      const result = await service.generateAdminOtp("testuser", 24);

      expect(result.rawOTP).toBeDefined();
      expect(result.rawOTP.length).toBe(8);
      expect(result.expiresAt).toBeDefined();

      expect(challengeRepo.createChallenge).toHaveBeenCalledWith(expect.objectContaining({
        username: "testuser",
        challenge_type: "admin_otp",
      }));

      expect(userRepo.setMustChangePassword).toHaveBeenCalledWith("testuser", true);
      expect(mockUsers.testuser.must_change_password).toBe(1);

      // User must be able to authenticate with this raw OTP as their password
      const canLoginWithOtp = await verifyPassword(result.rawOTP, "testuser", mockUsers.testuser.password_hash);
      expect(canLoginWithOtp).toBe(true);
    });
  });

  describe("changePasswordForced", () => {
    it("updates password, resets must_change_password to false, and purges challenges", async () => {
      mockUsers.testuser.must_change_password = 1;

      const result = await service.changePasswordForced("testuser", "UpdatedPermanentPw456!");
      expect(result.success).toBe(true);
      expect(userRepo.setMustChangePassword).toHaveBeenCalledWith("testuser", false);
      expect(mockUsers.testuser.must_change_password).toBe(0);

      const isPwValid = await verifyPassword("UpdatedPermanentPw456!", "testuser", mockUsers.testuser.password_hash);
      expect(isPwValid).toBe(true);
    });
  });
});

