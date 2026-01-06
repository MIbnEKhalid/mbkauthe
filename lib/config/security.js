import crypto from "crypto";

// Password hashing using PBKDF2
export const hashPassword = (password, username) => {
    const salt = username;
    // 128 characters returned
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
};

// Hash an API token for storage
// Uses SHA-256 for fast, secure non-reversible hashing
export const hashApiToken = (token) => {
    if (!token) return null;
    return crypto.createHash('sha256').update(token).digest('hex');
};