import crypto from "crypto";

// Password hashing using PBKDF2
export const hashPassword = (password, username) => {
    const salt = username;
    // 128 characters returned
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
};
