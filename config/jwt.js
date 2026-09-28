/**
 * [SECURITY FIX — Vulnerability 8: Hardcoded secrets & weak JWT] FIXED
 *
 * Before: JWT secret could be embedded in source and tokens had overly long lifetimes.
 * After: JWT_SECRET and JWT_REFRESH_SECRET are required from .env (validated at server startup).
 * Access tokens default to 1h; refresh tokens to 7d (overridable via JWT_EXPIRES_IN / JWT_REFRESH_EXPIRES_IN).
 * Production must never rely on fallback secrets defined here — only NODE_ENV=test may use test defaults.
 */
const jwt = require('jsonwebtoken');

const DEFAULT_ACCESS_COOKIE_MAX_MS = 60 * 60 * 1000;
const DEFAULT_REFRESH_COOKIE_MAX_MS = 7 * 24 * 60 * 60 * 1000;

function validateJwtEnv() {
    if (process.env.NODE_ENV === 'test') {
        return;
    }

    const missing = [];
    if (!process.env.JWT_SECRET?.trim()) {
        missing.push('JWT_SECRET');
    }
    if (!process.env.JWT_REFRESH_SECRET?.trim()) {
        missing.push('JWT_REFRESH_SECRET');
    }

    if (missing.length > 0) {
        console.error(
            `FATAL: Missing required environment variable(s): ${missing.join(', ')}. ` +
            'Copy .env.example to .env and set strong, unique secrets.'
        );
        process.exit(1);
    }
}

function getJwtOptions() {
    const secret = process.env.JWT_SECRET || 'test_secret';
    const refreshSecret = process.env.JWT_REFRESH_SECRET || secret;

    return {
        secret,
        refreshSecret,
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
        accessCookieMaxAge: Number(process.env.JWT_ACCESS_COOKIE_MAX_MS) || DEFAULT_ACCESS_COOKIE_MAX_MS,
        refreshCookieMaxAge: Number(process.env.JWT_REFRESH_COOKIE_MAX_MS) || DEFAULT_REFRESH_COOKIE_MAX_MS
    };
}

function signAccessToken(userId) {
    const { secret, expiresIn } = getJwtOptions();
    return jwt.sign({ id: userId }, secret, { expiresIn });
}

function signRefreshToken(userId) {
    const { refreshSecret, refreshExpiresIn } = getJwtOptions();
    return jwt.sign({ id: userId }, refreshSecret, { expiresIn: refreshExpiresIn });
}

module.exports = {
    validateJwtEnv,
    getJwtOptions,
    signAccessToken,
    signRefreshToken
};
