const rateLimit = require('express-rate-limit');

const FIFTEEN_MINUTES = 15 * 60 * 1000;

function isTestEnv() {
    return process.env.NODE_ENV === 'test';
}

function createLimiter({ windowMs, max, message, errorCode }) {
    return rateLimit({
        windowMs,
        max,
        standardHeaders: true,
        legacyHeaders: false,
        // Jest sends every request from one IP. Counting those would turn
        // the suite into a stream of 429s, so the limits apply only when
        // the server is actually running.
        skip: () => isTestEnv(),
        message: {
            message,
            error: errorCode
        }
    });
}

// One client flooding incidents, alerts, staff, and the other routes.
const apiLimiter = createLimiter({
    windowMs: FIFTEEN_MINUTES,
    max: 300,
    message: 'Too many requests. Please try again later.',
    errorCode: 'RATE_LIMIT_EXCEEDED'
});

// Password guessing and fake account creation. Much tighter than the general cap.
const authLimiter = createLimiter({
    windowMs: FIFTEEN_MINUTES,
    max: 10,
    message: 'Too many authentication attempts. Please try again later.',
    errorCode: 'AUTH_RATE_LIMIT_EXCEEDED'
});

module.exports = {
    apiLimiter,
    authLimiter
};
