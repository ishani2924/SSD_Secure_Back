/**
 * Auth middleware — session validation and refresh.
 *
 * [SECURITY FIX — Vulnerability 6: Token leakage] FIXED
 * Reads JWT from httpOnly cookies first (not from URL/query). Authorization header kept
 * only for backward compatibility with API clients/tests.
 *
 * [SECURITY FIX — Vulnerability 8: Weak JWT / hardcoded secrets] FIXED
 * Secrets and expiries come from config/jwt.js (.env). Expired access tokens trigger
 * refresh via a separate refresh cookie and short-lived re-issued access token.
 */
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { getJwtOptions, signAccessToken } = require('../config/jwt');

const authMiddleware = async (req, res, next) => {
    try {
        let token = req.cookies.token;

        // Fallback to Authorization header for backward compatibility
        if (!token && req.header('Authorization')) {
            token = req.header('Authorization').replace('Bearer ', '');
        }

        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        const { secret } = getJwtOptions();
        const decoded = jwt.verify(token, secret);
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            return res.status(401).json({ message: 'Token is not valid' });
        }

        if (user.status !== 'ACTIVE') {
            return res.status(403).json({ message: 'User account is not active' });
        }

        req.user = user;
        next();
    } catch (err) {
        // If token expired, try to refresh it
        if (err.name === 'TokenExpiredError' && req.cookies.refreshToken) {
            try {
                const { refreshSecret, accessCookieMaxAge } = getJwtOptions();
                const decoded = jwt.verify(req.cookies.refreshToken, refreshSecret);
                const user = await User.findById(decoded.id).select('-password');

                if (!user || user.status !== 'ACTIVE') {
                    return res.status(401).json({ message: 'Token is not valid' });
                }

                const newToken = signAccessToken(user._id);

                res.cookie('token', newToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: accessCookieMaxAge
                });

                req.user = user;
                next();
            } catch (refreshErr) {
                return res.status(401).json({ message: 'Token is not valid' });
            }
        } else {
            res.status(401).json({ message: 'Token is not valid' });
        }
    }
};

const roleMiddleware = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied: insufficient permissions' });
        }
        next();
    };
};

module.exports = { authMiddleware, roleMiddleware };
