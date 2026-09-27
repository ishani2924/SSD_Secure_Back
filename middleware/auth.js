const jwt = require('jsonwebtoken');
const User = require('../models/User');

// VULNERABILITY 8: Weak JWT Implementation - No token expiration validation beyond basic JWT verification
// FIX: Implement token refresh mechanism and shorter expiration times for access tokens
// VULNERABILITY 6: Sensitive Information in URL (Token Leakage) - Fixed by using httpOnly cookies instead of localStorage
const authMiddleware = async (req, res, next) => {
    try {
        // Try to get token from httpOnly cookie first
        let token = req.cookies.token;

        // Fallback to Authorization header for backward compatibility
        if (!token && req.header('Authorization')) {
            token = req.header('Authorization').replace('Bearer ', '');
        }

        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
                const decoded = jwt.verify(req.cookies.refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
                const user = await User.findById(decoded.id).select('-password');

                if (!user || user.status !== 'ACTIVE') {
                    return res.status(401).json({ message: 'Token is not valid' });
                }

                // Generate new access token
                const newToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

                // Set new cookie
                res.cookie('token', newToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 3600000 // 1 hour
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
