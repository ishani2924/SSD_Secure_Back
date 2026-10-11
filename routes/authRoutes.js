const express = require('express');
const router = express.Router();
const passport = require('passport');
const rateLimit = require('express-rate-limit');
const {
    register,
    login,
    facebookLogin, getProfile,
    updateRole,
    getAllUsers,
    logout,
    googleCallback
} = require('../controllers/authController');
const { authMiddleware, roleMiddleware } = require('../middleware/auth');

// ── [SECURITY FIX - Vulnerability 4] Auth Rate Limiter ───────
// Prevents brute-force attacks on login and register endpoints
const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute window
    max: 5,              // max 5 requests per IP per window
    message: {
        message: 'Too many requests from this IP, please try again after 1 minute.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// ── Existing Auth Routes ──────────────────────────────────────
router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/logout', authMiddleware, logout);
router.post('/facebook', facebookLogin);
router.get('/profile', authMiddleware, getProfile);
router.get('/users', authMiddleware, roleMiddleware(['ADMIN']), getAllUsers);
router.put('/users/:id/role', authMiddleware, roleMiddleware(['ADMIN']), updateRole);

// ── [NEW FEATURE] Google OAuth Routes ────────────────────────
// Step 1: User clicks "Sign in with Google" → goes to Google consent screen
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Step 2: Google redirects back here after user approves/denies
router.get(
    '/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/api/auth/google/failure' }),
    googleCallback
);

// Step 3: User denied / something went wrong
router.get('/google/failure', (req, res) => {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(frontendUrl + '/login?error=GoogleAuthDenied');
});

module.exports = router;
