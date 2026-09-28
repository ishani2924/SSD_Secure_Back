// ── MUST be first: load .env before any process.env references ──
const dotenv = require('dotenv');
dotenv.config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const User = require('./models/User');
const corsOptions = require('./middleware/corsConfig');
const sanitizeInput = require('./middleware/sanitizeInput');
const { apiLimiter } = require('./middleware/rateLimiters');

// ============================================================
// [NEW FEATURE] Google OAuth Strategy Configuration
// This runs AFTER dotenv.config() so env vars are available
// ============================================================
passport.use(new GoogleStrategy(
    {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            // Check if user already logged in with Google before
            let user = await User.findOne({ googleId: profile.id });
            if (!user) {
                const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
                // Check if they have an existing email/password account
                if (email) {
                    user = await User.findOne({ email: email });
                }
                if (user) {
                    // Link Google ID to existing account
                    user.googleId = profile.id;
                    await user.save();
                } else {
                    // Create a brand new user from Google profile
                    user = await User.create({
                        name: profile.displayName || 'Google User',
                        email: email,
                        googleId: profile.id,
                        status: 'ACTIVE',
                        role: 'CITIZEN'
                    });
                }
            }
            return done(null, user);
        } catch (err) {
            return done(err, null);
        }
    }
));

passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

const app = express();

// Fix 1: Disable X-Powered-By header to prevent information leakage
app.disable('x-powered-by');

// ============================================================
// [SECURITY FIX - Vulnerability 1] Content Security Policy (CSP)
// ZAP Alert: "Content Security Policy (CSP) Header Not Set"
// ============================================================
app.use(
    helmet.contentSecurityPolicy({
        useDefaults: true,
        directives: {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:', 'https://images.unsplash.com', 'blob:'],
            'connect-src': ["'self'", process.env.FRONTEND_URL || 'http://localhost:5173', 'http://localhost:5000'],
            'font-src': ["'self'", 'https://fonts.gstatic.com'],
            'frame-ancestors': ["'none'"],
        },
    })
);

// ============================================================
// [SECURITY FIX - Vulnerability 2] Anti-Clickjacking
// ZAP Alert: "Missing Anti-clickjacking Header"
// ============================================================
app.use(helmet.frameguard({ action: 'deny' }));

// ============================================================
// [SECURITY FIX - Vulnerability 3] Hide X-Powered-By
// ============================================================
app.use(helmet.hidePoweredBy());

// ============================================================
// [SECURITY FIX - Vulnerability 4] X-Content-Type-Options
// ============================================================
app.use(helmet.noSniff());

// Session middleware (required for passport)
app.use(session({
    secret: process.env.JWT_SECRET || 'wildsafe-session-secret',
    resave: false,
    saveUninitialized: false
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Middleware — only the frontend origins in corsConfig may call this API
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
// Drop MongoDB operators and HTML before any route reads the request.
app.use(sanitizeInput);
app.use('/uploads', express.static('uploads'));

// Fix 2: Enforce HTTP Strict Transport Security (HSTS)
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// Shared cap for every API route. Login and register add a stricter cap of their own.
app.use('/api', apiLimiter);

// Improve mongoose debug & connection handling
mongoose.set('strictQuery', false);

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/incidents', require('./routes/incidentRoutes'));
app.use('/api/analytics', require('./routes/analyticsRoutes'));
app.use('/api/threat-reports', require('./routes/threatReportRoutes'));
app.use('/api/cases', require('./routes/caseRoutes'));
app.use('/api/assignment', require('./routes/assignmentRoutes'));
app.use('/api/ai', require('./routes/aiRoutes'));
app.use('/api/notifications', require('./routes/notificationRoutes'));
app.use('/api/alerts', require('./routes/alertRoutes'));
app.use('/api/awareness', require('./routes/awarenessRoutes'));
app.use('/api/ranger', require('./routes/rangerRoutes'));
app.use('/api/staff', require('./routes/resourceStaff/staffRoutes'));
app.use('/api/resources', require('./routes/resourceStaff/resourceRoutes'));

// Basic health check route
app.get('/', (req, res) => {
    res.send('WildSafe API is running...');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled route error:', err.stack || err);
    res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

module.exports = app;
