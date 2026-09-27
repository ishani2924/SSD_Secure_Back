const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const helmet = require('helmet'); // [SECURITY FIX] Helmet for HTTP security headers

dotenv.config();

const app = express();

// ============================================================
// [SECURITY FIX - Vulnerability 1] Content Security Policy (CSP)
// REASON: Without CSP, browsers will execute any script injected
// by an attacker (XSS). This header tells the browser to ONLY
// load resources from trusted, explicitly listed sources.
// ZAP Alert: "Content Security Policy (CSP) Header Not Set"
// ============================================================
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:", "https://images.unsplash.com", "blob:"],
      "connect-src": [
        "'self'",
        process.env.FRONTEND_URL || "http://localhost:5173",
        "http://localhost:5000"
      ],
      "font-src": ["'self'", "https://fonts.gstatic.com"],
      "frame-ancestors": ["'none'"],
    },
  })
);

// ============================================================
// [SECURITY FIX - Vulnerability 2] Anti-Clickjacking (X-Frame-Options)
// REASON: Without this, attackers can embed your app in an iframe
// on a malicious website and trick users into clicking hidden buttons.
// ZAP Alert: "Missing Anti-clickjacking Header"
// ============================================================
app.use(helmet.frameguard({ action: 'deny' }));

// ============================================================
// [SECURITY FIX - Vulnerability 3] Hide X-Powered-By Header
// REASON: Exposing "X-Powered-By: Express" tells attackers exactly
// what server software is running, making targeted attacks easier.
// ============================================================
app.use(helmet.hidePoweredBy());

// ============================================================
// [SECURITY FIX - Vulnerability 4] X-Content-Type-Options
// REASON: Prevents browsers from MIME-sniffing a response away
// from the declared content-type, blocking drive-by downloads.
// ============================================================
app.use(helmet.noSniff());

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true // Enable credentials for cookies
}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));

// Improve mongoose debug & connection handling
mongoose.set('strictQuery', false);

// Express routes and middleware
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

// Resource & Staff management routes
app.use('/api/staff', require('./routes/resourceStaff/staffRoutes'));
app.use('/api/resources', require('./routes/resourceStaff/resourceRoutes'));

// Basic Route
app.get('/', (req, res) => {
    res.send('WildSafe API is running...');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled route error:', err.stack || err);
    res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

module.exports = app;
