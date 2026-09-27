const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware
// [SECURITY FIX — Vulnerability 6] credentials: true allows httpOnly auth cookies on cross-origin API calls
app.use(cors({
    origin: process.env.FRONTEND_URL || ['http://localhost:5173', 'http://[::1]:5173'],
    credentials: true
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
