const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const corsOptions = require('./middleware/corsConfig');
const { apiLimiter } = require('./middleware/rateLimiters');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware — only the frontend origins in corsConfig may call this API
app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Shared cap for every API route. Login and register add a stricter cap of their own.
app.use('/api', apiLimiter);

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
