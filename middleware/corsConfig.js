/**
 * Only these browser origins may read API responses.
 * Override with CORS_ORIGINS in .env (comma-separated) when the frontend
 * is deployed somewhere other than the local Vite app.
 */
function getAllowedOrigins() {
    const configured = process.env.CORS_ORIGINS
        || 'http://localhost:5173,http://127.0.0.1:5173';

    return configured
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
}

const corsOptions = {
    origin(origin, callback) {
        // No Origin header: Postman, curl, and the mobile app. Those are not
        // browser pages, so CORS does not apply to them.
        if (!origin || getAllowedOrigins().includes(origin)) {
            callback(null, true);
            return;
        }
        // Deny. The cors package omits Access-Control-Allow-Origin, so the
        // browser blocks the other website from reading the response.
        callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600
};

module.exports = corsOptions;
