// tests/health.test.js
// Unit/Integration test for server health check and security response headers

process.env.SKIP_DB = 'true';

const request = require('supertest');
const app = require('../app');

describe('Server Health and Security Headers Test', () => {
    test('GET / – returns 200 and "WildSafe API is running..."', async () => {
        const res = await request(app).get('/');
        expect(res.status).toBe(200);
        expect(res.text).toBe('WildSafe API is running...');
    });

    test('GET / – enforces security headers configured in app.js', async () => {
        const res = await request(app).get('/');

        // X-Powered-By should be removed
        expect(res.headers['x-powered-by']).toBeUndefined();

        // Anti-Clickjacking: X-Frame-Options set to DENY
        expect(res.headers['x-frame-options']).toBe('DENY');

        // MIME-type sniffing protection
        expect(res.headers['x-content-type-options']).toBe('nosniff');

        // HTTP Strict Transport Security
        expect(res.headers['strict-transport-security']).toContain('max-age=31536000');
    });
});
