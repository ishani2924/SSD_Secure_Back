// tests/authRoutes.test.js
// Route-level unit tests for routes/authRoutes.js

process.env.SKIP_DB = 'true';

const express = require('express');
const request = require('supertest');

let mockCurrentUserRole = 'ADMIN';

const mockRoleHandler = jest.fn((req, res, next) => {
    if (!['ADMIN'].includes(req.user?.role)) {
        return res.status(403).json({ message: 'Access denied: insufficient permissions' });
    }
    next();
});

jest.mock('../controllers/authController', () => ({
    register: jest.fn((req, res) => res.status(201).json({ success: true, message: 'registered' })),
    login: jest.fn((req, res) => res.status(200).json({ success: true, message: 'logged in' })),
    logout: jest.fn((req, res) => res.status(200).json({ success: true, message: 'logged out' })),
    facebookLogin: jest.fn((req, res) => res.status(200).json({ success: true, message: 'facebook login' })),
    getProfile: jest.fn((req, res) => res.status(200).json({ success: true, profile: { id: 'u1' } })),
    updateRole: jest.fn((req, res) => res.status(200).json({ success: true, message: 'role updated' })),
    getAllUsers: jest.fn((req, res) => res.status(200).json([{ id: 'u1' }, { id: 'u2' }])),
    googleCallback: jest.fn((req, res) => res.redirect('/dashboard?login=success'))
}));

jest.mock('../middleware/auth', () => ({
    authMiddleware: jest.fn((req, res, next) => {
        req.user = { id: 'test_user_id', role: mockCurrentUserRole };
        next();
    }),
    roleMiddleware: jest.fn(() => (req, res, next) => mockRoleHandler(req, res, next))
}));

const authController = require('../controllers/authController');
const { authMiddleware } = require('../middleware/auth');
const authRoutes = require('../routes/authRoutes');

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);

describe('authRoutes Route Unit Tests', () => {
    beforeEach(() => {
        mockCurrentUserRole = 'ADMIN';
        authController.register.mockClear();
        authController.login.mockClear();
        authController.logout.mockClear();
        authController.facebookLogin.mockClear();
        authController.getProfile.mockClear();
        authController.updateRole.mockClear();
        authController.getAllUsers.mockClear();
        authMiddleware.mockClear();
        mockRoleHandler.mockClear();
    });

    test('POST /api/auth/register – routes to authController.register', async () => {
        const payload = { name: 'Test', email: 'test@example.com', password: 'password123' };
        const res = await request(app)
            .post('/api/auth/register')
            .send(payload);

        expect(res.status).toBe(201);
        expect(authController.register).toHaveBeenCalledTimes(1);
    });

    test('POST /api/auth/login – routes to authController.login', async () => {
        const payload = { email: 'test@example.com', password: 'password123' };
        const res = await request(app)
            .post('/api/auth/login')
            .send(payload);

        expect(res.status).toBe(200);
        expect(authController.login).toHaveBeenCalledTimes(1);
    });

    test('POST /api/auth/logout – calls authMiddleware and routes to authController.logout', async () => {
        const res = await request(app).post('/api/auth/logout');

        expect(authMiddleware).toHaveBeenCalled();
        expect(authController.logout).toHaveBeenCalledTimes(1);
        expect(res.status).toBe(200);
    });

    test('POST /api/auth/facebook – routes to authController.facebookLogin', async () => {
        const payload = { accessToken: 'fb_access_token', userID: 'fb_12345' };
        const res = await request(app)
            .post('/api/auth/facebook')
            .send(payload);

        expect(res.status).toBe(200);
        expect(authController.facebookLogin).toHaveBeenCalledTimes(1);
    });

    test('GET /api/auth/profile – calls authMiddleware and routes to authController.getProfile', async () => {
        const res = await request(app).get('/api/auth/profile');

        expect(authMiddleware).toHaveBeenCalled();
        expect(authController.getProfile).toHaveBeenCalledTimes(1);
        expect(res.status).toBe(200);
    });

    test('GET /api/auth/users – allows ADMIN access and routes to authController.getAllUsers', async () => {
        mockCurrentUserRole = 'ADMIN';
        const res = await request(app).get('/api/auth/users');

        expect(authMiddleware).toHaveBeenCalled();
        expect(mockRoleHandler).toHaveBeenCalled();
        expect(authController.getAllUsers).toHaveBeenCalledTimes(1);
        expect(res.status).toBe(200);
    });

    test('GET /api/auth/users – blocks non-ADMIN access with 403', async () => {
        mockCurrentUserRole = 'CITIZEN';
        const res = await request(app).get('/api/auth/users');

        expect(authMiddleware).toHaveBeenCalled();
        expect(mockRoleHandler).toHaveBeenCalled();
        expect(authController.getAllUsers).not.toHaveBeenCalled();
        expect(res.status).toBe(403);
    });

    test('PUT /api/auth/users/:id/role – allows ADMIN to update role', async () => {
        mockCurrentUserRole = 'ADMIN';
        const res = await request(app)
            .put('/api/auth/users/user_abc/role')
            .send({ role: 'OFFICER' });

        expect(authMiddleware).toHaveBeenCalled();
        expect(mockRoleHandler).toHaveBeenCalled();
        expect(authController.updateRole).toHaveBeenCalledTimes(1);
        expect(res.status).toBe(200);
    });

    test('GET /api/auth/google/failure – redirects to frontend login with error query param', async () => {
        const res = await request(app).get('/api/auth/google/failure');

        expect(res.status).toBe(302);
        expect(res.headers.location).toContain('/login?error=GoogleAuthDenied');
    });
});
