// tests/authMiddleware.test.js
// Unit tests for middleware/auth.js

process.env.SKIP_DB = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_key';

jest.mock('../models/User');

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authMiddleware, roleMiddleware } = require('../middleware/auth');

const mockReq = (cookies = {}, headers = {}, user = null) => ({
    cookies,
    header: (name) => headers[name] || headers[name.toLowerCase()],
    user
});

const mockRes = () => {
    const res = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.cookie = jest.fn().mockReturnValue(res);
    return res;
};

describe('authMiddleware Unit Tests', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    test('200 – authenticates user via httpOnly cookie token and calls next()', async () => {
        const token = jwt.sign({ id: 'u123' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const mockUser = { _id: 'u123', name: 'John Doe', role: 'CITIZEN', status: 'ACTIVE' };

        User.findById.mockReturnValue({
            select: jest.fn().mockResolvedValue(mockUser)
        });

        const req = mockReq({ token });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(req.user).toEqual(mockUser);
        expect(next).toHaveBeenCalledTimes(1);
        expect(res.status).not.toHaveBeenCalled();
    });

    test('200 – authenticates user via Authorization header Bearer token', async () => {
        const token = jwt.sign({ id: 'u456' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const mockUser = { _id: 'u456', name: 'Officer Bob', role: 'OFFICER', status: 'ACTIVE' };

        User.findById.mockReturnValue({
            select: jest.fn().mockResolvedValue(mockUser)
        });

        const req = mockReq({}, { Authorization: `Bearer ${token}` });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(req.user).toEqual(mockUser);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('401 – rejects request when no token is present in cookies or headers', async () => {
        const req = mockReq({}, {});
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'No token, authorization denied' });
        expect(next).not.toHaveBeenCalled();
    });

    test('401 – rejects request when token is invalid or tampered with', async () => {
        const req = mockReq({ token: 'invalid.jwt.token' });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Token is not valid' });
        expect(next).not.toHaveBeenCalled();
    });

    test('401 – rejects request when user decoded from token is not found in database', async () => {
        const token = jwt.sign({ id: 'nonexistent' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        User.findById.mockReturnValue({
            select: jest.fn().mockResolvedValue(null)
        });

        const req = mockReq({ token });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Token is not valid' });
        expect(next).not.toHaveBeenCalled();
    });

    test('403 – rejects request when user account is not ACTIVE (e.g. SUSPENDED)', async () => {
        const token = jwt.sign({ id: 'uSuspended' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const mockUser = { _id: 'uSuspended', status: 'SUSPENDED', role: 'CITIZEN' };

        User.findById.mockReturnValue({
            select: jest.fn().mockResolvedValue(mockUser)
        });

        const req = mockReq({ token });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ message: 'User account is not active' });
        expect(next).not.toHaveBeenCalled();
    });

    test('200 – automatically refreshes access token if expired and refreshToken is valid', async () => {
        // Expired access token
        const expiredToken = jwt.sign({ id: 'uRefresh' }, process.env.JWT_SECRET, { expiresIn: '-1s' });
        // Valid refresh token
        const refreshToken = jwt.sign({ id: 'uRefresh' }, process.env.JWT_SECRET, { expiresIn: '7d' });

        const mockUser = { _id: 'uRefresh', name: 'Refreshed User', role: 'CITIZEN', status: 'ACTIVE' };
        User.findById.mockReturnValue({
            select: jest.fn().mockResolvedValue(mockUser)
        });

        const req = mockReq({ token: expiredToken, refreshToken });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.cookie).toHaveBeenCalledWith('token', expect.any(String), expect.objectContaining({
            httpOnly: true,
            maxAge: 3600000
        }));
        expect(req.user).toEqual(mockUser);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('401 – rejects request when access token expired and refreshToken is also expired/invalid', async () => {
        const expiredToken = jwt.sign({ id: 'uFail' }, process.env.JWT_SECRET, { expiresIn: '-1s' });
        const invalidRefreshToken = 'invalid.refresh.token';

        const req = mockReq({ token: expiredToken, refreshToken: invalidRefreshToken });
        const res = mockRes();
        const next = jest.fn();

        await authMiddleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Token is not valid' });
        expect(next).not.toHaveBeenCalled();
    });
});

describe('roleMiddleware Unit Tests', () => {
    test('calls next() when user has one of the allowed roles', () => {
        const middleware = roleMiddleware(['ADMIN', 'OFFICER']);
        const req = { user: { role: 'OFFICER' } };
        const res = mockRes();
        const next = jest.fn();

        middleware(req, res, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect(res.status).not.toHaveBeenCalled();
    });

    test('403 – blocks access when user does not have an allowed role', () => {
        const middleware = roleMiddleware(['ADMIN']);
        const req = { user: { role: 'CITIZEN' } };
        const res = mockRes();
        const next = jest.fn();

        middleware(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ message: 'Access denied: insufficient permissions' });
        expect(next).not.toHaveBeenCalled();
    });
});
