// tests/authController.test.js
// Unit tests for controllers/authController.js
// Mongoose models and external services are mocked — no DB required.

process.env.SKIP_DB = 'true';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_key';

jest.mock('../models/User');
jest.mock('axios');

const User = require('../models/User');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const {
    register,
    login,
    updateRole,
    getAllUsers,
    getProfile,
    logout,
    googleCallback,
    facebookLogin
} = require('../controllers/authController');

// ─── Helpers ─────────────────────────────────────────────────────────────────
const mockReq = (body = {}, params = {}, query = {}, user = null, cookies = {}) => ({
    body,
    params,
    query,
    user,
    cookies
});

const mockRes = () => {
    const res = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    res.cookie = jest.fn().mockReturnValue(res);
    res.clearCookie = jest.fn().mockReturnValue(res);
    res.redirect = jest.fn().mockReturnValue(res);
    return res;
};

describe('authController Unit Tests', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    // =========================================================================
    // 1. register
    // =========================================================================
    describe('register', () => {
        test('201 – successfully registers a new citizen user and sets cookies', async () => {
            User.findOne.mockResolvedValue(null);
            const createdUser = {
                _id: 'user123',
                name: 'John Doe',
                email: 'john@example.com',
                role: 'CITIZEN'
            };
            User.create.mockResolvedValue(createdUser);

            const req = mockReq({
                name: 'John Doe',
                email: 'john@example.com',
                password: 'password123',
                phone: '1234567890'
            });
            const res = mockRes();

            await register(req, res);

            expect(User.findOne).toHaveBeenCalledWith({ email: 'john@example.com' });
            expect(User.create).toHaveBeenCalledWith(expect.objectContaining({
                name: 'John Doe',
                email: 'john@example.com',
                password: 'password123',
                phone: '1234567890'
            }));
            expect(res.cookie).toHaveBeenCalledWith('token', expect.any(String), expect.objectContaining({
                httpOnly: true,
                sameSite: 'lax'
            }));
            expect(res.cookie).toHaveBeenCalledWith('refreshToken', expect.any(String), expect.objectContaining({
                httpOnly: true,
                sameSite: 'lax'
            }));
            expect(res.status).toHaveBeenCalledWith(201);
            expect(res.json).toHaveBeenCalledWith({
                user: {
                    id: 'user123',
                    name: 'John Doe',
                    email: 'john@example.com',
                    role: 'CITIZEN'
                }
            });
        });

        test('201 – parses valid geo coordinates when provided', async () => {
            User.findOne.mockResolvedValue(null);
            User.create.mockImplementation(async (data) => ({
                _id: 'user123',
                ...data,
                role: 'CITIZEN'
            }));

            const req = mockReq({
                name: 'Jane Doe',
                email: 'jane@example.com',
                password: 'password123',
                location: {
                    type: 'Point',
                    coordinates: [80.123, 7.456]
                }
            });
            const res = mockRes();

            await register(req, res);

            expect(User.create).toHaveBeenCalledWith(expect.objectContaining({
                location: { type: 'Point', coordinates: [80.123, 7.456] }
            }));
            expect(res.status).toHaveBeenCalledWith(201);
        });

        test('400 – rejects registration when name is missing', async () => {
            const req = mockReq({ email: 'john@example.com', password: 'password123' });
            const res = mockRes();

            await register(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Name, email and password are required'
            }));
        });

        test('400 – rejects registration when email or password is missing', async () => {
            const req = mockReq({ name: 'John Doe', password: 'password123' });
            const res = mockRes();

            await register(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Name, email and password are required'
            }));
        });

        test('400 – prevents NoSQL injection attempts by treating non-string input as empty', async () => {
            const req = mockReq({
                name: { $gt: '' },
                email: 'valid@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await register(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Name, email and password are required'
            }));
        });

        test('400 – returns error if user already exists', async () => {
            User.findOne.mockResolvedValue({ _id: 'existing123', email: 'john@example.com' });

            const req = mockReq({
                name: 'John Doe',
                email: 'john@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await register(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'User already exists' });
        });

        test('500 – returns server error if User.create throws an error', async () => {
            User.findOne.mockResolvedValue(null);
            User.create.mockRejectedValue(new Error('Database error'));

            const req = mockReq({
                name: 'John Doe',
                email: 'john@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await register(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Server error',
                error: 'Database error'
            }));
        });
    });

    // =========================================================================
    // 2. login
    // =========================================================================
    describe('login', () => {
        test('200 – successfully logs in with valid credentials and sets cookies', async () => {
            const mockUser = {
                _id: 'user123',
                name: 'John Doe',
                email: 'john@example.com',
                role: 'CITIZEN',
                comparePassword: jest.fn().mockResolvedValue(true)
            };
            User.findOne.mockResolvedValue(mockUser);

            const req = mockReq({
                email: 'john@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await login(req, res);

            expect(User.findOne).toHaveBeenCalledWith({ email: 'john@example.com' });
            expect(mockUser.comparePassword).toHaveBeenCalledWith('password123');
            expect(res.cookie).toHaveBeenCalledWith('token', expect.any(String), expect.any(Object));
            expect(res.cookie).toHaveBeenCalledWith('refreshToken', expect.any(String), expect.any(Object));
            expect(res.json).toHaveBeenCalledWith({
                user: {
                    id: 'user123',
                    name: 'John Doe',
                    email: 'john@example.com',
                    role: 'CITIZEN'
                }
            });
        });

        test('400 – rejects login when email or password is missing', async () => {
            const req = mockReq({ email: 'john@example.com' });
            const res = mockRes();

            await login(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Email and password are required' });
        });

        test('400 – prevents NoSQL injection attempts on login credentials', async () => {
            const req = mockReq({
                email: { $ne: null },
                password: 'password123'
            });
            const res = mockRes();

            await login(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Email and password are required' });
        });

        test('400 – returns invalid credentials when user is not found', async () => {
            User.findOne.mockResolvedValue(null);

            const req = mockReq({
                email: 'unknown@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await login(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' });
        });

        test('400 – returns invalid credentials when password does not match', async () => {
            const mockUser = {
                _id: 'user123',
                email: 'john@example.com',
                comparePassword: jest.fn().mockResolvedValue(false)
            };
            User.findOne.mockResolvedValue(mockUser);

            const req = mockReq({
                email: 'john@example.com',
                password: 'wrongpassword'
            });
            const res = mockRes();

            await login(req, res);

            expect(mockUser.comparePassword).toHaveBeenCalledWith('wrongpassword');
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Invalid credentials' });
        });

        test('500 – handles server error gracefully', async () => {
            User.findOne.mockRejectedValue(new Error('DB failure'));

            const req = mockReq({
                email: 'john@example.com',
                password: 'password123'
            });
            const res = mockRes();

            await login(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Server error',
                error: 'DB failure'
            }));
        });
    });

    // =========================================================================
    // 3. updateRole
    // =========================================================================
    describe('updateRole', () => {
        test('200 – successfully updates user role to valid role (OFFICER)', async () => {
            const updatedUser = { _id: 'u1', name: 'John', role: 'OFFICER' };
            User.findByIdAndUpdate.mockReturnValue({
                select: jest.fn().mockResolvedValue(updatedUser)
            });

            const req = mockReq({ role: 'OFFICER' }, { id: 'u1' });
            const res = mockRes();

            await updateRole(req, res);

            expect(User.findByIdAndUpdate).toHaveBeenCalledWith('u1', { role: 'OFFICER' }, { new: true });
            expect(res.json).toHaveBeenCalledWith({
                message: 'Role updated successfully',
                user: updatedUser
            });
        });

        test('400 – rejects invalid role name', async () => {
            const req = mockReq({ role: 'SUPERUSER' }, { id: 'u1' });
            const res = mockRes();

            await updateRole(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: expect.stringContaining('Role must be one of: CITIZEN, OFFICER, ADMIN')
            }));
        });

        test('400 – rejects missing role', async () => {
            const req = mockReq({}, { id: 'u1' });
            const res = mockRes();

            await updateRole(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
        });

        test('404 – returns not found if target user does not exist', async () => {
            User.findByIdAndUpdate.mockReturnValue({
                select: jest.fn().mockResolvedValue(null)
            });

            const req = mockReq({ role: 'ADMIN' }, { id: 'unknown_id' });
            const res = mockRes();

            await updateRole(req, res);

            expect(res.status).toHaveBeenCalledWith(404);
            expect(res.json).toHaveBeenCalledWith({ message: 'User not found' });
        });

        test('500 – handles DB error', async () => {
            User.findByIdAndUpdate.mockReturnValue({
                select: jest.fn().mockRejectedValue(new Error('DB error'))
            });

            const req = mockReq({ role: 'ADMIN' }, { id: 'u1' });
            const res = mockRes();

            await updateRole(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: 'Server error' }));
        });
    });

    // =========================================================================
    // 4. getAllUsers
    // =========================================================================
    describe('getAllUsers', () => {
        test('200 – returns all users without passwords', async () => {
            const mockUsers = [
                { _id: 'u1', name: 'User 1', email: 'u1@test.com' },
                { _id: 'u2', name: 'User 2', email: 'u2@test.com' }
            ];
            User.find.mockReturnValue({
                select: jest.fn().mockResolvedValue(mockUsers)
            });

            const req = mockReq();
            const res = mockRes();

            await getAllUsers(req, res);

            expect(User.find).toHaveBeenCalledWith({});
            expect(res.json).toHaveBeenCalledWith(mockUsers);
        });

        test('500 – returns server error when find fails', async () => {
            User.find.mockReturnValue({
                select: jest.fn().mockRejectedValue(new Error('Query failed'))
            });

            const req = mockReq();
            const res = mockRes();

            await getAllUsers(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: 'Server error' }));
        });
    });

    // =========================================================================
    // 5. getProfile
    // =========================================================================
    describe('getProfile', () => {
        test('200 – returns current authenticated user profile', async () => {
            const userProfile = { _id: 'u123', name: 'John Doe', email: 'john@example.com', role: 'CITIZEN' };
            User.findById.mockReturnValue({
                select: jest.fn().mockResolvedValue(userProfile)
            });

            const req = mockReq({}, {}, {}, { id: 'u123' });
            const res = mockRes();

            await getProfile(req, res);

            expect(User.findById).toHaveBeenCalledWith('u123');
            expect(res.json).toHaveBeenCalledWith(userProfile);
        });

        test('500 – returns server error when findById fails', async () => {
            User.findById.mockReturnValue({
                select: jest.fn().mockRejectedValue(new Error('Profile retrieval failed'))
            });

            const req = mockReq({}, {}, {}, { id: 'u123' });
            const res = mockRes();

            await getProfile(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ message: 'Server error' }));
        });
    });

    // =========================================================================
    // 6. logout
    // =========================================================================
    describe('logout', () => {
        test('200 – clears authentication cookies and returns success message', async () => {
            const req = mockReq();
            const res = mockRes();

            await logout(req, res);

            expect(res.clearCookie).toHaveBeenCalledWith('token');
            expect(res.clearCookie).toHaveBeenCalledWith('refreshToken');
            expect(res.json).toHaveBeenCalledWith({ message: 'Logged out successfully' });
        });
    });

    // =========================================================================
    // 7. googleCallback
    // =========================================================================
    describe('googleCallback', () => {
        test('302 – redirects to dashboard and sets cookies on successful Google authentication', () => {
            const mockUser = { _id: 'uGoogle1', name: 'Google User', email: 'g@example.com', role: 'CITIZEN' };
            const req = mockReq({}, {}, {}, mockUser);
            const res = mockRes();

            googleCallback(req, res);

            expect(res.cookie).toHaveBeenCalledWith('token', expect.any(String), expect.any(Object));
            expect(res.cookie).toHaveBeenCalledWith('refreshToken', expect.any(String), expect.any(Object));
            expect(res.redirect).toHaveBeenCalledWith(expect.stringContaining('/dashboard?login=success'));
        });

        test('302 – redirects to failure page when req.user is absent', () => {
            const req = mockReq({}, {}, {}, null);
            const res = mockRes();

            googleCallback(req, res);

            expect(res.redirect).toHaveBeenCalledWith(expect.stringContaining('/login?error=GoogleAuthFailed'));
        });
    });

    // =========================================================================
    // 8. facebookLogin
    // =========================================================================
    describe('facebookLogin', () => {
        test('400 – rejects request if accessToken or userID is missing', async () => {
            const req = mockReq({ accessToken: 'fb_token' });
            const res = mockRes();

            await facebookLogin(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Missing Facebook token or userID' });
        });

        test('400 – rejects if Facebook verification returned mismatched userID', async () => {
            axios.get.mockResolvedValue({
                data: { id: 'fb_9999', name: 'FB User', email: 'fb@example.com' }
            });

            const req = mockReq({ accessToken: 'valid_token', userID: 'fb_1111' });
            const res = mockRes();

            await facebookLogin(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ message: 'Invalid Facebook token for this user' });
        });

        test('200 – logs in existing user matching Facebook email and links facebookId', async () => {
            axios.get.mockResolvedValue({
                data: { id: 'fb_123', name: 'Existing User', email: 'user@example.com' }
            });

            const existingUser = {
                _id: 'uExisting',
                name: 'Existing User',
                email: 'user@example.com',
                role: 'CITIZEN',
                facebookId: null,
                save: jest.fn().mockResolvedValue(true)
            };
            User.findOne.mockResolvedValue(existingUser);

            const req = mockReq({ accessToken: 'valid_token', userID: 'fb_123' });
            const res = mockRes();

            await facebookLogin(req, res);

            expect(existingUser.facebookId).toBe('fb_123');
            expect(existingUser.save).toHaveBeenCalled();
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                token: expect.any(String),
                user: expect.objectContaining({ email: 'user@example.com' })
            }));
        });

        test('200 – creates new user when user does not exist with email or facebookId', async () => {
            axios.get.mockResolvedValue({
                data: { id: 'fb_456', name: 'Brand New User', email: 'brandnew@example.com' }
            });

            User.findOne.mockResolvedValue(null);
            User.create.mockResolvedValue({
                _id: 'uNew',
                name: 'Brand New User',
                email: 'brandnew@example.com',
                role: 'CITIZEN'
            });

            const req = mockReq({ accessToken: 'valid_token', userID: 'fb_456' });
            const res = mockRes();

            await facebookLogin(req, res);

            expect(User.create).toHaveBeenCalledWith(expect.objectContaining({
                name: 'Brand New User',
                email: 'brandnew@example.com',
                facebookId: 'fb_456'
            }));
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                token: expect.any(String),
                user: expect.objectContaining({ id: 'uNew' })
            }));
        });

        test('500 – handles Facebook API errors', async () => {
            axios.get.mockRejectedValue({
                response: { data: { error: { message: 'Invalid OAuth access token' } } }
            });

            const req = mockReq({ accessToken: 'bad_token', userID: 'fb_123' });
            const res = mockRes();

            await facebookLogin(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
                message: 'Facebook login failed',
                error: 'Invalid OAuth access token'
            }));
        });
    });
});
