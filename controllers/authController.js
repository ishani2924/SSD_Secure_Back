const User = require('../models/User');
const { getJwtOptions, signAccessToken, signRefreshToken } = require('../config/jwt');

/**
 * [SECURITY FIX — Vulnerability 6] FIXED: Tokens issued as httpOnly, Secure (prod), SameSite cookies —
 * not returned in JSON or URL redirects, reducing leakage and XSS token theft.
 *
 * [SECURITY FIX — Vulnerability 8] FIXED: Signing uses config/jwt.js (env secrets, JWT_EXPIRES_IN / JWT_REFRESH_EXPIRES_IN).
 */

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
    const { name, email, password, phone, location } = req.body;

    try {
        // Basic input validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email and password are required' });
        }
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        let locationPayload;
        if (
            location &&
            location.type === 'Point' &&
            Array.isArray(location.coordinates) &&
            location.coordinates.length === 2
        ) {
            const [lng, lat] = location.coordinates;
            if (
                Number.isFinite(lng) &&
                Number.isFinite(lat) &&
                lat >= -90 && lat <= 90 &&
                lng >= -180 && lng <= 180
            ) {
                locationPayload = {
                    type: 'Point',
                    coordinates: [lng, lat]
                };
            }
        }

        user = await User.create({
            name,
            email,
            password,
            phone,
            location: locationPayload
        });

        const jwtOptions = getJwtOptions();
        const token = signAccessToken(user._id);
        const refreshToken = signRefreshToken(user._id);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: jwtOptions.accessCookieMaxAge
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: jwtOptions.refreshCookieMaxAge
        });

        res.status(201).json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Authenticate user & get token
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const jwtOptions = getJwtOptions();
        const token = signAccessToken(user._id);
        const refreshToken = signRefreshToken(user._id);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: jwtOptions.accessCookieMaxAge
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: jwtOptions.refreshCookieMaxAge
        });

        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Update user role
// @route   PUT /api/auth/users/:id/role
// @access  Private/ADMIN
exports.updateRole = async (req, res) => {
    const { role } = req.body;
    const validRoles = ['CITIZEN', 'OFFICER', 'ADMIN'];

    if (!role || !validRoles.includes(role)) {
        return res.status(400).json({ message: `Role must be one of: ${validRoles.join(', ')}` });
    }

    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { role },
            { new: true }
        ).select('-password');

        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ message: 'Role updated successfully', user });
    } catch (err) {
        console.error('UpdateRole error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Get all users
// @route   GET /api/auth/users
// @access  Private/ADMIN
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json(users);
    } catch (err) {
        console.error('GetAllUsers error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Get user profile
// @route   GET /api/auth/profile
// @access  Private
exports.getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error('GetProfile error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Logout user / clear cookie
// @route   POST /api/auth/logout
// @access  Private
exports.logout = async (req, res) => {
    try {
        res.clearCookie('token');
        res.clearCookie('refreshToken');
        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};
