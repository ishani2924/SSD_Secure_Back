const User = require('../models/User');
const jwt = require('jsonwebtoken');
const axios = require('axios');

// Generate JWT Token (1 hour expiry - security fix)
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Generate refresh token (7 days)
const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET, { expiresIn: '7d' });
};

// Helper: set auth cookies
const setAuthCookies = (res, token, refreshToken) => {
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',  // 'lax' required for OAuth redirect flows (strict blocks cross-site top-level nav)
        maxAge: 3600000 // 1 hour
    });
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',  // 'lax' required for OAuth redirect flows
        maxAge: 604800000 // 7 days
    });
};

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
    // An object such as { "$gt": "" } is a MongoDB operator, not a credential.
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const phone = typeof req.body?.phone === 'string' ? req.body.phone.trim() : undefined;
    const { location } = req.body || {};
    try {
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
                locationPayload = { type: 'Point', coordinates: [lng, lat] };
            }
        }

        user = await User.create({ name, email, password, phone, location: locationPayload });

        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);
        setAuthCookies(res, token, refreshToken);

        res.status(201).json({
            user: { id: user._id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
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

        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);
        setAuthCookies(res, token, refreshToken);

        res.json({
            user: { id: user._id, name: user.name, email: user.email, role: user.role }
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
        const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password');
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

// @desc    Logout user
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

// ============================================================
// [NEW FEATURE] Google OAuth Callback
// @desc    Called by Google after user authorises WildSafe.
//          Sets JWT cookies and redirects user to the dashboard.
// @route   GET /api/auth/google/callback
// @access  Public (called by Google)
// ============================================================
exports.googleCallback = (req, res) => {
    try {
        const user = req.user;
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

        if (!user) {
            return res.redirect(frontendUrl + '/login?error=GoogleAuthFailed');
        }

        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);
        setAuthCookies(res, token, refreshToken);

        // Redirect user to dashboard on successful Google login
        res.redirect(frontendUrl + '/dashboard?login=success');
    } catch (err) {
        console.error('Google Callback Error:', err);
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
        res.redirect(frontendUrl + '/login?error=ServerError');
    }
};

// @desc    Facebook Login
// @route   POST /api/auth/facebook
// @access  Public
exports.facebookLogin = async (req, res) => {
    const { accessToken, userID } = req.body;
    try {
        if (!accessToken || !userID) {
            return res.status(400).json({ message: 'Missing Facebook token or userID' });
        }
        
        // Verify token with Facebook
        const { data } = await axios.get(`https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`);
        
        if (data.id !== userID) {
            return res.status(400).json({ message: 'Invalid Facebook token for this user' });
        }
        
        let user;
        if (data.email) {
            user = await User.findOne({ email: data.email });
        }
        
        if (!user) {
            user = await User.findOne({ facebookId: data.id });
        }
        
        if (!user) {
            user = await User.create({
                name: data.name || 'Facebook User',
                email: data.email || `${data.id}@facebook.local`,
                facebookId: data.id,
                // password is not required and will be empty
            });
        } else if (!user.facebookId) {
            // Link facebook to existing user
            user.facebookId = data.id;
            await user.save();
        }
        
        res.json({
            token: generateToken(user._id),
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Facebook login error:', err.response?.data || err.message);
        const errorDetail = err.response?.data?.error?.message || err.message;
        res.status(500).json({ message: 'Facebook login failed', error: errorDetail });
    }
};
