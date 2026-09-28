const express = require('express');
const router = express.Router();
const { register, login, getProfile, updateRole, getAllUsers, logout } = require('../controllers/authController');
const { authMiddleware, roleMiddleware } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiters');

router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/logout', authMiddleware, logout);
router.get('/profile', authMiddleware, getProfile);
router.get('/users', authMiddleware, roleMiddleware(['ADMIN']), getAllUsers);
router.put('/users/:id/role', authMiddleware, roleMiddleware(['ADMIN']), updateRole);

module.exports = router;
