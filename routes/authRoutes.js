const express = require('express');
const router = express.Router();
const { register, login, facebookLogin, getProfile, updateRole, getAllUsers } = require('../controllers/authController');
const { authMiddleware, roleMiddleware } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.post('/facebook', facebookLogin);
router.get('/profile', authMiddleware, getProfile);
router.get('/users', authMiddleware, roleMiddleware(['ADMIN']), getAllUsers);
router.put('/users/:id/role', authMiddleware, roleMiddleware(['ADMIN']), updateRole);

module.exports = router;
