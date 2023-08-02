const express = require('express');
const router = express.Router();
const authService = require('../../services/authenticationServices')

// no need token
router.post('/login', authService.login);
router.post('/register', authService.register);

// need token
router.get('/me', authService.tokenChecker, authService.detailUser);

module.exports = router;
