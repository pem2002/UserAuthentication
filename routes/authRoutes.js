const express = require('express');
const authController = require('../controller/authController');
const router = express.Router();

// Root route
router.get('/', (req, res) => {
    res.render('pages/landing');
});

// Signup routes
router.get('/signup', authController.getSignUp);         
router.post('/signup', authController.postSignUp);

// Email verification
router.get('/verify-email', authController.verifyEmail);

// Login routes
router.get('/login', authController.getLogin);           
router.post('/login', authController.postLogin);

// Forgot + Reset password routes
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);
router.get('/reset-password', authController.getResetPasswordPage); 
router.post('/reset-password', authController.resetPassword);

// Logout
router.get('/logout', authController.logout);

module.exports = router;
