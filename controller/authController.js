// controller/authController.js

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const nodemailer = require('nodemailer');
require('dotenv').config();

const saltRounds = 10;

// Render the sign up page
exports.getSignUp = (req, res) => {
    res.render('pages/signup', { message: null });
};

// Render the login page
exports.getLogin = (req, res) => {
    res.render('pages/login', { message: null });
};

// Render forgot password page
exports.getForgotPassword = (req, res) => {
    res.render('pages/forgot-password', { message: null });
};

// Render reset password page
exports.getResetPasswordPage = (req, res) => {
    const token = req.query.token || '';
    res.render('pages/reset-password', { message: null, token });
};

// Email transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Handle sign up logic
exports.postSignUp = async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser) {
            return res.render('pages/signup', { message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        await db.none(
            `INSERT INTO users (name, email, password, role, verification_token) VALUES ($1, $2, $3, $4, $5)`,
            [name, email, hashedPassword, role, verificationToken]
        );

        const verificationLink = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;

        await transporter.sendMail({
            from: `"Bootcamp Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Email Verification',
            html: `<p>Hi ${name},</p>
                   <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
                   <a href="${verificationLink}">Verify Email</a>
                   <p>If you did not sign up, please ignore this email.</p>`
        });

        res.render('pages/signup', { message: 'Registration successful! Please check your email to verify your account.' });

    } catch (error) {
        console.error('Error during sign up:', error);
        res.render('pages/signup', { message: 'An error occurred during registration. Please try again.' });
    }
};

// Handle email verification
exports.verifyEmail = async (req, res) => {
    const { token } = req.query;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const email = decoded.email;
        await db.none(`UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1`, [email]);
        res.send('Email verified successfully! You can now log in.');
    } catch (error) {
        res.send('Invalid or expired verification link');
    }
};

// Handle login logic
exports.postLogin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }
        if (!user.is_verified) {
            return res.render('pages/login', { message: 'Please verify your email before logging in.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000 // 1 hour
        });

        if (user.role === 'admin') {
            res.redirect('/admin/dashboard');
        } else {
            res.redirect('/user/dashboard');
        }

    } catch (error) {
        console.error('Error during login:', error);
        res.render('pages/login', { message: 'An error occurred during login. Please try again.' });
    }
};

// Handle forgot password logic
exports.postForgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/forgot-password', { message: 'Email not registered' });
        }

        const resetToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        await db.none('UPDATE users SET reset_token = $1 WHERE email = $2', [resetToken, email]);

        const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
        await transporter.sendMail({
            from: `"Bootcamp Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset',
            html: `<p>Hi ${user.name},</p>
                   <p>You requested a password reset. Click the link below to reset your password:</p>
                   <a href="${resetLink}">Reset Password</a>
                   <p>If you did not request this, please ignore this email.</p>`
        });

        res.render('pages/forgot-password', { message: 'Password reset link sent to your email.' });

    } catch (error) {
        console.error('Error during forgot password:', error);
        res.render('pages/forgot-password', { message: 'An error occurred. Please try again.' });
    }
};

// Handle reset password logic
exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await db.oneOrNone(`SELECT * FROM users WHERE reset_token = $1`, [token]);

        if (!user) {
            return res.render('pages/reset-password', { message: 'Invalid or expired token', token });
        }

        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.none('UPDATE users SET password = $1, reset_token = NULL WHERE email = $2', [hashedPassword, user.email]);

        res.render('pages/reset-password', { message: 'Password reset successfully! You can now log in.', token: '' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.render('pages/reset-password', { message: 'Invalid or expired token', token });
    }
};

// Handle logout
exports.logout = (req, res) => {
    try {
        res.clearCookie('token');
        res.redirect('/login');
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).send('An error occurred while logging out.');
    }
};
