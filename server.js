// Load environment variables from .env file
require('dotenv').config();
// Import Node.js/Express ecosystem
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit'); // For brute-force protection
const helmet = require('helmet'); // For HTTP header hardening
const csurf = require('csurf'); // For CSRF protection

// Initialize the Express application
const app = express();
// Use helmet to set various secure HTTP headers
app.use(helmet());

// Load secrets from environment variables
const SECRET = process.env.JWT_SECRET || 'changeme_in_env_file';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'changeme_refresh_in_env_file';

// Limit login attempts to prevent brute force
app.use('/api/login', rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // max 10 requests per window
    message: { message: 'Too many login attempts, try again later.' }
}));

// Setup middleware for parsing JSON, form data, and cookies
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Setup CSRF protection for all POST/PUT/DELETE routes (use double-submit for AJAX)
app.use(csurf({ cookie: true }));

// User data (replace with a real DB in production)
const USERS_FILE = path.join(__dirname, 'users.json');

// Helper: Load users from file
function readUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

// Helper: Save users to file
function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Helper: Generate JWT Access Token
function generateAccessToken(user) {
    // Short-lived access token
    return jwt.sign({ username: user.username, role: user.role, tokenVersion: user.tokenVersion || 0 }, SECRET, {
        expiresIn: '15m'
    });
}

// Helper: Generate JWT Refresh Token
function generateRefreshToken(user) {
    // Long-lived refresh token
    return jwt.sign({ username: user.username, tokenVersion: user.tokenVersion || 0 }, REFRESH_SECRET, {
        expiresIn: '7d'
    });
}

// Helper: Validate user input (basic, for demo only)
function validateInput(username, password) {
    return typeof username === 'string' && username.length >= 3 &&
           typeof password === 'string' && password.length >= 6;
}

// --- SIGNUP ---

app.post('/api/signup', (req, res) => {
    const { username, password } = req.body;
    if (!validateInput(username, password)) {
        return res.status(400).json({ message: 'Invalid username or password format.' });
    }
    const users = readUsers();
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ message: 'User exists' });
    }
    // Hash password with bcrypt
    bcrypt.hash(password, 12, (err, hashed) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        // Store role and tokenVersion for future revocation
        users.push({ username, password: hashed, role: 'user', tokenVersion: 0, isVerified: false });
        writeUsers(users);
        // Simulate email verification (skip actual email for demo)
        res.status(201).json({ message: 'User created. (Verification simulated.)' });
    });
});

// --- LOGIN ---

app.post('/api/login', (req, res) => {
    const { username, password, remember } = req.body;
    const users = readUsers();
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    // If email verification is required, check isVerified
    // if (!user.isVerified) return res.status(403).json({ message: 'Email not verified' });
    // Validate password with bcrypt
    bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err || !isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        // Generate tokens
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // Set tokens as cookies (secure, httpOnly, SameSite)
        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: remember ? 604800000 : 900000 // 7d or 15min
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 604800000 // 7d
        });
        res.json({ message: 'Logged in', csrfToken: req.csrfToken() }); // Send CSRF token for AJAX forms
    });
});

// --- REFRESH TOKEN ---

app.post('/api/refresh', (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ message: 'Missing refresh token' });
    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });
        const users = readUsers();
        const user = users.find(u => u.username === decoded.username);
        // Token version check to support revocation
        if (!user || user.tokenVersion !== decoded.tokenVersion) {
            return res.status(403).json({ message: 'Invalid session' });
        }
        // Generate new access token
        const accessToken = generateAccessToken(user);
        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 900000 // 15min
        });
        res.json({ message: 'Token refreshed' });
    });
});

// --- LOGOUT ---

app.post('/api/logout', (req, res) => {
    // Clear auth cookies
    res.clearCookie('token');
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out' });
});

// --- AUTHENTICATION MIDDLEWARE ---

function authenticateJWT(req, res, next) {
    // Read JWT token from cookie or header
    const token = req.cookies.token || (req.headers['authorization']?.split(' ')[1]);
    if (!token) return res.status(401).json({ message: 'Missing token' });
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// --- ROLE-BASED AUTHORIZATION MIDDLEWARE ---

function authorizeRoles(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden (insufficient role)' });
        }
        next();
    };
}

// --- PROTECTED ROUTE: Dashboard (User & Admin) ---

app.get('/api/dashboard', authenticateJWT, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}!`, user: req.user });
});

// --- PROTECTED ROUTE: Admin only ---

app.get('/api/admin', authenticateJWT, authorizeRoles('admin'), (req, res) => {
    res.json({ message: 'Welcome, Admin!', user: req.user });
});

// --- PASSWORD RESET & EMAIL VERIFICATION (Not implemented, just stubs for extensibility) ---

app.post('/api/request-reset', (req, res) => {
    // TODO: Send email with secure, time-limited token (use crypto.randomBytes)
    res.json({ message: 'Password reset link sent (demo).' });
});

// --- CSRF TOKEN FOR AJAX FORMS ---

app.get('/api/csrf-token', (req, res) => {
    // Endpoint to fetch CSRF token for AJAX (since token is per-session)
    res.json({ csrfToken: req.csrfToken() });
});

// --- FALLBACK ROUTE ---

app.get('/', (req, res) => res.redirect('/login.html'));

// --- ERROR HANDLING ---

app.use((err, req, res, next) => {
    // Handle CSRF token errors specially
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ message: 'Invalid CSRF token' });
    }
    // Other errors
    res.status(500).json({ message: 'Server error', error: err.message });
});

// --- START SERVER ---

app.listen(3000, () => console.log('Server running at http://localhost:3000/'));
