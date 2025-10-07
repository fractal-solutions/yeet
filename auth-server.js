const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey'; // Use environment variable for production
const TOKEN_EXPIRATION = '1h';

// --- User Management Functions ---
const readUsers = () => {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify({}), 'utf8');
    }
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
};

const writeUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
};

const findUser = (username) => {
    const users = readUsers();
    return users[username];
};

const addUser = async (username, password) => {
    const users = readUsers();
    if (users[username]) {
        return { success: false, message: 'User already exists' };
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    writeUsers(users);
    return { success: true, message: 'User created successfully' };
};

// --- Express App Setup ---
const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// Serve static auth UI files
app.use(express.static(path.join(__dirname, 'auth-ui')));

// --- Routes ---

// Login Page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth-ui', 'login.html'));
});

// Signup Page
app.get('/signup', (req, res) => {
    // Check for --no-signup flag
    const noSignup = process.argv.includes('--no-signup');
    if (noSignup) {
        return res.status(404).send('Signup is disabled.');
    }
    res.sendFile(path.join(SHARE_DIR, 'auth-ui', 'signup.html'));
});

// Login API
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = findUser(username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ message: 'Logged in successfully' });
});

// Signup API
app.post('/signup', async (req, res) => {
    const noSignup = process.argv.includes('--no-signup');
    if (noSignup) {
        return res.status(403).json({ message: 'Signup is disabled.' });
    }

    const { username, password } = req.body;
    const result = await addUser(username, password);

    if (!result.success) {
        return res.status(409).json({ message: result.message });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ message: 'Signed up and logged in successfully' });
});

// Logout API
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// Auth Check API (for Zig server to verify token)
app.get('/auth/check', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ authenticated: false, message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ authenticated: false, message: 'Invalid token' });
        }
        res.json({ authenticated: true, username: decoded.username });
    });
});

// Admin User Creation API (for TUI)
app.post('/admin/users', async (req, res) => {
    // This endpoint should ideally be protected by an admin token/session
    // For now, assuming TUI has direct access or a separate admin login
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const result = await addUser(username, password);
    if (!result.success) {
        return res.status(409).json({ message: result.message });
    }
    res.status(201).json({ message: 'User created successfully', username });
});

// --- Server Start ---
const AUTH_SERVER_PORT_ARG_INDEX = process.argv.indexOf('--auth-server-port');
const AUTH_SERVER_PORT = AUTH_SERVER_PORT_ARG_INDEX !== -1 ? parseInt(process.argv[AUTH_SERVER_PORT_ARG_INDEX + 1], 10) : 3001;

app.listen(AUTH_SERVER_PORT, () => {
    console.log(`Auth Server running on port ${AUTH_SERVER_PORT}`);
});
