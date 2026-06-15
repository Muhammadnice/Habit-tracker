const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_habit_key_123';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error('Database opening error:', err.message);
    else console.log('Connected to SQLite database.');
});

// Create tables safely if they don't exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tracker_data (
        user_id INTEGER PRIMARY KEY,
        data TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// Middleware to verify JWT Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. Sign in required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Session expired. Please log in again.' });
        req.user = user;
        next();
    });
};

// 1. Auth Endpoint: Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields are required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Username already taken.' });
                }
                return res.status(500).json({ error: 'Database conflict.' });
            }
            res.status(201).json({ message: 'User registered successfully!' });
        });
    } catch (e) {
        res.status(500).json({ error: 'Server error during hashing.' });
    }
});

// 2. Auth Endpoint: Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields are required.' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database reading error.' });
        if (!user) return res.status(400).json({ error: 'User not found.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password.' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, username: user.username });
    });
});

// 3. Data Endpoint: Get User Habits
app.get('/api/tracker', authenticateToken, (req, res) => {
    db.get(`SELECT data FROM tracker_data WHERE user_id = ?`, [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Error fetching data.' });
        res.json({ data: row ? JSON.parse(row.data) : {} });
    });
});

// 4. Data Endpoint: Save User Habits
app.post('/api/tracker', authenticateToken, (req, res) => {
    const trackerData = JSON.stringify(req.body.data || {});
    db.run(`INSERT INTO tracker_data (user_id, data) VALUES (?, ?) 
            ON CONFLICT(user_id) DO UPDATE SET data = excluded.data`, 
            [req.user.id, trackerData], (err) => {
        if (err) return res.status(500).json({ error: 'Error saving data.' });
        res.json({ message: 'Progress autosaved successfully!' });
    });
});

// Fallback to serving frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server performance active on port ${PORT}`);
});