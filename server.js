const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_habit_key_123';

// Fallback to local memory database if MongoDB URI isn't provided yet
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/habit_tracker';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB Cloud
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Successfully connected to secure cloud database.'))
    .catch(err => console.error('Database connection error:', err.message));

// Define User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Define Tracker Data Schema
const trackerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    data: { type: Object, default: {} }
});
const Tracker = mongoose.model('Tracker', trackerSchema);

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

// Auth Endpoint: Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields are required.' });

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Username already taken.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (e) {
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Auth Endpoint: Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields are required.' });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password.' });

        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, username: user.username });
    } catch (e) {
        res.status(500).json({ error: 'Server error during login.' });
    }
});

// Data Endpoint: Get User Habits
app.get('/api/tracker', authenticateToken, async (req, res) => {
    try {
        const record = await Tracker.findOne({ userId: req.user.id });
        res.json({ data: record ? record.data : {} });
    } catch (e) {
        res.status(500).json({ error: 'Error fetching tracking metrics.' });
    }
});

// Data Endpoint: Save User Habits
app.post('/api/tracker', authenticateToken, async (req, res) => {
    try {
        const trackerData = req.body.data || {};
        await Tracker.findOneAndUpdate(
            { userId: req.user.id },
            { data: trackerData },
            { upsert: true, new: true }
        );
        res.json({ message: 'Progress autosaved securely!' });
    } catch (e) {
        res.status(500).json({ error: 'Error saving tracking data.' });
    }
});

// Fallback to serving frontend layout
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});