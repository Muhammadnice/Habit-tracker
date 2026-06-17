const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_habit_key_123';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/habit_tracker';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(MONGODB_URI)
    .then(() => console.log('Successfully connected to secure cloud database.'))
    .catch(err => console.error('Database connection error:', err.message));

// Define User Schema — now includes security question/answer so password
// recovery works from ANY device, not just the one used to register.
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    securityQuestion: { type: String, default: '' },
    securityAnswer: { type: String, default: '' } // stored lowercase for case-insensitive match
});
const User = mongoose.model('User', userSchema);

const trackerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    data: { type: Object, default: {} }
});
const Tracker = mongoose.model('Tracker', trackerSchema);

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

// Auth Endpoint: Register — now also saves the security question/answer to MongoDB
app.post('/api/auth/register', async (req, res) => {
    const { username, password, securityQuestion, securityAnswer } = req.body;
    if (!username || !password || !securityQuestion || !securityAnswer) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Username already taken.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            password: hashedPassword,
            securityQuestion,
            securityAnswer: securityAnswer.toLowerCase().trim()
        });
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

// Recovery Endpoint: Get a user's security question (step 1 of "forgot password")
// Only returns the QUESTION, never the answer.
app.post('/api/auth/recovery-question', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required.' });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found.' });
        if (!user.securityQuestion) return res.status(400).json({ error: 'No recovery question set for this account.' });

        res.json({ question: user.securityQuestion });
    } catch (e) {
        res.status(500).json({ error: 'Server error fetching recovery question.' });
    }
});

// Recovery Endpoint: Verify answer + reset password in one step (step 2)
app.post('/api/auth/reset-password', async (req, res) => {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: 'All fields are required.' });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found.' });

        if (user.securityAnswer !== answer.toLowerCase().trim()) {
            return res.status(400).json({ error: 'Incorrect security answer.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.json({ message: 'Password reset successfully.' });
    } catch (e) {
        res.status(500).json({ error: 'Server error during password reset.' });
    }
});

// Profile Endpoint: Update password (and optionally username)
app.post('/api/profile/update', authenticateToken, async (req, res) => {
    const { newPassword, newUsername } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found.' });

        if (newUsername && newUsername !== user.username) {
            const taken = await User.findOne({ username: newUsername });
            if (taken) return res.status(400).json({ error: 'Username already taken.' });
            user.username = newUsername;
        }
        if (newPassword) {
            user.password = await bcrypt.hash(newPassword, 10);
        }
        await user.save();

        // Re-issue a token in case the username changed, so the client stays logged in correctly
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'Profile updated successfully.', token, username: user.username });
    } catch (e) {
        res.status(500).json({ error: 'Server error updating profile.' });
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

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running smoothly on port ${PORT}`);
});