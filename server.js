require('dotenv').config({ path: '.env' });
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const app = express();
const PORT = process.env.PORT || 3000;

const session = require('express-session');
const MongoStore = require('connect-mongo');

const sessionSecret = process.env.SESSION_SECRET || process.env.NODE_SESSION_SECRET;

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

// MySQL connection configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'game_db',
    connectTimeout: 10000,
    ssl: process.env.DB_HOST && process.env.DB_HOST !== 'localhost' ? {
        rejectUnauthorized: false
    } : false
};

console.log('Attempting MySQL connection to:', {
    host: dbConfig.host,
    port: dbConfig.port,
    user: dbConfig.user,
    database: dbConfig.database
});

const db = mysql.createConnection(dbConfig);

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        console.error('Error code:', err.code);
    } else {
        console.log('Connected to MySQL database');
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const expireTime = 1 * 60 * 60 * 1000; // expires after 1 hour (hours * minutes * seconds * millis)

if (!sessionSecret) {
    console.error('WARNING: SESSION_SECRET or NODE_SESSION_SECRET not set in .env file');
}

if (!mongodb_user || !mongodb_password) {
    console.error('WARNING: MONGODB_USER and MONGODB_PASSWORD must be set in .env file');
}

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.gzq1fkp.mongodb.net/game_sessions?retryWrites=true&w=majority&appName=Cluster0`,
    crypto: mongodb_session_secret ? {
        secret: mongodb_session_secret,
    } : undefined,
    ttl: 3600,  // Session expiration in seconds (1 hour = 3600 seconds)
    autoRemove: 'native', 
});

app.use(session({ 
    secret: sessionSecret || 'fallback-secret-change-in-production',
    store: mongoStore,
    saveUninitialized: false, 
    resave: false,
    cookie: {
        maxAge: expireTime,
        httpOnly: true,
        secure: false // Set to true if using HTTPS
    }
}));

// Basic route
app.get('/', (req, res) => {
    res.json({ message: 'Server is running!' });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Login endpoint
app.post('/api/login', (req, res) => {
    console.log("Got here")
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    // Query database for user by username only
    const query = 'SELECT * FROM user WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid username or password' });
        }

        const user = results[0];
        console.log(user);
        // Compare provided password with hashed password in database
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (passwordMatch) {
            // Create session
            req.session.user = {
                user_id: user.user_id || user.id,
                username: user.username
            };
            req.session.cookie.maxAge = expireTime;
            
            res.json({ 
                success: true, 
                message: 'Login successful', 
                user: user 
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid username or password' });
        }
    });
});

// Game endpoint - retrieves level from user table
app.post('/api/game', (req, res) => {
    const { username, user_id } = req.body;

    if (!username && !user_id) {
        return res.status(400).json({ success: false, message: 'Username or user_id required' });
    }

    // Query database for user's level
    const query = user_id 
        ? 'SELECT level FROM users WHERE user_id = ?'
        : 'SELECT level FROM users WHERE username = ?';
    const param = user_id || username;

    db.query(query, [param], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            res.json({ success: true, level: results[0].level });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    });
});

// Increment level endpoint
app.post('/api/increment-level', (req, res) => {
    const { username, user_id } = req.body;

    if (!username && !user_id) {
        return res.status(400).json({ success: false, message: 'Username or user_id required' });
    }

    // Update user's level by incrementing by 1
    const query = user_id 
        ? 'UPDATE user SET level = level + 1 WHERE user_id = ?'
        : 'UPDATE user SET level = level + 1 WHERE username = ?';
    const param = user_id || username;

    db.query(query, [param], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, message: 'Level incremented successfully' });
    });
});

app.post('/api/reset-level', (req, res) => {
    const { username, user_id } = req.body;
    if (!username && !user_id) {
        return res.status(400).json({ success: false, message: 'Username or user_id required' });
    }
    const query = user_id ? 'UPDATE user SET level = 0 WHERE user_id = ?' : 'UPDATE user SET level = 0 WHERE username = ?';
    const param = user_id || username;
    db.query(query, [param], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        res.json({ success: true, message: 'Level reset successfully' });
    });
});

// Example GET endpoint
app.get('/api/players', (req, res) => {
    res.json({ players: [] });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

