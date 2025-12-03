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

const db = mysql.createConnection(dbConfig);

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        console.error('Error code:', err.code);
    } else {
        // Connected successfully
    }
});

// CORS configuration - Allow Unity WebGL origin
const allowedOrigins = [
    'https://webgl-unity-game.netlify.app',
    'http://localhost:3000', // For local testing
    'http://localhost:8080', // Common local dev port
    'http://127.0.0.1:3000',
    'http://127.0.0.1:8080'
];

const corsOptions = {
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps, Postman, or curl)
        if (!origin) {
            return callback(null, true);
        }
        
        // Normalize origin (remove trailing slash)
        const normalizedOrigin = origin.endsWith('/') ? origin.slice(0, -1) : origin;
        const normalizedAllowed = allowedOrigins.map(o => o.endsWith('/') ? o.slice(0, -1) : o);
        
        if (normalizedAllowed.includes(normalizedOrigin)) {
            callback(null, true);
        } else {
            console.error(`[CORS] Origin not allowed: ${normalizedOrigin}. Allowed: ${normalizedAllowed.join(', ')}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Required for cookies/sessions
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Session-Token', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie']
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight OPTIONS requests explicitly
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const expireTime = 1 * 60 * 60 * 1000; // expires after 1 hour (hours * minutes * seconds * millis)

const passwordPolicyRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{};':"\\|,.<>/?]).{10,}$/;

if (!sessionSecret) {
    console.error('WARNING: SESSION_SECRET or NODE_SESSION_SECRET not set in .env file');
}

if (!mongodb_user || !mongodb_password) {
    console.error('WARNING: MONGODB_USER and MONGODB_PASSWORD must be set in .env file');
}

if (!mongodb_session_secret || mongodb_session_secret.length < 32) {
    throw new Error('MONGODB_SESSION_SECRET must be set and at least 32 characters for encrypted sessions');
}

let mongoStore;
if (mongodb_user && mongodb_password) {
    // URL encode credentials to handle special characters
    const encodedUser = encodeURIComponent(mongodb_user);
    const encodedPassword = encodeURIComponent(mongodb_password);
    const mongoUrl = `mongodb+srv://${encodedUser}:${encodedPassword}@cluster0.gzq1fkp.mongodb.net/game_sessions?retryWrites=true&w=majority&appName=Cluster0`;
    
    mongoStore = MongoStore.create({
        mongoUrl: mongoUrl,
        ttl: 3600,  // Session expiration in seconds (1 hour = 3600 seconds)
        autoRemove: 'native',
        touchAfter: 24 * 3600, // lazy session update
        crypto: {
            secret: mongodb_session_secret,
        },
    });
    
    // Handle store errors
    mongoStore.on('error', (error) => {
        console.error('MongoDB session store error:', error);
    });
    
    mongoStore.on('connected', () => {});
    
    mongoStore.on('disconnected', () => {});
} else {
    console.warn('MongoDB session store not initialized - missing credentials');
}

// Determine if we're using HTTPS
const isProduction = process.env.NODE_ENV === 'production' || process.env.PORT;
const isSecure = process.env.SECURE_COOKIES === 'true' || isProduction;

app.use(session({ 
    name: 'session', // Cookie name (default is 'connect.sid')
    secret: sessionSecret || 'fallback-secret-change-in-production',
    store: mongoStore,
    saveUninitialized: false, 
    resave: false,
    cookie: {
        maxAge: expireTime,
        httpOnly: true, // Keep httpOnly for security
        secure: isSecure, // true for HTTPS, false for HTTP (development)
        sameSite: isSecure ? 'none' : 'lax' // 'none' requires secure: true for cross-origin
    }
}));

// Helper function to set CORS headers
const setCorsHeaders = (req, res) => {
    const origin = req.headers.origin;
    
    if (origin) {
        // Normalize origin (remove trailing slash)
        const normalizedOrigin = origin.endsWith('/') ? origin.slice(0, -1) : origin;
        const normalizedAllowed = allowedOrigins.map(o => o.endsWith('/') ? o.slice(0, -1) : o);
        
        // CRITICAL: Cannot use '*' with credentials: true - must use actual origin
        if (normalizedAllowed.includes(normalizedOrigin)) {
            res.header('Access-Control-Allow-Origin', origin); // Use original origin, not normalized
            res.header('Access-Control-Allow-Credentials', 'true');
            res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Session-Token, X-Requested-With');
        }
    } else {
        // No origin header (like Postman, curl) - allow but don't set credentials
        res.header('Access-Control-Allow-Origin', '*');
    }
};

// Session validation middleware - supports both cookie and token auth
const requireSession = (req, res, next) => {
    // Check for session cookie first
    if (req.session && req.session.user) {
        return next();
    }
    
    // Check for token in Authorization header (fallback for Unity WebGL)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        let token = authHeader.replace('Bearer ', '').trim();
        
        // Validate token by looking up session in MongoDB
        if (!mongoStore) {
            console.error('MongoDB store not available for token validation');
            setCorsHeaders(req, res);
            return res.status(500).json({ 
                success: false, 
                message: 'Server configuration error',
                code: 'SERVER_ERROR'
            });
        }
        
        // Set timeout for MongoDB lookup (5 seconds)
        let responded = false;
        const timeout = setTimeout(() => {
            if (!responded) {
                responded = true;
                console.error('MongoDB session lookup timeout for token');
                setCorsHeaders(req, res);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Session lookup timeout',
                    code: 'TIMEOUT'
                });
            }
        }, 5000);
        
        // Try lookup with token as-is first
        mongoStore.get(token, (err, sessionData) => {
            if (responded) return;
            clearTimeout(timeout);
            
            if (err) {
                responded = true;
                console.error('MongoDB session lookup error:', err);
                setCorsHeaders(req, res);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Session lookup error',
                    code: 'SESSION_ERROR'
                });
            }
            
            // If found, restore session properly
            if (sessionData && sessionData.user) {
                responded = true;
                // Set session ID
                req.sessionID = token;
                // Re-create the session using express-session helper to preserve prototype
                req.session = req.sessionStore.createSession(req, sessionData);
                return next();
            }
            
            // Try with 's:' prefix (express-session format)
            const prefixedToken = 's:' + token;
            mongoStore.get(prefixedToken, (err2, sessionData2) => {
                if (responded) return;
                responded = true;
                
                if (err2) {
                    console.error('MongoDB session lookup error (prefixed):', err2);
                    setCorsHeaders(req, res);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Session lookup error',
                        code: 'SESSION_ERROR'
                    });
                }
                
                if (sessionData2 && sessionData2.user) {
                    // Set session ID
                    req.sessionID = prefixedToken;
                    // Re-create the session using express-session helper to preserve prototype
                    req.session = req.sessionStore.createSession(req, sessionData2);
                    return next();
                }
                
                // Not found in either format
                setCorsHeaders(req, res);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Session required. Please log in.',
                    code: 'SESSION_REQUIRED'
                });
            });
        });
    } else {
        setCorsHeaders(req, res);
        return res.status(401).json({ 
            success: false, 
            message: 'Session required. Please log in.',
            code: 'SESSION_REQUIRED'
        });
    }
};

// Basic route
app.get('/', (req, res) => {
    res.json({ message: 'Server is running!' });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});



// Signup endpoint
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    if (password.length < 10) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password must be at least 10 characters long and include upper/lower case letters, numbers, and symbols.' 
        });
    }

    if (!passwordPolicyRegex.test(password)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password must include uppercase, lowercase, numeric, and symbol characters.' 
        });
    }

    // Check if username already exists
    const checkQuery = 'SELECT * FROM user WHERE username = ?';
    db.query(checkQuery, [username], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(409).json({ success: false, message: 'Username already exists' });
        }

        // Hash password
        const saltRounds = 12;
        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Insert new user into database
            const insertQuery = 'INSERT INTO user (username, password, level, user_type_id) VALUES (?, ?, 0, 1)';
            db.query(insertQuery, [username, hashedPassword], async (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ success: false, message: 'Database error' });
                }

                const newUserId = results.insertId;

                // Fetch the created user
                const getUserQuery = 'SELECT * FROM user WHERE user_id = ?';
                db.query(getUserQuery, [newUserId], async (err, userResults) => {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ success: false, message: 'Database error' });
                    }

                    const user = userResults[0];

                    // Create session
                    req.session.user = {
                        user_id: user.user_id,
                        username: user.username
                    };
                    req.session.cookie.maxAge = expireTime;

                    // Save session and handle errors
                    req.session.save((err) => {
                        if (err) {
                            console.error('Session save error:', err);
                            return res.status(500).json({ success: false, message: 'Session error' });
                        }

                        // Get session ID - handle express-session format
                        let sessionToken = req.sessionID;
                        // Remove 's:' prefix if present
                        if (sessionToken && sessionToken.startsWith('s:')) {
                            sessionToken = sessionToken.substring(2);
                        }
                        // URL decode if needed
                        try {
                            sessionToken = decodeURIComponent(sessionToken);
                        } catch (e) {
                            // If decode fails, use original
                        }

                        res.status(201).json({
                            success: true,
                            message: 'Account created successfully',
                            user: user,
                            sessionToken: sessionToken // Add token for Unity to use
                        });
                    });
                });
            });
        } catch (hashError) {
            console.error('Password hashing error:', hashError);
            return res.status(500).json({ success: false, message: 'Error creating account' });
        }
    });
});

// Login endpoint
app.post('/api/login', (req, res) => {
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
        // Compare provided password with hashed password in database
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (passwordMatch) {
            // Create session
            req.session.user = {
                user_id: user.user_id || user.id,
                username: user.username
            };
            req.session.cookie.maxAge = expireTime;
            
            // Save session and handle errors
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    return res.status(500).json({ success: false, message: 'Session error' });
                }
                // Get session ID - express-session may prefix with 's:' which gets URL encoded
                let sessionToken = req.sessionID;
                // Remove 's:' prefix if present (express-session default)
                if (sessionToken && sessionToken.startsWith('s:')) {
                    sessionToken = sessionToken.substring(2);
                }
                // URL decode if needed
                try {
                    sessionToken = decodeURIComponent(sessionToken);
                } catch (e) {
                    // If decode fails, use original
                }
                // Return session token for Unity WebGL (cookie may not work)
                res.json({ 
                    success: true, 
                    message: 'Login successful', 
                    user: user,
                    sessionToken: sessionToken // Add token for Unity to use
                });
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid username or password' });
        }
    });
});

// Logout endpoint
app.post('/api/logout', requireSession, (req, res) => {
    const sessionId = req.sessionID;

    const finish = () => {
        res.clearCookie('session');
        setCorsHeaders(req, res);
        res.json({ success: true, message: 'Logout successful' });
    };

    const destroyInStore = (nextStep) => {
        if (mongoStore && sessionId) {
            mongoStore.destroy(sessionId, (storeErr) => {
                if (storeErr) {
                    console.error('Mongo store destroy error:', storeErr);
                    // fall through; even if store delete fails we continue
                }
                nextStep();
            });
        } else {
            nextStep();
        }
    };

    if (req.session && typeof req.session.destroy === 'function') {
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
                setCorsHeaders(req, res);
                return res.status(500).json({ success: false, message: 'Logout error' });
            }
            destroyInStore(finish);
        });
    } else if (sessionId) {
        destroyInStore(finish);
    } else {
        finish();
    }
});

// Get current session info
app.get('/api/session', requireSession, (req, res) => {
    res.json({ 
        success: true, 
        user: req.session.user,
        sessionId: req.sessionID
    });
});

// Get user endpoint - returns user data for session validation
app.post('/api/get-user', requireSession, (req, res) => {
    const { user_id, username } = req.body;
    const sessionUserId = req.session.user.user_id;
    const sessionUsername = req.session.user.username;

    // Use session user_id for security (user can only get their own data)
    const targetUserId = user_id ? parseInt(user_id) : sessionUserId;
    const targetUsername = username || sessionUsername;

    // Security check: ensure user can only access their own data
    if (targetUserId && targetUserId !== sessionUserId) {
        setCorsHeaders(req, res);
        return res.status(403).json({ 
            success: false, 
            message: 'Access denied. You can only access your own user data.',
            code: 'ACCESS_DENIED'
        });
    }

    // Query database for user
    const query = targetUserId 
        ? 'SELECT user_id, username, level, user_type_id, profile_image_url FROM user WHERE user_id = ?'
        : 'SELECT user_id, username, level, user_type_id, profile_image_url FROM user WHERE username = ?';
    const param = targetUserId || targetUsername;

    db.query(query, [param], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            setCorsHeaders(req, res);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            setCorsHeaders(req, res);
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const user = results[0];

        // Verify the user matches the session
        if (user.user_id !== sessionUserId) {
            setCorsHeaders(req, res);
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. You can only access your own user data.',
                code: 'ACCESS_DENIED'
            });
        }

        // Success response - CORS headers should be set by middleware, but ensure they're there
        setCorsHeaders(req, res);
        res.json({ 
            success: true, 
            user: {
                user_id: user.user_id,
                username: user.username,
                level: user.level,
                user_type_id: user.user_type_id,
                profile_image_url: user.profile_image_url
            }
        });
    });
});

// Game endpoint - retrieves level from user table
app.post('/api/game', requireSession, (req, res) => {
    // Use session user_id to ensure user can only access their own game data
    const user_id = req.session.user.user_id;

    if (!user_id) {
        return res.status(400).json({ success: false, message: 'User ID required' });
    }

    // Query database for user's level
    const query = 'SELECT level FROM user WHERE user_id = ?';

    db.query(query, [user_id], (err, results) => {
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
app.post('/api/increment-level', requireSession, (req, res) => {
    // Use session user_id to ensure user can only increment their own level
    const user_id = req.session.user.user_id;

    // Update user's level by incrementing by 1
    const query = 'UPDATE user SET level = level + 1 WHERE user_id = ?';

    db.query(query, [user_id], (err, results) => {
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

app.post('/api/reset-level', requireSession, (req, res) => {
    // Use session user_id to ensure user can only reset their own level
    const user_id = req.session.user.user_id;
    const query = 'UPDATE user SET level = 1 WHERE user_id = ?';
    db.query(query, [user_id], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, message: 'Level reset successfully' });
    });
});

// Error handling middleware - ensure CORS headers are always sent
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    
    // Handle CORS errors specifically
    if (err.message && err.message.includes('CORS')) {
        console.error('[CORS Error]', err.message);
        const origin = req.headers.origin;
        if (origin && allowedOrigins.includes(origin)) {
            // If origin is actually allowed, set headers anyway
            res.header('Access-Control-Allow-Origin', origin);
            res.header('Access-Control-Allow-Credentials', 'true');
            res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Session-Token, X-Requested-With');
        }
        return res.status(403).json({ 
            success: false, 
            message: 'CORS policy violation',
            code: 'CORS_ERROR',
            origin: origin
        });
    }
    
    // Ensure CORS headers are set even on other errors
    setCorsHeaders(req, res);
    
    res.status(err.status || 500).json({ 
        success: false, 
        message: err.message || 'Internal server error',
        code: 'INTERNAL_ERROR'
    });
});


// Start server
app.listen(PORT, () => {});

