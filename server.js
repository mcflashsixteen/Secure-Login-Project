const express = require ('express')
const crypto = require ('crypto')
const Database = require ('better-sqlite3')
const path = require('path')


const app = express();
const port = 1738;


app.use(express.json());
app.use(express.static('public'));

const db = new Database('secure_login.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name_encrypted TEXT NOT NULL,
        phone_encrypted TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        attempt_count INTEGER DEFAULT 0,
        locked_until INTEGER,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reset_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);
    CREATE INDEX IF NOT EXISTS idx_reset_codes_email ON reset_codes(email);
`);

console.log('Database initialized');


const ENCRYPTION_KEY = crypto.scryptSync('MyPassword' , 'salt' , 32)
const IV_LENGTH = 16;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 5* 60 * 1000; 

function generateSalt(){
    return crypto.randomBytes(16).toString('hex');

}

function hashPassword(password, salt){
    return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha256').toString('hex');
}

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData) {
    try {
        const parts = encryptedData.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return '[Decryption Error]';
    }
}

function checkPassStrength(password){
    let strength =  0;
    if(password.length >= 8) strength++
    if(password.length >= 12 ) strength++
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++
    if (/[0-9]/.test(password)) strength++
    if (/[^a-zA-Z\d]/.test(password) )strength++
    return strength;
}

function checkLoginAttempts(email) {
    const stmt = db.prepare('SELECT * FROM login_attempts WHERE email = ?');
    const attempt = stmt.get(email);
    
    if (!attempt) {
        return { allowed: true };
    }
    
    if (attempt.locked_until && Date.now() < attempt.locked_until) {
        const remainingTime = Math.ceil((attempt.locked_until - Date.now()) / 1000 / 60);
        return { 
            allowed: false, 
            message: `Account locked. Try again in ${remainingTime} minutes.` 
        };
    }
    
    if (attempt.locked_until && Date.now() >= attempt.locked_until) {
        const updateStmt = db.prepare('UPDATE login_attempts SET attempt_count = 0, locked_until = NULL WHERE email = ?');
        updateStmt.run(email);
    }
    
    return { allowed: true };
}

function recordFailedLogin(email) {
    const stmt = db.prepare('SELECT * FROM login_attempts WHERE email = ?');
    let attempt = stmt.get(email);
    
    if (!attempt) {
        const insertStmt = db.prepare('INSERT INTO login_attempts (email, attempt_count) VALUES (?, 1)');
        insertStmt.run(email);
        return `Invalid credentials. ${MAX_LOGIN_ATTEMPTS - 1} attempts remaining.`;
    }
    
    const newCount = attempt.attempt_count + 1;
    
    if (newCount >= MAX_LOGIN_ATTEMPTS) {
        const lockedUntil = Date.now() + LOCKOUT_TIME;
        const updateStmt = db.prepare('UPDATE login_attempts SET attempt_count = ?, locked_until = ? WHERE email = ?');
        updateStmt.run(newCount, lockedUntil, email);
        return `Too many failed attempts. Account locked for 5 minutes.`;
    }
    
    const updateStmt = db.prepare('UPDATE login_attempts SET attempt_count = ? WHERE email = ?');
    updateStmt.run(newCount, email);
    const remaining = MAX_LOGIN_ATTEMPTS - newCount;
    return `Invalid credentials. ${remaining} attempts remaining.`;
}

function resetLoginAttempts(email) {
    const stmt = db.prepare('UPDATE login_attempts SET attempt_count = 0, locked_until = NULL WHERE email = ?');
    stmt.run(email);
}

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    const attemptCheck = checkLoginAttempts(email);
    if (!attemptCheck.allowed) {
        return res.status(429).json({ success: false, message: attemptCheck.message });
    }
    
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    const user = stmt.get(email);
    
    if (!user) {
        return res.status(401).json({ success: false, message: recordFailedLogin(email) });
    }
    
    const hashedInput = hashPassword(password, user.salt);
    
    if (hashedInput !== user.password_hash) {
        return res.status(401).json({ success: false, message: recordFailedLogin(email) });
    }
    
    resetLoginAttempts(email);
    
    res.json({ 
        success: true, 
        user: {
            name: decrypt(user.name_encrypted),
            email: user.email,
            phone: decrypt(user.phone_encrypted),
            createdAt: user.created_at
        }
    });
});

// Signup
app.post('/api/signup', (req, res) => {
    const { name, email, phone, password } = req.body;
    
    // Check if user exists
    const checkStmt = db.prepare('SELECT email FROM users WHERE email = ?');
    if (checkStmt.get(email)) {
        return res.status(400).json({ success: false, message: 'Email already registered!' });
    }
    
    // Check password strength
    if (checkPassStrength(password) < 3) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password too weak. Use 8+ chars with uppercase, lowercase, numbers, symbols.' 
        });
    }
    
    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);
    
    const insertStmt = db.prepare(`
        INSERT INTO users (email, name_encrypted, phone_encrypted, password_hash, salt) 
        VALUES (?, ?, ?, ?, ?)
    `);
    
    try {
        insertStmt.run(email, encrypt(name), encrypt(phone), hashedPassword, salt);
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error creating account.' });
    }
});

// Forgot Password
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    
    const stmt = db.prepare('SELECT email FROM users WHERE email = ?');
    if (!stmt.get(email)) {
        return res.json({ 
            success: true, 
            message: 'If this email exists, a reset code has been sent.' 
        });
    }
    
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
    
 
    const deleteStmt = db.prepare('DELETE FROM reset_codes WHERE email = ?');
    deleteStmt.run(email);
    
    const insertStmt = db.prepare('INSERT INTO reset_codes (email, code, expires_at) VALUES (?, ?, ?)');
    insertStmt.run(email, resetCode, expiresAt);
    
    res.json({ 
        success: true, 
        message: `Reset code sent! (Your Reset  Code is: ${resetCode})`,
        code: resetCode 
    });
});

// Reset Password
app.post('/api/reset-password', (req, res) => {
    const { email, code, newPassword } = req.body;
    
    const stmt = db.prepare('SELECT * FROM reset_codes WHERE email = ? AND code = ?');
    const resetCode = stmt.get(email, code);
    
    if (!resetCode) {
        return res.status(400).json({ success: false, message: 'Invalid reset code!' });
    }
    
    if (Date.now() > resetCode.expires_at) {
        const deleteStmt = db.prepare('DELETE FROM reset_codes WHERE email = ?');
        deleteStmt.run(email);
        return res.status(400).json({ success: false, message: 'Reset code expired!' });
    }
    
    if (checkPassStrength(newPassword) < 3) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password too weak.' 
        });
    }
    
    const salt = generateSalt();
    const hashedPassword = hashPassword(newPassword, salt);
    
    const updateStmt = db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE email = ?');
    updateStmt.run(hashedPassword, salt, email);
    
    const deleteStmt = db.prepare('DELETE FROM reset_codes WHERE email = ?');
    deleteStmt.run(email);
    
    resetLoginAttempts(email);
    
    res.json({ success: true, message: 'Password reset successful!' });
});

app.get('/api/stats', (req, res) => {
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const attemptCount = db.prepare('SELECT COUNT(*) as count FROM login_attempts').get();
    
    res.json({
        totalUsers: userCount.count,
        trackedAttempts: attemptCount.count,
        databaseFile: 'secure_login.db'
    });
});

// Start the jawn
const PORT = process.env.PORT || 1738;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Database: secure_login.db');
  });