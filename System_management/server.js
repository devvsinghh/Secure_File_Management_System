// ═══════════════════════════════════════════════════════════
//  ZenCrypt — Backend Server
//  JWT Auth, bcrypt, SQLite, Input Validation, SQL Injection Protection
// ═══════════════════════════════════════════════════════════
//
//  To run: npm install && node server.js
//  Server starts at: http://localhost:3000
//

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const crypto = require('crypto');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const BCRYPT_ROUNDS = 12;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// ─── Ensure directories exist ───
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ═══════════════════════════════════════════════
//  DATABASE SETUP (SQLite with parameterized queries)
// ═══════════════════════════════════════════════

const db = new Database(path.join(__dirname, 'ZenCrypt.db'));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create tables with parameterized queries (SQL injection safe)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    two_factor_enabled INTEGER DEFAULT 0,
    two_factor_secret TEXT,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    encrypted INTEGER DEFAULT 1,
    encryption_iv TEXT,
    owner_id INTEGER NOT NULL,
    scan_result TEXT DEFAULT 'pending',
    threat_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS file_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    permission TEXT NOT NULL CHECK(permission IN ('read', 'write', 'admin')),
    granted_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(file_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    shared_by INTEGER NOT NULL,
    shared_with INTEGER NOT NULL,
    permission TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id),
    FOREIGN KEY (shared_with) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS threat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Prepare statements (prevents SQL injection via parameterized queries)
const stmts = {
  // User operations
  createUser: db.prepare(`INSERT INTO users (username, email, password, two_factor_enabled, two_factor_secret, role) VALUES (?, ?, ?, ?, ?, ?)`),
  findUserByUsername: db.prepare(`SELECT * FROM users WHERE username = ?`),
  findUserById: db.prepare(`SELECT id, username, email, role, two_factor_enabled, two_factor_secret, created_at FROM users WHERE id = ?`),
  findUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  updatePassword: db.prepare(`UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?`),
  update2FA: db.prepare(`UPDATE users SET two_factor_enabled = ?, two_factor_secret = ?, updated_at = datetime('now') WHERE id = ?`),

  // File operations
  createFile: db.prepare(`INSERT INTO files (id, name, original_name, size, mime_type, encrypted, encryption_iv, owner_id, scan_result, threat_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
  getFileById: db.prepare(`SELECT * FROM files WHERE id = ?`),
  getFilesByOwner: db.prepare(`SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC`),
  updateFile: db.prepare(`UPDATE files SET name = ?, size = ?, updated_at = datetime('now') WHERE id = ?`),
  deleteFile: db.prepare(`DELETE FROM files WHERE id = ? AND owner_id = ?`),

  // Permissions
  setPermission: db.prepare(`INSERT OR REPLACE INTO file_permissions (file_id, user_id, permission) VALUES (?, ?, ?)`),
  getPermission: db.prepare(`SELECT permission FROM file_permissions WHERE file_id = ? AND user_id = ?`),
  getFilePermissions: db.prepare(`SELECT fp.*, u.username FROM file_permissions fp JOIN users u ON fp.user_id = u.id WHERE fp.file_id = ?`),
  removePermission: db.prepare(`DELETE FROM file_permissions WHERE file_id = ? AND user_id = ?`),

  // Shares
  createShare: db.prepare(`INSERT INTO shares (file_id, shared_by, shared_with, permission) VALUES (?, ?, ?, ?)`),
  getSharesByUser: db.prepare(`SELECT s.*, f.original_name as file_name, u.username as shared_with_name FROM shares s JOIN files f ON s.file_id = f.id JOIN users u ON s.shared_with = u.id WHERE s.shared_by = ? ORDER BY s.created_at DESC`),
  deleteShare: db.prepare(`DELETE FROM shares WHERE file_id = ? AND shared_with = ?`),

  // Activity logs
  addLog: db.prepare(`INSERT INTO activity_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)`),
  getLogs: db.prepare(`SELECT * FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`),

  // Threat logs
  addThreat: db.prepare(`INSERT INTO threat_logs (file_name, threat_type, severity, detail, user_id) VALUES (?, ?, ?, ?, ?)`),
  getThreats: db.prepare(`SELECT * FROM threat_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`),
  getThreatStats: db.prepare(`SELECT threat_type, COUNT(*) as count FROM threat_logs WHERE user_id = ? GROUP BY threat_type`),

  // ── ADMIN-ONLY statements ──
  getAllUsers: db.prepare(`SELECT id, username, email, role, two_factor_enabled, created_at, updated_at FROM users ORDER BY created_at DESC`),
  updateUserRole: db.prepare(`UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?`),
  deleteUser: db.prepare(`DELETE FROM users WHERE id = ?`),
  getUserCount: db.prepare(`SELECT COUNT(*) as count FROM users`),
  getAllFiles: db.prepare(`SELECT f.*, u.username as owner_name FROM files f JOIN users u ON f.owner_id = u.id ORDER BY f.created_at DESC`),
  getAllLogs: db.prepare(`SELECT al.*, u.username FROM activity_logs al JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT 100`),
  getAllThreats: db.prepare(`SELECT tl.*, u.username FROM threat_logs tl JOIN users u ON tl.user_id = u.id ORDER BY tl.created_at DESC LIMIT 100`),
  deleteFileAdmin: db.prepare(`DELETE FROM files WHERE id = ?`),
};

// ═══════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts for our frontend
  crossOriginEmbedderPolicy: false,
}));

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Limit payload size (buffer overflow protection)
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html', 'css', 'js'],
}));

// ─── File upload config ───
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueName = crypto.randomUUID() + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max (buffer overflow protection)
  fileFilter: (req, file, cb) => {
    // Block dangerous executable files
    const blocked = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.ps1', '.msi'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (blocked.includes(ext)) {
      return cb(new Error(`Blocked file type: ${ext}`), false);
    }
    cb(null, true);
  }
});

// ─── JWT Authentication Middleware ───
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ─── RBAC Middleware — Restrict routes by role ───

// Role hierarchy: admin > user
const ROLE_HIERARCHY = { admin: 2, user: 1 };

/**
 * Middleware: requireRole(minRole)
 * Checks if the authenticated user has at least the specified role level.
 * Must be used AFTER authenticateToken middleware.
 *
 * Usage:
 *   app.get('/admin-route', authenticateToken, requireRole('admin'), handler)
 *   app.get('/user-route',  authenticateToken, requireRole('user'),  handler)
 */
function requireRole(minRole) {
  return (req, res, next) => {
    const userRole = req.user?.role || 'user';
    const userLevel = ROLE_HIERARCHY[userRole] || 0;
    const requiredLevel = ROLE_HIERARCHY[minRole] || 0;

    if (userLevel < requiredLevel) {
      logActivity(req.user?.id, 'access_denied', `Tried to access ${minRole}-only route: ${req.method} ${req.path}`, req.ip);
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: minRole,
        current: userRole,
      });
    }
    next();
  };
}

/**
 * Shorthand middleware: requireAdmin
 * Equivalent to requireRole('admin').
 */
function requireAdmin(req, res, next) {
  return requireRole('admin')(req, res, next);
}

// ─── Rate limiting (simple in-memory) ───
const rateLimitMap = new Map();

function rateLimit(maxRequests = 30, windowMs = 60000) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
    const requests = rateLimitMap.get(ip).filter(t => t > windowStart);
    requests.push(now);
    rateLimitMap.set(ip, requests);

    if (requests.length > maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }
    next();
  };
}

// ─── Input sanitizer (SQL injection protection) ───
function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  // Remove null bytes (buffer overflow protection)
  str = str.replace(/\0/g, '');
  // Limit length
  if (str.length > 10000) str = str.slice(0, 10000);
  return str;
}

// ─── Activity logger ───
function logActivity(userId, action, details, ip) {
  try {
    stmts.addLog.run(userId, sanitizeInput(action), sanitizeInput(details || ''), ip || '');
  } catch (e) { console.error('Log error:', e.message); }
}

// ═══════════════════════════════════════════════
//  MALWARE / THREAT DETECTION
// ═══════════════════════════════════════════════

const MALWARE_SIGS = [
  'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}$',
  'eval(base64_decode', 'document.write(unescape',
  '<script>alert(', 'cmd.exe /c', 'powershell -enc',
  'rm -rf /', 'DROP TABLE', 'UNION SELECT',
  '<?php system(', 'os.system(', 'subprocess.call',
  'Runtime.getRuntime().exec'
];

function scanFileContent(content, fileName) {
  const threats = [];
  const upper = (content || '').toUpperCase();

  for (const sig of MALWARE_SIGS) {
    if (upper.includes(sig.toUpperCase())) {
      threats.push({ type: 'malware', severity: 'critical', detail: `Signature: "${sig.slice(0, 30)}"` });
    }
  }

  // Buffer overflow patterns
  if (/(.)\1{500,}/.test(content)) {
    threats.push({ type: 'overflow', severity: 'warning', detail: 'Repeated character pattern (potential buffer overflow)' });
  }
  if (content && content.length > 10000000) {
    threats.push({ type: 'overflow', severity: 'critical', detail: 'Content exceeds safe size limit' });
  }

  // SQL injection in content
  if (/('|--|\/\*|\*\/|union\s+select|drop\s+table|insert\s+into|delete\s+from)/i.test(content)) {
    threats.push({ type: 'injection', severity: 'warning', detail: 'SQL injection pattern detected' });
  }

  // XSS
  if (/<script[\s>]|javascript:|on\w+\s*=/i.test(content)) {
    threats.push({ type: 'xss', severity: 'warning', detail: 'XSS pattern detected' });
  }

  return threats;
}

// ═══════════════════════════════════════════════
//  FILE ENCRYPTION (AES-256-CBC)
// ═══════════════════════════════════════════════

const ENCRYPTION_KEY = crypto.scryptSync(JWT_SECRET.slice(0, 32), 'ZenCrypt-salt', 32);

function encryptFile(filePath) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const input = fs.readFileSync(filePath);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  fs.writeFileSync(filePath, encrypted);
  return iv.toString('hex');
}

function decryptFile(filePath, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const encrypted = fs.readFileSync(filePath);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ═══════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════

// ── SIGNUP ──
app.post('/api/auth/signup',
  rateLimit(10, 60000), // 10 signups per minute
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 50 }).withMessage('Username: 3-50 characters')
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username: letters, numbers, underscores only'),
    body('email')
      .trim()
      .isEmail().withMessage('Valid email required')
      .normalizeEmail()
      .isLength({ max: 100 }).withMessage('Email too long'),
    body('password')
      .isLength({ min: 8, max: 128 }).withMessage('Password: 8-128 characters')
      .matches(/[A-Z]/).withMessage('Password needs an uppercase letter')
      .matches(/[0-9]/).withMessage('Password needs a number'),
    body('enable2FA')
      .optional()
      .isBoolean(),
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, email, password, enable2FA } = req.body;

    try {
      // Check if user exists (parameterized query — SQL injection safe)
      if (stmts.findUserByUsername.get(username)) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      if (stmts.findUserByEmail.get(email)) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      // Hash password with bcrypt
      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

      // Generate 2FA secret if enabled
      let tfaSecret = null;
      if (enable2FA) {
        tfaSecret = String(Math.floor(100000 + Math.random() * 900000)); // Simulated TOTP
      }

      // First user → auto-Admin, subsequent users → 'user' role
      const userCount = stmts.getUserCount.get().count;
      const assignedRole = userCount === 0 ? 'admin' : 'user';

      // Insert user (parameterized query — SQL injection safe)
      const result = stmts.createUser.run(username, email, hashedPassword, enable2FA ? 1 : 0, tfaSecret, assignedRole);

      logActivity(result.lastInsertRowid, 'signup', `New account created: ${username}`, req.ip);

      res.status(201).json({
        message: 'Account created successfully',
        tfaSecret: enable2FA ? tfaSecret : null,
      });

    } catch (err) {
      console.error('Signup error:', err);
      res.status(500).json({ error: 'Server error during registration' });
    }
  }
);

// ── LOGIN ATTEMPT LIMITER ──
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_COOLDOWN_MS = 15 * 60 * 1000; // 15 minutes

// ── LOGIN ──
app.post('/api/auth/login',
  rateLimit(20, 60000), // 20 login attempts per minute
  [
    body('username').trim().isLength({ min: 1, max: 50 }).withMessage('Username required'),
    body('password').isLength({ min: 1, max: 128 }).withMessage('Password required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, password } = req.body;

    try {
      // Check attempt limiter FIRST
      const now = Date.now();
      const attemptData = loginAttempts.get(username) || { count: 0, lockUntil: 0 };
      
      if (attemptData.lockUntil > now) {
        const remainingMinutes = Math.ceil((attemptData.lockUntil - now) / 60000);
        return res.status(423).json({ error: `Account locked due to multiple failed login attempts. Try again in ${remainingMinutes} minute(s).` });
      }

      // Find user (parameterized query — SQL injection safe)
      const user = stmts.findUserByUsername.get(username);

      if (!user) {
        // Increment attempts even for non-existent users
        attemptData.count++;
        if (attemptData.count >= MAX_LOGIN_ATTEMPTS) attemptData.lockUntil = now + LOGIN_COOLDOWN_MS;
        loginAttempts.set(username, attemptData);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Verify password with bcrypt
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        attemptData.count++;
        if (attemptData.count >= MAX_LOGIN_ATTEMPTS) attemptData.lockUntil = now + LOGIN_COOLDOWN_MS;
        loginAttempts.set(username, attemptData);
        logActivity(user.id, 'failed_login', `Failed login attempt (${attemptData.count}/${MAX_LOGIN_ATTEMPTS})`, req.ip);
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Success! Clear attempts
      loginAttempts.delete(username);

      // Check if 2FA is needed
      if (user.two_factor_enabled) {
        // Generate a temporary token for 2FA verification
        const tempToken = jwt.sign(
          { id: user.id, username: user.username, pending2FA: true },
          JWT_SECRET,
          { expiresIn: '5m' }
        );

        return res.json({
          requires2FA: true,
          tempToken,
          hint: user.two_factor_secret, // In production, this would be sent via SMS/Authenticator
        });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      logActivity(user.id, 'login', 'Successful login', req.ip);

      res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, username: user.username, email: user.email, role: user.role, twoFactor: !!user.two_factor_enabled, createdAt: user.created_at },
      });

    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Server error during login' });
    }
  }
);

// ── VERIFY 2FA ──
app.post('/api/auth/verify-2fa',
  rateLimit(10, 60000),
  [
    body('tempToken').isString().notEmpty(),
    body('code').isString().isLength({ min: 6, max: 6 }).withMessage('6-digit code required'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { tempToken, code } = req.body;

    try {
      const decoded = jwt.verify(tempToken, JWT_SECRET);
      if (!decoded.pending2FA) {
        return res.status(400).json({ error: 'Invalid verification request' });
      }

      const user = stmts.findUserById.get(decoded.id);
      if (!user || user.two_factor_secret !== code) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }

      // Issue full JWT
      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      logActivity(user.id, 'login', 'Successful login with 2FA', req.ip);

      res.json({
        message: 'Verification successful',
        token,
        user: { id: user.id, username: user.username, email: user.email, role: user.role, twoFactor: true, createdAt: user.created_at },
      });
    } catch (err) {
      res.status(403).json({ error: 'Invalid or expired verification token' });
    }
  }
);

// ── CHANGE PASSWORD ──
app.post('/api/auth/change-password',
  authenticateToken,
  [
    body('currentPassword').isLength({ min: 1, max: 128 }),
    body('newPassword').isLength({ min: 8, max: 128 }).withMessage('New password: 8-128 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { currentPassword, newPassword } = req.body;

    try {
      const user = stmts.findUserByUsername.get(req.user.username);
      const valid = await bcrypt.compare(currentPassword, user.password);
      if (!valid) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
      stmts.updatePassword.run(hashed, req.user.id);
      logActivity(req.user.id, 'password_change', 'Password updated', req.ip);

      res.json({ message: 'Password updated successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ── TOGGLE 2FA ──
app.post('/api/auth/toggle-2fa', authenticateToken, (req, res) => {
  const user = stmts.findUserById.get(req.user.id);
  const enabled = !user.two_factor_enabled;
  const secret = enabled ? String(Math.floor(100000 + Math.random() * 900000)) : null;

  stmts.update2FA.run(enabled ? 1 : 0, secret, req.user.id);
  logActivity(req.user.id, '2fa_toggle', enabled ? 'Enabled 2FA' : 'Disabled 2FA', req.ip);

  res.json({ enabled, secret, message: enabled ? '2FA enabled' : '2FA disabled' });
});

// ── GET PROFILE ──
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  const user = stmts.findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const files = stmts.getFilesByOwner.all(req.user.id);
  const shares = stmts.getSharesByUser.all(req.user.id);
  const threatStats = stmts.getThreatStats.all(req.user.id);
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  res.json({
    user,
    stats: {
      totalFiles: files.length,
      encrypted: files.filter(f => f.encrypted).length,
      shared: shares.length,
      threats: threatStats.reduce((s, t) => s + t.count, 0),
      totalSize,
    }
  });
});

// ═══════════════════════════════════════════════
//  FILE ROUTES
// ═══════════════════════════════════════════════

// ── UPLOAD FILE ──
app.post('/api/files/upload',
  authenticateToken,
  upload.single('file'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
      // Read file content for scanning
      const content = fs.readFileSync(req.file.path, 'utf8').slice(0, 1000000); // Scan first 1MB
      const threats = scanFileContent(content, req.file.originalname);

      // Log threats
      threats.forEach(t => {
        stmts.addThreat.run(req.file.originalname, t.type, t.severity, t.detail, req.user.id);
      });

      // Block critical threats
      if (threats.some(t => t.severity === 'critical')) {
        fs.unlinkSync(req.file.path); // Delete the file
        logActivity(req.user.id, 'upload_blocked', `Blocked: ${req.file.originalname}`, req.ip);
        return res.status(400).json({ error: 'File blocked — malware detected', threats });
      }

      // Encrypt file
      const iv = encryptFile(req.file.path);
      const fileId = crypto.randomUUID();

      stmts.createFile.run(
        fileId, req.file.filename, req.file.originalname,
        req.file.size, req.file.mimetype,
        1, iv, req.user.id,
        threats.length > 0 ? 'warnings' : 'clean', threats.length
      );

      // Set owner permission
      stmts.setPermission.run(fileId, req.user.id, 'admin');
      logActivity(req.user.id, 'upload', `Uploaded: ${req.file.originalname}`, req.ip);

      res.status(201).json({
        message: 'File uploaded securely',
        file: { id: fileId, name: req.file.originalname, size: req.file.size },
        threats,
        scanResult: threats.length > 0 ? 'warnings' : 'clean',
      });
    } catch (err) {
      console.error('Upload error:', err);
      res.status(500).json({ error: 'Upload failed' });
    }
  }
);

// ── LIST FILES ──
app.get('/api/files', authenticateToken, (req, res) => {
  const files = stmts.getFilesByOwner.all(req.user.id);
  res.json({ files });
});

// ── GET FILE (Download / Read) ──
app.get('/api/files/:id', authenticateToken, (req, res) => {
  const file = stmts.getFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  // Check access
  if (file.owner_id !== req.user.id) {
    const perm = stmts.getPermission.get(file.id, req.user.id);
    if (!perm) return res.status(403).json({ error: 'Access denied' });
  }

  logActivity(req.user.id, 'read', `Read: ${file.original_name}`, req.ip);
  res.json({ file });
});

// ── DOWNLOAD FILE ──
app.get('/api/files/:id/download', authenticateToken, (req, res) => {
  const file = stmts.getFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  // Check read access
  if (file.owner_id !== req.user.id) {
    const perm = stmts.getPermission.get(file.id, req.user.id);
    if (!perm) return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const filePath = path.join(UPLOAD_DIR, file.name);
    const decrypted = decryptFile(filePath, file.encryption_iv);

    logActivity(req.user.id, 'download', `Downloaded: ${file.original_name}`, req.ip);

    res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
    res.setHeader('Content-Type', file.mime_type);
    res.send(decrypted);
  } catch (err) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// ── DELETE FILE ──
app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const file = stmts.getFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  // Owner can always delete; system admins can delete any file
  const isSystemAdmin = req.user.role === 'admin';
  if (file.owner_id !== req.user.id && !isSystemAdmin) {
    const perm = stmts.getPermission.get(file.id, req.user.id);
    if (!perm || perm.permission !== 'admin') {
      return res.status(403).json({ error: 'Admin permission required' });
    }
  }

  // Delete physical file
  const filePath = path.join(UPLOAD_DIR, file.name);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  // System admin can delete any file; owners delete their own
  if (isSystemAdmin && file.owner_id !== req.user.id) {
    stmts.deleteFileAdmin.run(file.id);
  } else {
    stmts.deleteFile.run(file.id, file.owner_id);
  }
  logActivity(req.user.id, 'delete', `Deleted: ${file.original_name}`, req.ip);

  res.json({ message: 'File deleted' });
});

// ── SHARE FILE ──
app.post('/api/files/:id/share',
  authenticateToken,
  [
    body('username').trim().isLength({ min: 1, max: 50 }),
    body('permission').isIn(['read', 'write', 'admin']),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const file = stmts.getFileById.get(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Only owner/admin can share
    if (file.owner_id !== req.user.id) {
      const perm = stmts.getPermission.get(file.id, req.user.id);
      if (!perm || perm.permission !== 'admin') {
        return res.status(403).json({ error: 'Admin permission required to share' });
      }
    }

    const targetUser = stmts.findUserByUsername.get(req.body.username);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    stmts.setPermission.run(file.id, targetUser.id, req.body.permission);
    stmts.createShare.run(file.id, req.user.id, targetUser.id, req.body.permission);

    logActivity(req.user.id, 'share', `Shared ${file.original_name} with ${req.body.username}`, req.ip);

    res.json({ message: `Shared with ${req.body.username}` });
  }
);

// ── GET FILE METADATA ──
app.get('/api/files/:id/metadata', authenticateToken, (req, res) => {
  const file = stmts.getFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found' });

  const permissions = stmts.getFilePermissions.all(file.id);
  const owner = stmts.findUserById.get(file.owner_id);

  res.json({
    file: { ...file, owner_name: owner?.username },
    permissions
  });
});

// ── GET SHARES ──
app.get('/api/shares', authenticateToken, (req, res) => {
  const shares = stmts.getSharesByUser.all(req.user.id);
  res.json({ shares });
});

// ═══════════════════════════════════════════════
//  SECURITY ROUTES
// ═══════════════════════════════════════════════

app.get('/api/security/threats', authenticateToken, (req, res) => {
  const threats = stmts.getThreats.all(req.user.id);
  const stats = stmts.getThreatStats.all(req.user.id);
  const files = stmts.getFilesByOwner.all(req.user.id);

  res.json({
    threats,
    stats: {
      clean: files.filter(f => f.scan_result === 'clean').length,
      malware: stats.find(s => s.threat_type === 'malware')?.count || 0,
      overflow: stats.find(s => s.threat_type === 'overflow')?.count || 0,
      encrypted: files.filter(f => f.encrypted).length,
    }
  });
});

app.get('/api/activity', authenticateToken, (req, res) => {
  const logs = stmts.getLogs.all(req.user.id);
  res.json({ logs });
});

// ═══════════════════════════════════════════════
//  DASHBOARD STATS
// ═══════════════════════════════════════════════

app.get('/api/dashboard', authenticateToken, (req, res) => {
  const files = stmts.getFilesByOwner.all(req.user.id);
  const shares = stmts.getSharesByUser.all(req.user.id);
  const threatStats = stmts.getThreatStats.all(req.user.id);
  const logs = stmts.getLogs.all(req.user.id);

  res.json({
    stats: {
      totalFiles: files.length,
      encrypted: files.filter(f => f.encrypted).length,
      shared: shares.length,
      threats: threatStats.reduce((s, t) => s + t.count, 0),
    },
    recentActivity: logs.slice(0, 20),
    recentFiles: files.slice(0, 5),
  });
});

// ═══════════════════════════════════════════════
//  ADMIN-ONLY ROUTES (requireRole('admin') middleware)
// ═══════════════════════════════════════════════

// ── LIST ALL USERS (Admin only) ──
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const users = stmts.getAllUsers.all();
  logActivity(req.user.id, 'admin_view_users', 'Viewed all users', req.ip);
  res.json({ users });
});

// ── CHANGE USER ROLE (Admin only) ──
app.put('/api/admin/users/:id/role',
  authenticateToken, requireAdmin,
  [
    body('role').isIn(['admin', 'user']).withMessage('Role must be admin or user'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const targetId = parseInt(req.params.id);
    const newRole = req.body.role;

    // Cannot change your own role
    if (targetId === req.user.id) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }

    const target = stmts.findUserById.get(targetId);
    if (!target) return res.status(404).json({ error: 'User not found' });

    stmts.updateUserRole.run(newRole, targetId);
    logActivity(req.user.id, 'admin_role_change', `Changed ${target.username} role to ${newRole}`, req.ip);

    res.json({ message: `${target.username} role updated to ${newRole}` });
  }
);

// ── DELETE USER (Admin only) ──
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id);

  // Cannot delete yourself
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  const target = stmts.findUserById.get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  // Delete user's files from disk
  const userFiles = stmts.getFilesByOwner.all(targetId);
  userFiles.forEach(f => {
    const filePath = path.join(UPLOAD_DIR, f.name);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });

  stmts.deleteUser.run(targetId);
  logActivity(req.user.id, 'admin_delete_user', `Deleted user: ${target.username}`, req.ip);

  res.json({ message: `User ${target.username} deleted` });
});

// ── VIEW ALL FILES (Admin only) ──
app.get('/api/admin/files', authenticateToken, requireAdmin, (req, res) => {
  const files = stmts.getAllFiles.all();
  logActivity(req.user.id, 'admin_view_files', 'Viewed all system files', req.ip);
  res.json({ files });
});

// ── VIEW ALL ACTIVITY LOGS (Admin only) ──
app.get('/api/admin/logs', authenticateToken, requireAdmin, (req, res) => {
  const logs = stmts.getAllLogs.all();
  res.json({ logs });
});

// ── SYSTEM-WIDE STATS (Admin only) ──
app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  const users = stmts.getAllUsers.all();
  const files = stmts.getAllFiles.all();
  const threats = stmts.getAllThreats.all();
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  res.json({
    users: {
      total: users.length,
      admins: users.filter(u => u.role === 'admin').length,
      regularUsers: users.filter(u => u.role === 'user').length,
      with2FA: users.filter(u => u.two_factor_enabled).length,
    },
    files: {
      total: files.length,
      encrypted: files.filter(f => f.encrypted).length,
      totalSize,
      clean: files.filter(f => f.scan_result === 'clean').length,
      warnings: files.filter(f => f.scan_result === 'warnings').length,
    },
    threats: {
      total: threats.length,
      malware: threats.filter(t => t.threat_type === 'malware').length,
      overflow: threats.filter(t => t.threat_type === 'overflow').length,
      injection: threats.filter(t => t.threat_type === 'injection').length,
      xss: threats.filter(t => t.threat_type === 'xss').length,
    },
  });
});

// ═══════════════════════════════════════════════
//  ERROR HANDLING
// ═══════════════════════════════════════════════

// Multer error handling
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large (max 50MB)' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

// 404 handler
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ═══════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║     🛡️  ZenCrypt Server           ║');
  console.log(`  ║     Running on http://localhost:${PORT}  ║`);
  console.log('  ╠══════════════════════════════════════╣');
  console.log('  ║  ✅ JWT Authentication               ║');
  console.log('  ║  ✅ bcrypt Password Hashing          ║');
  console.log('  ║  ✅ SQLite (Parameterized Queries)   ║');
  console.log('  ║  ✅ Input Validation                 ║');
  console.log('  ║  ✅ SQL Injection Protection          ║');
  console.log('  ║  ✅ Buffer Overflow Protection        ║');
  console.log('  ║  ✅ AES-256-CBC File Encryption      ║');
  console.log('  ║  ✅ Malware Detection                ║');
  console.log('  ║  ✅ Rate Limiting                    ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n  Shutting down ZenCrypt...');
  db.close();
  process.exit(0);
});
