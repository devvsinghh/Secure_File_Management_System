const fs = require('fs');
let s = fs.readFileSync('server.js', 'utf8');

const anchor = `const MALWARE_SIGS = [
  'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
  'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}.trim().isLength({ min: 1, max: 50 }).withMessage('Username required'),
    body('password').isLength({ min: 1, max: 128 }).withMessage('Password required'),
  ],`;

const replacement = `const MALWARE_SIGS = [
  'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
  'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$',
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
      threats.push({ type: 'malware', severity: 'critical', detail: \`Signature: "\${sig.slice(0, 30)}"\` });
    }
  }

  // Buffer overflow patterns
  if (/(.)\\1{500,}/.test(content)) {
    threats.push({ type: 'overflow', severity: 'warning', detail: 'Repeated character pattern (potential buffer overflow)' });
  }
  if (content && content.length > 10000000) {
    threats.push({ type: 'overflow', severity: 'critical', detail: 'Content exceeds safe size limit' });
  }

  // SQL injection in content
  if (/('|--|\\/\\*|\\*\\/|union\\s+select|drop\\s+table|insert\\s+into|delete\\s+from)/i.test(content)) {
    threats.push({ type: 'injection', severity: 'warning', detail: 'SQL injection pattern detected' });
  }

  // XSS
  if (/<script[\\s>]|javascript:|on\\w+\\s*=/i.test(content)) {
    threats.push({ type: 'xss', severity: 'warning', detail: 'XSS pattern detected' });
  }

  return threats;
}

// ═══════════════════════════════════════════════
//  FILE ENCRYPTION (AES-256-CBC)
// ═══════════════════════════════════════════════

const ENCRYPTION_KEY = require('crypto').scryptSync(JWT_SECRET.slice(0, 32), 'ZenCrypt-salt', 32);

function encryptFile(filePath) {
  const crypto = require('crypto');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const input = fs.readFileSync(filePath);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  fs.writeFileSync(filePath, encrypted);
  return iv.toString('hex');
}

function decryptFile(filePath, ivHex) {
  const crypto = require('crypto');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  const encrypted = fs.readFileSync(filePath);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ═══════════════════════════════════════════════
//  PUBLIC DASHBOARD ROUTES
// ═══════════════════════════════════════════════

// ── GET PUBLIC USERS ──
app.get('/api/public/users', (req, res) => {
  try {
    const users = stmts.getPublicUsers.all();
    res.json({ users });
  } catch (err) {
    console.error('Public users error:', err);
    res.status(500).json({ error: 'Failed to fetch public users' });
  }
});

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
      if (stmts.findUserByUsername.get(username)) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      if (stmts.findUserByEmail.get(email)) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

      let tfaSecret = null;
      if (enable2FA) {
        tfaSecret = String(Math.floor(100000 + Math.random() * 900000)); // Simulated TOTP
      }

      const userCount = stmts.getUserCount.get().count;
      const assignedRole = userCount === 0 ? 'admin' : 'user';

      const result = stmts.createUser.run(username, email, hashedPassword, enable2FA ? 1 : 0, tfaSecret, assignedRole);
      logActivity(result.lastInsertRowid, 'signup', \`New account created: \${username}\`, req.ip);

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
  ],`;

s = s.replace(anchor, replacement);
fs.writeFileSync('server.js', s);
console.log('Final fix applied');
