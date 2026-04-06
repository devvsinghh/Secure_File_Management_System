// ═══════════════════════════════════════════════════════════
//  ZenCrypt — Secure File Management System
//  Auth, 2FA, AES-256 Encryption, RBAC, Threat Detection
// ═══════════════════════════════════════════════════════════

// ─── STATE ───
let currentUser = null;
let pending2FAUser = null;
let currentEditFileId = null;
let currentShareFileId = null;
let currentViewFileId = null;
let currentFolderId = null;

// ─── STORAGE HELPERS ───
const store = {
  get: (k) => JSON.parse(localStorage.getItem(k) || 'null'),
  set: (k, v) => localStorage.setItem(k, JSON.stringify(v)),
};

function getUsers() { return store.get('sv_users') || {}; }
function saveUsers(u) { store.set('sv_users', u); }
function getUserFiles() {
  if (!currentUser) return [];
  return (store.get('sv_files') || {})[currentUser.username] || [];
}
function saveUserFiles(files) {
  const all = store.get('sv_files') || {};
  all[currentUser.username] = files;
  store.set('sv_files', all);
}
function getUserFolders() {
  if (!currentUser) return [];
  return (store.get('sv_folders') || {})[currentUser.username] || [];
}
function saveUserFolders(folders) {
  const all = store.get('sv_folders') || {};
  all[currentUser.username] = folders;
  store.set('sv_folders', all);
}
function getShares() { return store.get('sv_shares') || []; }
function saveShares(s) { store.set('sv_shares', s); }
function getThreats() { return store.get('sv_threats') || []; }
function saveThreats(t) { store.set('sv_threats', t); }
function getLogs() { return store.get('sv_logs') || []; }
function saveLogs(l) { store.set('sv_logs', l); }

// ─── TOAST NOTIFICATIONS ───
function toast(msg, type = 'info') {
  const c = document.getElementById('toastContainer');
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${icons[type]}</span><span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.animation = 'slideOut 0.4s ease forwards';
    setTimeout(() => t.remove(), 400);
  }, 3500);
}

// ─── ACTIVITY LOG ───
function addLog(msg) {
  const logs = getLogs();
  logs.unshift({ msg, time: new Date().toLocaleString(), user: currentUser?.username });
  if (logs.length > 100) logs.length = 100;
  saveLogs(logs);
}

function renderActivityLog() {
  const logs = getLogs().filter(l => l.user === currentUser?.username);
  const el = document.getElementById('activityLog');
  if (!logs.length) {
    el.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px;">No activity yet. Upload or create a file to get started.</p>';
    return;
  }
  el.innerHTML = logs.slice(0, 20).map(l =>
    `<div class="log-entry"><span class="log-time">${l.time}</span><span class="log-msg">${l.msg}</span></div>`
  ).join('');

  // Also update profile activity log
  const pel = document.getElementById('profileActivityLog');
  if (pel) {
    pel.innerHTML = logs.slice(0, 10).map(l =>
      `<div class="log-entry"><span class="log-time">${l.time}</span><span class="log-msg">${l.msg}</span></div>`
    ).join('');
  }
}

// ─── PASSWORD HASHING (SHA-256 + Salt) ───
async function hashPassword(password) {
  const data = new TextEncoder().encode(password + 'sv_salt_ZenCrypt_2024');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── PASSWORD STRENGTH CHECKER ───
function checkPasswordStrength(val) {
  const bar = document.getElementById('passStrengthBar');
  const policyBox = document.getElementById('passwordPolicy');
  
  if (!bar) return;
  if (policyBox) policyBox.style.display = val.length > 0 ? 'block' : 'none';

  let score = 0;
  // Update Policy Visuals
  const pLen = document.getElementById('pol-length');
  const pUp = document.getElementById('pol-upper');
  const pSpec = document.getElementById('pol-special');

  const hasLen = val.length >= 8;
  const hasUp = /[A-Z]/.test(val);
  const hasSpec = /[^A-Za-z0-9]/.test(val);

  if (pLen) { pLen.innerHTML = hasLen ? '✅ 8+ characters' : '❌ 8+ characters'; pLen.style.color = hasLen ? 'var(--success)' : 'var(--text-muted)'; }
  if (pUp) { pUp.innerHTML = hasUp ? '✅ 1 uppercase letter' : '❌ 1 uppercase letter'; pUp.style.color = hasUp ? 'var(--success)' : 'var(--text-muted)'; }
  if (pSpec) { pSpec.innerHTML = hasSpec ? '✅ 1 special character' : '❌ 1 special character'; pSpec.style.color = hasSpec ? 'var(--success)' : 'var(--text-muted)'; }

  // Calc score
  if (val.length >= 8) score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  
  const pct = (score / 5) * 100;
  const colors = ['#ef4444', '#ef4444', '#f59e0b', '#f59e0b', '#22c55e', '#22c55e'];
  bar.style.width = pct + '%';
  bar.style.background = colors[score];
}

// ═══════════════════════════════════════════════
//  AUTHENTICATION — Login / Signup / 2FA
// ═══════════════════════════════════════════════

function showLogin() {
  document.getElementById('loginForm').classList.remove('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('tfaForm').classList.add('hidden');
}

function showRegister() {
  document.getElementById('loginForm').classList.add('hidden');
  document.getElementById('registerForm').classList.remove('hidden');
  document.getElementById('tfaForm').classList.add('hidden');
}

async function handleRegister() {
  const user = document.getElementById('regUser').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const pass = document.getElementById('regPass').value;
  const pass2 = document.getElementById('regPass2').value;
  const enable2fa = document.getElementById('enable2faToggle').classList.contains('active');

  // Input validation (buffer overflow protection)
  if (!user || !email || !pass) { toast('Please fill all fields', 'error'); return; }
  if (user.length > 50) { toast('Username too long (max 50 chars)', 'error'); return; }
  if (email.length > 100) { toast('Email too long', 'error'); return; }
  if (pass.length < 6) { toast('Password must be at least 6 characters', 'error'); return; }
  if (pass.length > 128) { toast('Password too long (max 128 chars)', 'error'); return; }
  if (pass !== pass2) { toast('Passwords do not match', 'error'); return; }
  if (!/^[a-zA-Z0-9_]+$/.test(user)) { toast('Username: letters, numbers, underscores only', 'error'); return; }

  const users = getUsers();
  if (users[user]) { toast('Username already exists', 'error'); return; }

  const hashed = await hashPassword(pass);
  const tfaSecret = enable2fa ? generateTOTP() : null;

  // First user → Admin, subsequent → User
  const existingCount = Object.keys(users).length;
  const assignedRole = existingCount === 0 ? 'admin' : 'user';

  users[user] = {
    username: user, email, password: hashed,
    twoFactor: enable2fa, tfaSecret,
    role: assignedRole,
    createdAt: new Date().toISOString()
  };
  saveUsers(users);

  if (enable2fa) {
    toast('Account created! Your 2FA code: ' + tfaSecret, 'success');
  } else {
    toast('Account created successfully!', 'success');
  }
  showLogin();
}

async function handleLogin() {
  const user = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value;

  if (!user || !pass) { toast('Please enter username and password', 'error'); return; }
  if (user.length > 50 || pass.length > 128) { toast('Invalid input length', 'error'); return; }

  const users = getUsers();
  if (!users[user]) { toast('Invalid username or password', 'error'); return; }

  const hashed = await hashPassword(pass);
  if (users[user].password !== hashed) { toast('Invalid username or password', 'error'); return; }

  if (users[user].twoFactor) {
    pending2FAUser = users[user];
    initiate2FA(users[user]);
    return;
  }

  loginSuccess(users[user]);
}

// ═══════════════════════════════════════════════
//  TWO-FACTOR AUTHENTICATION — OTP System
// ═══════════════════════════════════════════════

let currentOTP = null;       // The active OTP code
let otpExpiry = null;        // When OTP expires
let otpTimerInterval = null; // Countdown interval
let otpAttempts = 0;         // Failed attempts counter
const OTP_EXPIRY_SECONDS = 60;
const OTP_MAX_ATTEMPTS = 3;

function generateTOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Generate fresh OTP and show 2FA form
function initiate2FA(userData) {
  // Generate a fresh OTP for this login attempt
  currentOTP = generateTOTP();
  otpAttempts = 0;

  // Update the stored secret (so it changes each login)
  const users = getUsers();
  users[userData.username].tfaSecret = currentOTP;
  saveUsers(users);
  pending2FAUser.tfaSecret = currentOTP;

  // Switch to 2FA form
  document.getElementById('loginForm').classList.add('hidden');
  document.getElementById('registerForm').classList.add('hidden');
  document.getElementById('tfaForm').classList.remove('hidden');

  // Simulate OTP delivery
  simulateOTPDelivery(userData);

  // Start countdown timer
  startOTPTimer();

  // Display the OTP in simulated box (in production this would be hidden)
  document.getElementById('otpDisplayCode').textContent = currentOTP;

  // Clear any previous input
  const inputs = document.querySelectorAll('#tfaInputs input');
  inputs.forEach(i => { i.value = ''; });
  inputs[0].focus();

  toast('📨 OTP code sent! Check your email/SMS', 'info');
}

// Simulate sending OTP via email/SMS
function simulateOTPDelivery(userData) {
  const email = userData.email || 'user@example.com';
  const maskedEmail = maskEmail(email);

  // Show delivery notification
  const deliveryMsg = document.getElementById('otpDeliveryMsg');
  const deliveryDetail = document.getElementById('otpDeliveryDetail');

  deliveryMsg.textContent = '📨 OTP sent successfully!';
  deliveryDetail.textContent = `A 6-digit code was sent to ${maskedEmail}`;

  // Simulate delivery animation
  const notice = document.getElementById('otpDeliveryNotice');
  notice.style.animation = 'none';
  notice.offsetHeight; // Force reflow
  notice.style.animation = 'fadeUp 0.5s ease';

  // Log the simulated delivery
  console.log(`[ZenCrypt 2FA] OTP ${currentOTP} sent to ${email} at ${new Date().toLocaleString()}`);
  console.log(`[ZenCrypt 2FA] OTP expires in ${OTP_EXPIRY_SECONDS} seconds`);
}

// Mask email for display (u***@g***.com)
function maskEmail(email) {
  const [localPart, domain] = email.split('@');
  if (!domain) return '***@***.com';
  const maskedLocal = localPart[0] + '***';
  const domainParts = domain.split('.');
  const maskedDomain = domainParts[0][0] + '***.' + domainParts.slice(1).join('.');
  return maskedLocal + '@' + maskedDomain;
}

// Start the OTP expiry countdown
function startOTPTimer() {
  // Clear any existing timer
  if (otpTimerInterval) clearInterval(otpTimerInterval);

  otpExpiry = Date.now() + (OTP_EXPIRY_SECONDS * 1000);
  const timerEl = document.getElementById('otpTimer');
  const timerText = document.getElementById('otpTimerText');

  otpTimerInterval = setInterval(() => {
    const remaining = Math.max(0, Math.ceil((otpExpiry - Date.now()) / 1000));
    timerEl.textContent = remaining + 's';

    // Color changes based on time
    if (remaining <= 10) {
      timerEl.style.color = 'var(--danger)';
    } else if (remaining <= 20) {
      timerEl.style.color = 'var(--warning)';
    } else {
      timerEl.style.color = 'var(--warning)';
    }

    if (remaining === 0) {
      clearInterval(otpTimerInterval);
      otpTimerInterval = null;
      currentOTP = null;
      timerText.innerHTML = '<span style="color:var(--danger);font-weight:600;">⏰ Code expired!</span> Click "Resend Code" to get a new one.';
      document.getElementById('otpDisplayCode').textContent = 'EXPIRED';
      document.getElementById('otpDisplayCode').style.color = 'var(--danger)';
      toast('OTP expired. Request a new code.', 'warning');
    }
  }, 1000);
}

// Resend OTP
function resendOTP() {
  if (!pending2FAUser) return;

  const btn = document.getElementById('resendOtpBtn');

  // Cooldown check (prevent spam)
  if (btn.disabled) {
    toast('Please wait before requesting a new code', 'warning');
    return;
  }

  // Generate new OTP
  currentOTP = generateTOTP();
  otpAttempts = 0;

  // Update stored secret
  const users = getUsers();
  users[pending2FAUser.username].tfaSecret = currentOTP;
  saveUsers(users);
  pending2FAUser.tfaSecret = currentOTP;

  // Update display
  const codeEl = document.getElementById('otpDisplayCode');
  codeEl.textContent = currentOTP;
  codeEl.style.color = 'var(--blue-400)';

  // Clear inputs
  const inputs = document.querySelectorAll('#tfaInputs input');
  inputs.forEach(i => { i.value = ''; });
  inputs[0].focus();

  // Restart timer
  startOTPTimer();

  // Simulate re-delivery
  simulateOTPDelivery(pending2FAUser);

  // 30-second cooldown on resend button
  btn.disabled = true;
  btn.textContent = '⏳ Wait 30s...';
  btn.style.opacity = '0.5';
  let cooldown = 30;
  const cooldownInterval = setInterval(() => {
    cooldown--;
    btn.textContent = `⏳ Wait ${cooldown}s...`;
    if (cooldown <= 0) {
      clearInterval(cooldownInterval);
      btn.disabled = false;
      btn.textContent = '🔄 Resend Code';
      btn.style.opacity = '1';
    }
  }, 1000);

  toast('📨 New OTP code sent!', 'success');
}

// Cancel OTP / Go back to login
function cancelOTP() {
  if (otpTimerInterval) { clearInterval(otpTimerInterval); otpTimerInterval = null; }
  currentOTP = null;
  pending2FAUser = null;
  otpAttempts = 0;
  showLogin();
  toast('Verification cancelled', 'info');
}

function tfaNext(el, idx) {
  // Only allow digits
  el.value = el.value.replace(/[^0-9]/g, '');
  if (el.value && idx < 5) document.querySelectorAll('#tfaInputs input')[idx + 1].focus();
  // Auto-verify when all 6 digits entered
  if (idx === 5 && el.value) {
    const inputs = document.querySelectorAll('#tfaInputs input');
    const allFilled = Array.from(inputs).every(i => i.value.length === 1);
    if (allFilled) setTimeout(() => verify2FA(), 200);
  }
}

function tfaBack(e, el, idx) {
  if (e.key === 'Backspace' && !el.value && idx > 0) document.querySelectorAll('#tfaInputs input')[idx - 1].focus();
}

function verify2FA() {
  const inputs = document.querySelectorAll('#tfaInputs input');
  const code = Array.from(inputs).map(i => i.value).join('');

  // Check if OTP expired
  if (!currentOTP) {
    toast('Code has expired. Request a new one.', 'error');
    return;
  }

  // Check code length
  if (code.length !== 6) {
    toast('Please enter all 6 digits', 'error');
    return;
  }

  // Verify the code
  if (code === currentOTP) {
    // Success!
    if (otpTimerInterval) { clearInterval(otpTimerInterval); otpTimerInterval = null; }
    currentOTP = null;
    otpAttempts = 0;
    loginSuccess(pending2FAUser);
    pending2FAUser = null;
    toast('✅ Two-factor verification successful!', 'success');
  } else {
    // Failed attempt
    otpAttempts++;
    const remaining = OTP_MAX_ATTEMPTS - otpAttempts;

    inputs.forEach(i => { i.value = ''; });
    inputs[0].focus();

    if (remaining <= 0) {
      // Too many attempts — expire the OTP
      if (otpTimerInterval) { clearInterval(otpTimerInterval); otpTimerInterval = null; }
      currentOTP = null;
      toast('❌ Too many failed attempts. Please request a new code.', 'error');
      document.getElementById('otpTimerText').innerHTML = '<span style="color:var(--danger);font-weight:600;">🔒 Locked — too many attempts.</span> Click "Resend Code"';
      document.getElementById('otpDisplayCode').textContent = 'LOCKED';
      document.getElementById('otpDisplayCode').style.color = 'var(--danger)';
    } else {
      toast(`Invalid code. ${remaining} attempt(s) remaining.`, 'error');
    }
  }
}

function loginSuccess(userData) {
  currentUser = userData;
  localStorage.setItem('sv_session', userData.username);

  document.getElementById('authSection').classList.add('hidden');
  document.getElementById('appSection').classList.remove('hidden');
  document.getElementById('sidebarUsername').textContent = userData.username;
  document.getElementById('userAvatar').textContent = userData.username[0].toUpperCase();

  // Sync 2FA toggles
  const has2fa = userData.twoFactor;
  ['settings2faToggle', 'profile2faToggle'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('active', has2fa);
  });

  // ─── RBAC: Show/hide admin features based on role ───
  const isAdmin = userData.role === 'admin';
  const adminNav = document.getElementById('navAdmin');
  const roleBadge = document.getElementById('sidebarRoleBadge');
  if (adminNav) adminNav.style.display = isAdmin ? 'flex' : 'none';
  if (roleBadge) {
    roleBadge.textContent = isAdmin ? '⚡ Admin' : '○ User';
    roleBadge.style.color = isAdmin ? '#f59e0b' : '';
  }

  addLog('Logged in successfully');
  addNotification('🔐', 'You signed in successfully');
  // Check for new shares
  const incomingShares = getShares().filter(s => s.sharedWith === userData.username);
  if (incomingShares.length) addNotification('📥', `You have ${incomingShares.length} file(s) shared with you`);
  toast('Welcome back, ' + userData.username + '!', 'success');
  refreshAll();
  resetSessionTimer();
}

function handleLogout() {
  addLog('Logged out');
  currentUser = null;
  localStorage.removeItem('sv_session');
  document.getElementById('appSection').classList.add('hidden');
  document.getElementById('authSection').classList.remove('hidden');
  showLogin();
  document.getElementById('loginUser').value = '';
  document.getElementById('loginPass').value = '';
  clearTimeout(sessionTimer);
  clearInterval(countdownTimer);
  toast('Signed out successfully', 'info');
}

// ─── SESSION TIMEOUT ───
let sessionTimer = null;
let countdownTimer = null;
let countdownValue = 60;
const SESSION_INACTIVITY_LIMIT = 15 * 60 * 1000; // 15 minutes

function resetSessionTimer() {
  if (!currentUser) return;
  clearTimeout(sessionTimer);
  clearInterval(countdownTimer);
  closeModal('sessionTimeoutModal');
  sessionTimer = setTimeout(triggerSessionTimeout, SESSION_INACTIVITY_LIMIT);
}

function triggerSessionTimeout() {
  if (!currentUser) return;
  countdownValue = 60;
  document.getElementById('sessionCountdown').textContent = countdownValue;
  openModal('sessionTimeoutModal');
  
  countdownTimer = setInterval(() => {
    countdownValue--;
    document.getElementById('sessionCountdown').textContent = countdownValue;
    if (countdownValue <= 0) {
      clearInterval(countdownTimer);
      closeModal('sessionTimeoutModal');
      handleLogout();
      toast('Session expired due to inactivity', 'warning');
    }
  }, 1000);
}

function extendSession() {
  resetSessionTimer();
  addLog('Session extended');
}

// Attach activity listeners
['mousemove', 'keydown', 'mousedown', 'touchstart'].forEach(evt => {
  document.addEventListener(evt, () => {
    const modal = document.getElementById('sessionTimeoutModal');
    if (currentUser && modal && !modal.classList.contains('active')) {
      resetSessionTimer();
    }
  });
});

function changePassword() {
  const currEl = document.getElementById('currentPassInput') || document.getElementById('profileCurrentPass');
  const newEl = document.getElementById('newPassInput') || document.getElementById('profileNewPass');
  const curr = currEl?.value;
  const newP = newEl?.value;

  if (!curr || !newP) { toast('Fill both password fields', 'error'); return; }
  if (newP.length < 6) { toast('New password must be at least 6 characters', 'error'); return; }
  if (newP.length > 128) { toast('Password too long (max 128 chars)', 'error'); return; }

  hashPassword(curr).then(h => {
    if (h !== currentUser.password) { toast('Current password is incorrect', 'error'); return; }
    hashPassword(newP).then(nh => {
      const users = getUsers();
      users[currentUser.username].password = nh;
      currentUser.password = nh;
      saveUsers(users);
      toast('Password updated successfully!', 'success');
      addLog('Password changed');
      if (currEl) currEl.value = '';
      if (newEl) newEl.value = '';
    });
  });
}

function toggleSettings2FA() {
  const users = getUsers();
  const enabled = !currentUser.twoFactor;

  if (enabled) {
    const code = generateTOTP();
    users[currentUser.username].twoFactor = true;
    users[currentUser.username].tfaSecret = code;
    currentUser.twoFactor = true;
    currentUser.tfaSecret = code;
    toast('2FA enabled! Your code: ' + code, 'success');
  } else {
    users[currentUser.username].twoFactor = false;
    currentUser.twoFactor = false;
    toast('2FA disabled', 'warning');
  }

  saveUsers(users);
  addLog(enabled ? 'Enabled 2FA' : 'Disabled 2FA');

  ['settings2faToggle', 'profile2faToggle'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('active', enabled);
  });

  updateProfilePage();
}

// ═══════════════════════════════════════════════
//  ENCRYPTION — AES-256-GCM via Web Crypto API
// ═══════════════════════════════════════════════

async function getEncryptionKey() {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(currentUser.password.slice(0, 32).padEnd(32, '0')),
    'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode('sv_enc_salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptContent(text) {
  try {
    const key = await getEncryptionKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined));
  } catch { return btoa(unescape(encodeURIComponent(text))); }
}

async function decryptContent(b64) {
  try {
    const key = await getEncryptionKey();
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const data = raw.slice(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch {
    try { return decodeURIComponent(escape(atob(b64))); } catch { return '[Decryption failed]'; }
  }
}

// ═══════════════════════════════════════════════
//  THREAT DETECTION — Malware, Buffer Overflow, XSS, SQLi
// ═══════════════════════════════════════════════

const MALWARE_SIGNATURES = [
  'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$',
  'eval(base64_decode', 'document.write(unescape', '<script>alert(',
  'cmd.exe /c', 'powershell -enc', 'rm -rf /', 'DROP TABLE',
  'UNION SELECT', '<?php system(', 'exec(', 'os.system(',
  'subprocess.call', 'Runtime.getRuntime().exec'
];

const OVERFLOW_PATTERNS = [/(.)\1{500,}/, /\x00{50,}/, /A{1000,}/i];

function scanForMalware(content, fileName) {
  const threats = [];
  const upper = content.toUpperCase();

  for (const sig of MALWARE_SIGNATURES) {
    if (upper.includes(sig.toUpperCase())) {
      threats.push({ type: 'malware', severity: 'critical', detail: `Malware signature: "${sig.slice(0, 30)}..."` });
    }
  }

  const dangerExts = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.ps1', '.sh'];
  const ext = '.' + fileName.split('.').pop().toLowerCase();
  if (dangerExts.includes(ext)) {
    threats.push({ type: 'malware', severity: 'warning', detail: `Dangerous file type: ${ext}` });
  }

  if (content.length > 10000000) {
    threats.push({ type: 'overflow', severity: 'critical', detail: 'File exceeds safe size limit (>10MB)' });
  }

  for (const pat of OVERFLOW_PATTERNS) {
    if (pat.test(content)) {
      threats.push({ type: 'overflow', severity: 'warning', detail: 'Buffer overflow pattern detected' });
      break;
    }
  }

  if (/('|--|;|\/\*|\*\/|union\s+select|drop\s+table)/i.test(content)) {
    threats.push({ type: 'injection', severity: 'warning', detail: 'SQL injection pattern detected' });
  }

  if (/<script[\s>]|javascript:|on\w+\s*=/i.test(content)) {
    threats.push({ type: 'xss', severity: 'warning', detail: 'XSS pattern detected' });
  }

  return threats;
}

function logThreat(threat, fileName) {
  const threats = getThreats();
  threats.unshift({ ...threat, fileName, time: new Date().toLocaleString(), user: currentUser.username });
  if (threats.length > 200) threats.length = 200;
  saveThreats(threats);
}

// ═══════════════════════════════════════════════
//  FILE OPERATIONS
// ═══════════════════════════════════════════════

function generateId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function readFileContent(file) {
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => resolve('');
    reader.readAsText(file);
  });
}

// ── Upload ──
async function handleFileSelect(event) {
  for (const file of event.target.files) await processUploadedFile(file);
  event.target.value = '';
}

function handleDrop(event) {
  event.preventDefault();
  document.getElementById('uploadZone').classList.remove('dragover');
  for (const file of event.dataTransfer.files) processUploadedFile(file);
}

async function processUploadedFile(file) {
  const resultsDiv = document.getElementById('uploadScanResults');
  const scanCard = document.createElement('div');
  scanCard.className = 'card';
  scanCard.style.animation = 'fadeUp 0.4s ease';
  scanCard.innerHTML = `
    <div class="card-header"><h3>🔍 Scanning: ${file.name}</h3><span class="badge badge-blue">Processing</span></div>
    <div class="card-body">
      <div class="scan-progress"><div class="fill" style="width:0%"></div></div>
      <p style="font-size:12px;color:var(--text-muted);" class="scan-msg">Initializing scan...</p>
    </div>`;
  resultsDiv.prepend(scanCard);

  const fill = scanCard.querySelector('.fill');
  const msg = scanCard.querySelector('.scan-msg');
  const badge = scanCard.querySelector('.badge');

  fill.style.width = '25%'; msg.textContent = 'Reading file content...';
  const content = await readFileContent(file);

  fill.style.width = '55%'; msg.textContent = 'Scanning for malware signatures...';
  await sleep(500);

  const threats = scanForMalware(content, file.name);

  fill.style.width = '80%'; msg.textContent = 'Checking buffer overflow & injection patterns...';
  await sleep(400);
  fill.style.width = '100%';

  if (threats.length > 0) {
    const criticals = threats.filter(t => t.severity === 'critical');
    threats.forEach(t => logThreat(t, file.name));

    if (criticals.length > 0) {
      msg.textContent = `⛔ BLOCKED — ${threats.length} threat(s) detected`;
      msg.style.color = 'var(--danger)';
      fill.style.background = 'var(--danger)';
      badge.className = 'badge badge-red'; badge.textContent = 'Blocked';
      addLog(`Blocked: ${file.name} (${criticals.length} critical threats)`);
      toast(`"${file.name}" blocked — malware detected!`, 'error');
      refreshAll();
      return;
    }

    msg.textContent = `⚠️ ${threats.length} warning(s) — uploaded with caution`;
    msg.style.color = 'var(--warning)';
    fill.style.background = 'var(--warning)';
    badge.className = 'badge badge-yellow'; badge.textContent = 'Warnings';
    toast(`"${file.name}" uploaded with warnings`, 'warning');
    addNotification('⚠️', `"${file.name}" has ${threats.length} warning(s)`);
  } else {
    msg.textContent = '✅ Clean — no threats detected';
    msg.style.color = 'var(--success)';
    fill.style.background = 'var(--success)';
    badge.className = 'badge badge-green'; badge.textContent = 'Clean';
    toast(`"${file.name}" uploaded securely`, 'success');
    addNotification('✅', `"${file.name}" uploaded & verified clean`);
  }

  const autoEncrypt = document.getElementById('autoEncryptToggle')?.classList.contains('active') ?? true;
  const encrypted = autoEncrypt ? await encryptContent(content) : btoa(unescape(encodeURIComponent(content)));

  const fileObj = {
    id: generateId(), name: file.name, size: file.size,
    type: file.type || 'application/octet-stream',
    content: encrypted, encrypted: autoEncrypt,
    owner: currentUser.username,
    folderId: currentFolderId,
    permissions: { [currentUser.username]: 'admin' },
    createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString(),
    threats: threats.length, scanResult: threats.length > 0 ? 'warnings' : 'clean'
  };

  const files = getUserFiles();
  files.push(fileObj);
  saveUserFiles(files);
  addLog(`Uploaded: ${file.name}` + (autoEncrypt ? ' (encrypted)' : ''));
  refreshAll();
}

// ── Folders ──
function createFolder() {
  const name = prompt('New Folder Name:');
  if (!name) return;
  const folders = getUserFolders();
  folders.push({ id: generateId(), name, createdAt: new Date().toISOString() });
  saveUserFolders(folders);
  toast(`Folder "${name}" created`, 'success');
  refreshAll();
}

function navigateFolder(id) {
  currentFolderId = id || null;
  const inputs = document.querySelectorAll('.search-bar input');
  inputs.forEach(input => input.value = '');
  refreshAll();
}

function renderFolders() {
  const foldersGrid = document.getElementById('foldersGrid');
  const breadcrumb = document.getElementById('folderBreadcrumb');
  if (!foldersGrid || !breadcrumb) return;

  const folders = getUserFolders();
  const files = getUserFiles();

  if (currentFolderId) {
    const f = folders.find(f => f.id === currentFolderId);
    foldersGrid.style.display = 'none';
    breadcrumb.innerHTML = `
      <span class="breadcrumb-item" onclick="navigateFolder(null)">🏠 All Files</span>
      <span class="breadcrumb-separator">/</span>
      <span class="breadcrumb-item active">📁 ${f ? escapeHtml(f.name) : 'Unknown'}</span>
    `;
    const titleEl = document.getElementById('filesViewTitle');
    if (titleEl) titleEl.textContent = f ? escapeHtml(f.name) : 'Files';
  } else {
    foldersGrid.style.display = folders.length ? 'grid' : 'none';
    breadcrumb.innerHTML = `<span class="breadcrumb-item active" onclick="navigateFolder(null)">🏠 All Files</span>`;
    const titleEl = document.getElementById('filesViewTitle');
    if (titleEl) titleEl.textContent = 'All Files';
    
    foldersGrid.innerHTML = folders.map(f => {
      const folderFiles = files.filter(file => file.folderId === f.id);
      const b = folderFiles.reduce((sum, file) => sum + (file.size || 0), 0);
      return `<div class="folder-card" onclick="navigateFolder('${f.id}')">
        <div class="folder-icon">📁</div>
        <div class="folder-info">
          <div class="folder-name">${escapeHtml(f.name)}</div>
          <div class="folder-count">${folderFiles.length} files · ${formatSize(b)}</div>
        </div>
      </div>`;
    }).join('');
  }
}

// ── File Table ──
function renderFileTable(filterText = '') {
  renderFolders();
  const files = getUserFiles();
  const tbody = document.getElementById('fileTableBody');
  const filter = filterText ? filterText.toLowerCase() : '';
  
  // Filter by folder and search text
  const folderFiles = files.filter(f => currentFolderId ? f.folderId === currentFolderId : !f.folderId);
  const filtered = filter ? folderFiles.filter(f => f.name.toLowerCase().includes(filter)) : folderFiles;

  if (!filtered.length) {
    if (filter) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:48px;">No files match your search.</td></tr>`;
    } else {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:48px;">
        ${currentFolderId ? 'This folder is empty.' : 'No files found.'} <a style="color:var(--blue-400);cursor:pointer" onclick="switchView('upload')">Upload</a> or
        <a style="color:var(--blue-400);cursor:pointer" onclick="openModal('createFileModal')">create</a> a file.
      </td></tr>`;
    }
    return;
  }

  tbody.innerHTML = filtered.map(f => {
    const icon = getFileIcon(f.name);
    const size = formatSize(f.size);
    const status = f.encrypted
      ? '<span class="badge badge-green">🔒 Encrypted</span>'
      : '<span class="badge badge-yellow">🔓 Plain</span>';
    const date = new Date(f.modifiedAt).toLocaleDateString();

    return `<tr>
      <td><span class="file-icon">${icon}</span>${escapeHtml(f.name)}</td>
      <td>${size}</td>
      <td><span class="badge badge-blue">${f.type.split('/').pop()}</span></td>
      <td>${status}</td>
      <td>${date}</td>
      <td>
        <div class="action-btns">
          <button class="action-btn" title="Read/View" onclick="viewFile('${f.id}')">👁️</button>
          <button class="action-btn" title="Edit/Write" onclick="editFile('${f.id}')">✏️</button>
          <button class="action-btn" title="Download" onclick="downloadFile('${f.id}')">⬇️</button>
          <button class="action-btn" title="Share" onclick="openShareModal('${f.id}')">🔗</button>
          <button class="action-btn" title="Metadata" onclick="viewMetadata('${f.id}')">📋</button>
          <button class="action-btn" title="Delete" onclick="deleteFile('${f.id}')">🗑️</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function filterFileTable(val) { renderFileTable(val); }
function searchFiles(val) { renderFileTable(val); }

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = { txt:'📄', pdf:'📕', doc:'📘', docx:'📘', xls:'📊', xlsx:'📊', csv:'📊', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️', svg:'🖼️', mp4:'🎬', mp3:'🎵', wav:'🎵', zip:'📦', rar:'📦', json:'📋', xml:'📋', html:'🌐', css:'🎨', js:'⚡', ts:'⚡', py:'🐍', java:'☕', cpp:'⚙️', c:'⚙️', md:'📝', sql:'🗄️' };
  return map[ext] || '📄';
}

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ── Read File ──
async function viewFile(id) {
  const file = getUserFiles().find(f => f.id === id);
  if (!file) return;
  if (!checkAccess(file, 'read')) { toast('Access denied — no read permission', 'error'); return; }

  currentViewFileId = id;
  document.getElementById('viewModalTitle').textContent = '📄 ' + file.name;
  const contentEl = document.getElementById('viewModalContent');

  // Detect binary/non-text file types
  const ext = file.name.split('.').pop().toLowerCase();
  const binaryExts = ['pdf','doc','docx','xls','xlsx','ppt','pptx','zip','rar','7z','tar','gz','exe','bin','dll','so','dmg','iso','mp4','mp3','wav','avi','mov','mkv','flv','ogg','webm','jpg','jpeg','png','gif','svg','bmp','webp','ico','tiff'];
  const imageExts = ['jpg','jpeg','png','gif','svg','bmp','webp','ico','tiff'];
  const isBinary = binaryExts.includes(ext) || (file.type && !file.type.startsWith('text/') && file.type !== 'application/json' && file.type !== 'application/javascript' && file.type !== 'application/xml');
  const isImage = imageExts.includes(ext);

  if (isBinary) {
    // For binary files, show a friendly preview message instead of garbled text
    let previewHTML = `
      <div style="text-align:center;padding:40px 20px;">
        <div style="font-size:56px;margin-bottom:16px;">${getFileIcon(file.name)}</div>
        <h3 style="font-size:18px;font-weight:700;margin-bottom:8px;">${escapeHtml(file.name)}</h3>
        <p style="color:var(--text-muted);font-size:13px;margin-bottom:6px;">Type: <strong>${file.type || ext.toUpperCase()}</strong> · Size: <strong>${formatSize(file.size)}</strong></p>
        <p style="color:var(--text-muted);font-size:13px;margin-bottom:20px;">Status: ${file.encrypted ? '🔒 Encrypted with AES-256' : '🔓 Unencrypted'}</p>
        <div style="background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);border-radius:var(--radius);padding:16px;margin:0 auto;max-width:360px;">
          <p style="color:var(--text-secondary);font-size:13px;">📌 This is a <strong>${ext.toUpperCase()}</strong> file and cannot be previewed as text.</p>
          <p style="color:var(--text-muted);font-size:12px;margin-top:6px;">Use the <strong>Download</strong> button below to open it in the appropriate application.</p>
        </div>
      </div>`;
    contentEl.innerHTML = previewHTML;
  } else {
    // Text-based files — decrypt and show content
    const content = file.encrypted ? await decryptContent(file.content) : safeAtob(file.content);
    contentEl.textContent = content;
  }

  openModal('fileViewModal');
  addLog(`Viewed: ${file.name}`);
}

// ── Download File ──
async function downloadFile(id) {
  const file = getUserFiles().find(f => f.id === id);
  if (!file) return;
  if (!checkAccess(file, 'read')) { toast('Access denied', 'error'); return; }

  const content = file.encrypted ? await decryptContent(file.content) : safeAtob(file.content);
  const blob = new Blob([content], { type: file.type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = file.name;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  addLog(`Downloaded: ${file.name}`);
  toast(`Downloading "${file.name}"`, 'success');
}

function downloadCurrentFile() {
  if (currentViewFileId) downloadFile(currentViewFileId);
}

// ── Write/Edit File ──
async function editFile(id) {
  const file = getUserFiles().find(f => f.id === id);
  if (!file) return;
  if (!checkAccess(file, 'write')) { toast('Access denied — no write permission', 'error'); return; }

  currentEditFileId = id;
  const content = file.encrypted ? await decryptContent(file.content) : safeAtob(file.content);
  document.getElementById('editModalTitle').textContent = '✏️ Edit: ' + file.name;
  document.getElementById('editModalContent').value = content;
  openModal('fileEditModal');
}

async function saveFileEdit() {
  if (!currentEditFileId) return;
  const files = getUserFiles();
  const idx = files.findIndex(f => f.id === currentEditFileId);
  if (idx === -1) return;

  const newContent = document.getElementById('editModalContent').value;
  const threats = scanForMalware(newContent, files[idx].name);

  if (threats.some(t => t.severity === 'critical')) {
    toast('Save blocked — malicious content detected!', 'error');
    threats.forEach(t => logThreat(t, files[idx].name));
    return;
  }

  files[idx].content = files[idx].encrypted ? await encryptContent(newContent) : btoa(unescape(encodeURIComponent(newContent)));
  files[idx].modifiedAt = new Date().toISOString();
  files[idx].size = new Blob([newContent]).size;
  saveUserFiles(files);

  addLog(`Edited: ${files[idx].name}`);
  toast('File saved successfully', 'success');
  closeModal('fileEditModal');
  currentEditFileId = null;
  refreshAll();
}

// ── Create File ──
async function createNewFile() {
  const name = document.getElementById('newFileName').value.trim();
  const content = document.getElementById('newFileContent').value;
  const encrypt = document.getElementById('newFileEncrypt').classList.contains('active');

  if (!name) { toast('Please enter a file name', 'error'); return; }
  if (name.length > 200) { toast('File name too long', 'error'); return; }

  const threats = scanForMalware(content, name);
  if (threats.some(t => t.severity === 'critical')) {
    toast('Blocked — malicious content detected!', 'error');
    threats.forEach(t => logThreat(t, name));
    return;
  }

  const encoded = encrypt ? await encryptContent(content) : btoa(unescape(encodeURIComponent(content)));

  const fileObj = {
    id: generateId(), name, size: new Blob([content]).size,
    type: 'text/' + (name.split('.').pop() || 'plain'),
    content: encoded, encrypted: encrypt,
    owner: currentUser.username,
    folderId: currentFolderId,
    permissions: { [currentUser.username]: 'admin' },
    createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString(),
    threats: threats.length, scanResult: threats.length > 0 ? 'warnings' : 'clean'
  };

  const files = getUserFiles();
  files.push(fileObj);
  saveUserFiles(files);

  addLog(`Created: ${name}` + (encrypt ? ' (encrypted)' : ''));
  toast('File created!', 'success');
  closeModal('createFileModal');
  document.getElementById('newFileName').value = '';
  document.getElementById('newFileContent').value = '';
  refreshAll();
}

// ── Delete File ──
function deleteFile(id) {
  const files = getUserFiles();
  const file = files.find(f => f.id === id);
  if (!file) return;
  if (!checkAccess(file, 'admin')) { toast('Access denied — admin required', 'error'); return; }
  if (!confirm(`Delete "${file.name}"? This cannot be undone.`)) return;

  saveUserFiles(files.filter(f => f.id !== id));
  addLog(`Deleted: ${file.name}`);
  toast('File deleted', 'info');
  refreshAll();
}

// ── Metadata ──
function viewMetadata(id) {
  const file = getUserFiles().find(f => f.id === id);
  if (!file) return;

  const perms = Object.entries(file.permissions).map(([u, p]) => `${u}: ${p}`).join(', ');
  const grid = document.getElementById('metadataGrid');
  grid.innerHTML = [
    ['File Name', escapeHtml(file.name)], ['File ID', file.id],
    ['Size', formatSize(file.size)], ['Type', file.type],
    ['Owner', file.owner], ['Encryption', file.encrypted ? '🔒 AES-256-GCM' : '🔓 None'],
    ['Created', new Date(file.createdAt).toLocaleString()], ['Modified', new Date(file.modifiedAt).toLocaleString()],
    ['Scan Result', file.scanResult === 'clean' ? '✅ Clean' : '⚠️ Warnings'], ['Permissions', perms],
  ].map(([l, v]) => `<div class="meta-item"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');

  openModal('metadataModal');
  addLog(`Viewed metadata: ${file.name}`);
}

function safeAtob(b64) {
  try { return decodeURIComponent(escape(atob(b64))); } catch { return b64; }
}

// ═══════════════════════════════════════════════
//  SHARING & ACCESS CONTROL (RBAC)
// ═══════════════════════════════════════════════

function openShareModal(id) {
  currentShareFileId = id;
  const file = getUserFiles().find(f => f.id === id);
  if (!file) return;
  if (!checkAccess(file, 'admin')) { toast('Admin permission required to share', 'error'); return; }

  document.getElementById('shareUsername').value = '';
  renderPermissions(file);
  renderAvailableUsers(file);
  openModal('shareModal');
}

function renderAvailableUsers(file) {
  const listEl = document.getElementById('availableUsersList');
  if (!listEl) return;
  const users = getUsers();
  const otherUsers = Object.keys(users).filter(u => u !== currentUser.username && !file.permissions[u]);
  
  if (!otherUsers.length) {
    listEl.innerHTML = '<p style="color:var(--text-muted);font-size:12px;padding:8px 0;">No other users to share with — or all users already have access.</p>';
    return;
  }
  
  listEl.innerHTML = otherUsers.map(u => {
    const user = users[u];
    return `<div style="display:inline-flex;align-items:center;gap:6px;padding:5px 12px 5px 5px;background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.12);border-radius:20px;cursor:pointer;transition:all 0.2s;font-size:12px;" onclick="document.getElementById('shareUsername').value='${u}'" onmouseover="this.style.borderColor='rgba(59,130,246,0.3)'" onmouseout="this.style.borderColor='rgba(59,130,246,0.12)'">
      <span style="width:22px;height:22px;border-radius:50%;background:linear-gradient(135deg,#3B82F6,#6366F1);display:flex;align-items:center;justify-content:center;color:white;font-size:10px;font-weight:800;">${u[0].toUpperCase()}</span>
      <span style="font-weight:600;color:var(--text-primary);">${u}</span>
    </div>`;
  }).join(' ');
}

function renderPermissions(file) {
  const list = document.getElementById('permList');
  list.innerHTML = Object.entries(file.permissions).map(([user, level]) => {
    const badge = level === 'admin' ? 'badge-blue' : level === 'write' ? 'badge-green' : 'badge-yellow';
    const isOwner = user === file.owner;
    return `<div class="perm-row">
      <span class="perm-user">${user} ${isOwner ? '◆' : ''}</span>
      <span class="badge ${badge}">${level}</span>
      ${!isOwner ? `<button class="action-btn" onclick="revokeAccess('${user}')">✕</button>` : ''}
    </div>`;
  }).join('');
}

function shareFile() {
  const username = document.getElementById('shareUsername').value.trim();
  const permission = document.getElementById('sharePermission').value;

  if (!username) { toast('Enter a username', 'error'); return; }
  if (username.length > 50) { toast('Username too long', 'error'); return; }

  // Validate: user must exist
  const users = getUsers();
  if (!users[username]) {
    toast(`User "${username}" does not exist`, 'error');
    return;
  }

  // Cannot share with yourself
  if (username === currentUser.username) {
    toast('Cannot share with yourself', 'error');
    return;
  }

  const files = getUserFiles();
  const idx = files.findIndex(f => f.id === currentShareFileId);
  if (idx === -1) return;

  // Check for duplicate share
  const existingShares = getShares();
  const alreadyShared = existingShares.find(s => s.fileId === currentShareFileId && s.sharedWith === username);
  if (alreadyShared) {
    // Update permission instead
    alreadyShared.permission = permission;
    saveShares(existingShares);
    files[idx].permissions[username] = permission;
    saveUserFiles(files);
    renderPermissions(files[idx]);
    renderAvailableUsers(files[idx]);
    toast(`Updated ${username}'s permission to ${permission}`, 'success');
    refreshAll();
    return;
  }

  files[idx].permissions[username] = permission;
  files[idx].modifiedAt = new Date().toISOString();
  saveUserFiles(files);

  existingShares.push({
    fileId: currentShareFileId, fileName: files[idx].name,
    sharedBy: currentUser.username, sharedWith: username,
    permission, date: new Date().toISOString()
  });
  saveShares(existingShares);

  renderPermissions(files[idx]);
  renderAvailableUsers(files[idx]);
  addLog(`Shared "${files[idx].name}" with ${username} (${permission})`);
  toast(`✅ Shared with ${username} successfully!`, 'success');
  addNotification('🔗', `Shared "${files[idx].name}" with ${username}`);
  document.getElementById('shareUsername').value = '';
  refreshAll();
}

function revokeAccess(username) {
  const files = getUserFiles();
  const idx = files.findIndex(f => f.id === currentShareFileId);
  if (idx === -1) return;
  delete files[idx].permissions[username];
  saveUserFiles(files);
  renderPermissions(files[idx]);
  addLog(`Revoked ${username}'s access`);
  toast(`Revoked access for ${username}`, 'info');
}

function revokeShareEntry(fileId, username) {
  const files = getUserFiles();
  const file = files.find(f => f.id === fileId);
  if (file) { delete file.permissions[username]; saveUserFiles(files); }

  let shares = getShares().filter(s => !(s.fileId === fileId && s.sharedWith === username));
  saveShares(shares);
  renderSharedTable();
  toast(`Revoked ${username}'s access`, 'info');
}

function checkAccess(file, level) {
  if (file.owner === currentUser.username) return true;
  const userPerm = file.permissions[currentUser.username];
  if (!userPerm) return false;
  const hierarchy = { read: 1, write: 2, admin: 3 };
  return (hierarchy[userPerm] || 0) >= (hierarchy[level] || 1);
}

function renderSharedTable() {
  const shares = getShares().filter(s => s.sharedBy === currentUser.username);
  const tbody = document.getElementById('sharedTableBody');

  if (!shares.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:40px;">No shared files yet</td></tr>';
    return;
  }

  tbody.innerHTML = shares.map(s => {
    const badge = s.permission === 'admin' ? 'badge-blue' : s.permission === 'write' ? 'badge-green' : 'badge-yellow';
    return `<tr>
      <td>${getFileIcon(s.fileName)} ${escapeHtml(s.fileName)}</td>
      <td>${escapeHtml(s.sharedWith)}</td>
      <td><span class="badge ${badge}">${s.permission}</span></td>
      <td>${new Date(s.date).toLocaleDateString()}</td>
      <td><button class="action-btn" onclick="revokeShareEntry('${s.fileId}','${s.sharedWith}')">✕</button></td>
    </tr>`;
  }).join('');

  // Also render "Shared With Me"
  renderSharedWithMe();
}

function renderSharedWithMe() {
  const tbody = document.getElementById('sharedWithMeBody');
  if (!tbody || !currentUser) return;

  // Find shares where current user is the recipient
  const shares = getShares().filter(s => s.sharedWith === currentUser.username && s.sharedBy !== currentUser.username);

  if (!shares.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:40px;">No files have been shared with you yet</td></tr>';
    return;
  }

  // Look up the actual files from the sharer's file store
  const allFiles = store.get('sv_files') || {};

  tbody.innerHTML = shares.map(s => {
    const badge = s.permission === 'admin' ? 'badge-blue' : s.permission === 'write' ? 'badge-green' : 'badge-yellow';
    // Try to find the actual file from the sharer's storage
    const sharerFiles = allFiles[s.sharedBy] || [];
    const file = sharerFiles.find(f => f.id === s.fileId);
    const fileExists = !!file;

    return `<tr>
      <td>${getFileIcon(s.fileName)} ${escapeHtml(s.fileName)}</td>
      <td>${escapeHtml(s.sharedBy)}</td>
      <td><span class="badge ${badge}">${s.permission}</span></td>
      <td>${new Date(s.date).toLocaleDateString()}</td>
      <td>
        <div class="action-btns">
          ${fileExists ? `<button class="action-btn" title="View" onclick="viewSharedFile('${s.sharedBy}','${s.fileId}')">👁️</button>` : ''}
          ${fileExists ? `<button class="action-btn" title="Download" onclick="downloadSharedFile('${s.sharedBy}','${s.fileId}')">⬇️</button>` : '<span style="color:var(--text-dim);font-size:11px;">File removed</span>'}
        </div>
      </td>
    </tr>`;
  }).join('');
}

// View a file shared by another user
async function viewSharedFile(ownerUsername, fileId) {
  const allFiles = store.get('sv_files') || {};
  const ownerFiles = allFiles[ownerUsername] || [];
  const file = ownerFiles.find(f => f.id === fileId);
  if (!file) { toast('File no longer exists', 'error'); return; }

  document.getElementById('viewModalTitle').textContent = '📄 ' + file.name + ' (from ' + ownerUsername + ')';
  const contentEl = document.getElementById('viewModalContent');

  const ext = file.name.split('.').pop().toLowerCase();
  const binaryExts = ['pdf','doc','docx','xls','xlsx','ppt','pptx','zip','rar','7z','tar','gz','exe','bin','dll','so','dmg','iso','mp4','mp3','wav','avi','mov','mkv','flv','ogg','webm','jpg','jpeg','png','gif','svg','bmp','webp','ico','tiff'];
  const isBinary = binaryExts.includes(ext);

  if (isBinary) {
    contentEl.innerHTML = `
      <div style="text-align:center;padding:40px 20px;">
        <div style="font-size:56px;margin-bottom:16px;">${getFileIcon(file.name)}</div>
        <h3 style="font-size:18px;font-weight:700;margin-bottom:8px;">${escapeHtml(file.name)}</h3>
        <p style="color:var(--text-muted);font-size:13px;margin-bottom:6px;">Shared by: <strong>${ownerUsername}</strong> · Size: <strong>${formatSize(file.size)}</strong></p>
        <div style="background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);border-radius:var(--radius);padding:16px;margin:0 auto;max-width:360px;">
          <p style="color:var(--text-secondary);font-size:13px;">📌 This is a <strong>${ext.toUpperCase()}</strong> file — use Download to open it.</p>
        </div>
      </div>`;
  } else {
    try {
      const content = file.encrypted ? await decryptContent(file.content) : safeAtob(file.content);
      contentEl.textContent = content;
    } catch {
      contentEl.textContent = '[Cannot decrypt — encryption keys differ between users]';
    }
  }

  currentViewFileId = null; // Not the current user's file
  openModal('fileViewModal');
  addLog(`Viewed shared file: ${file.name} (from ${ownerUsername})`);
}

// Download a file shared by another user
async function downloadSharedFile(ownerUsername, fileId) {
  const allFiles = store.get('sv_files') || {};
  const ownerFiles = allFiles[ownerUsername] || [];
  const file = ownerFiles.find(f => f.id === fileId);
  if (!file) { toast('File no longer exists', 'error'); return; }

  try {
    const content = file.encrypted ? await decryptContent(file.content) : safeAtob(file.content);
    const blob = new Blob([content], { type: file.type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = file.name;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addLog(`Downloaded shared file: ${file.name} (from ${ownerUsername})`);
    toast(`Downloading "${file.name}"`, 'success');
  } catch {
    toast('Cannot download — decryption failed', 'error');
  }
}

// ═══════════════════════════════════════════════
//  SECURITY MONITOR
// ═══════════════════════════════════════════════

function renderThreatLog() {
  const threats = getThreats().filter(t => t.user === currentUser?.username);
  const el = document.getElementById('threatLog');

  if (!threats.length) {
    el.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px;">No threats detected — your system is clean! ✅</p>';
    return;
  }

  const icons = { malware: '🦠', overflow: '💥', injection: '💉', xss: '⚡' };
  el.innerHTML = threats.slice(0, 25).map(t => {
    const bgColor = t.severity === 'critical' ? 'var(--danger-bg)' : 'var(--warning-bg)';
    return `<div class="threat-item">
      <div class="threat-icon" style="background:${bgColor}">${icons[t.type] || '⚠️'}</div>
      <div class="threat-info">
        <div class="threat-name">${t.type.toUpperCase()} — ${t.severity.toUpperCase()}</div>
        <div class="threat-desc">${escapeHtml(t.detail)}</div>
        <div class="threat-time">📁 ${escapeHtml(t.fileName)} • ${t.time}</div>
      </div>
      <span class="badge ${t.severity === 'critical' ? 'badge-red' : 'badge-yellow'}">${t.severity}</span>
    </div>`;
  }).join('');
}

async function runSecurityScan() {
  const fill = document.getElementById('scanFill');
  const status = document.getElementById('scanStatus');
  const files = getUserFiles();

  if (!files.length) { toast('No files to scan', 'info'); return; }

  fill.style.width = '0%';
  status.textContent = 'Starting scan...';
  status.style.color = '';
  let foundThreats = 0;

  for (let i = 0; i < files.length; i++) {
    const pct = ((i + 1) / files.length * 100).toFixed(0);
    fill.style.width = pct + '%';
    status.textContent = `Scanning: ${files[i].name} (${i + 1}/${files.length})`;

    const content = files[i].encrypted ? await decryptContent(files[i].content) : safeAtob(files[i].content);
    const threats = scanForMalware(content, files[i].name);
    threats.forEach(t => { logThreat(t, files[i].name); foundThreats++; });
    await sleep(300);
  }

  fill.style.width = '100%';
  if (foundThreats) {
    status.textContent = `⚠️ Scan complete — ${foundThreats} issue(s) found`;
    status.style.color = 'var(--warning)';
    toast(`Found ${foundThreats} issue(s)`, 'warning');
  } else {
    status.textContent = '✅ All files are clean!';
    status.style.color = 'var(--success)';
    toast('All files are clean!', 'success');
  }

  addLog(`Security scan: ${files.length} files, ${foundThreats} threats`);
  refreshAll();
}

function updateSecurityStats() {
  const files = getUserFiles();
  const threats = getThreats().filter(t => t.user === currentUser?.username);
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('secClean', files.filter(f => f.scanResult === 'clean').length);
  el('secMalware', threats.filter(t => t.type === 'malware').length);
  el('secOverflow', threats.filter(t => t.type === 'overflow').length);
  el('secEncTotal', files.filter(f => f.encrypted).length);
}

// ═══════════════════════════════════════════════
//  USER PROFILE PAGE
// ═══════════════════════════════════════════════

function updateProfilePage() {
  if (!currentUser) return;

  const files = getUserFiles();
  const shares = getShares().filter(s => s.sharedBy === currentUser.username);
  const threats = getThreats().filter(t => t.user === currentUser.username);
  const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);

  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };

  el('profileAvatarLg', currentUser.username[0].toUpperCase());
  el('profileName', currentUser.username);
  el('profileEmail', currentUser.email || 'N/A');
  el('profileJoined', currentUser.createdAt ? new Date(currentUser.createdAt).toLocaleDateString() : '—');
  el('profile2FA', currentUser.twoFactor ? '✅ Enabled' : '❌ Disabled');

  el('pStatFiles', files.length);
  el('pStatEncrypted', files.filter(f => f.encrypted).length);
  el('pStatShared', shares.length);
  el('pStatThreats', threats.length);
  el('pStatStorage', formatSize(totalSize));
}

// ═══════════════════════════════════════════════
//  DASHBOARD & NAVIGATION
// ═══════════════════════════════════════════════

function refreshDashboard() {
  const files = getUserFiles();
  const shares = getShares().filter(s => s.sharedBy === currentUser?.username);
  const threats = getThreats().filter(t => t.user === currentUser?.username);

  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('statFiles', files.length);
  el('statEncrypted', files.filter(f => f.encrypted).length);
  el('statShared', shares.length);
  el('statThreats', threats.length);

  // Render charts
  renderFileTypeChart(files);
  renderSecurityChart(files, threats);
}

// ── Donut Chart: File Type Distribution ──
function renderFileTypeChart(files) {
  const canvas = document.getElementById('fileTypeChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 180 * dpr;
  canvas.height = 180 * dpr;
  canvas.style.width = '180px';
  canvas.style.height = '180px';
  ctx.scale(dpr, dpr);

  const cx = 90, cy = 90, outerR = 80, innerR = 50;
  ctx.clearRect(0, 0, 180, 180);

  // Count file types
  const typeCounts = {};
  files.forEach(f => {
    const ext = f.name.split('.').pop().toLowerCase();
    const category = { pdf:'PDF', doc:'Docs', docx:'Docs', txt:'Text', md:'Text', json:'Data', csv:'Data', xls:'Data', xlsx:'Data', jpg:'Images', jpeg:'Images', png:'Images', gif:'Images', svg:'Images', js:'Code', ts:'Code', py:'Code', html:'Code', css:'Code', java:'Code', cpp:'Code', c:'Code', zip:'Archive', rar:'Archive', '7z':'Archive', mp4:'Media', mp3:'Media', wav:'Media' }[ext] || 'Other';
    typeCounts[category] = (typeCounts[category] || 0) + 1;
  });

  const colors = ['#3B82F6','#F59E0B','#8B5CF6','#22C55E','#EF4444','#EC4899','#06B6D4','#F97316'];
  const entries = Object.entries(typeCounts).sort((a,b) => b[1] - a[1]);
  const total = files.length;
  const legend = document.getElementById('fileTypeLegend');

  if (!total) {
    // Empty state
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
    ctx.fillStyle = 'rgba(0,0,0,0.04)';
    ctx.fill();
    ctx.fillStyle = '#94A3B8';
    ctx.font = '600 13px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No files', cx, cy);
    if (legend) legend.innerHTML = '<p style="color:var(--text-muted);">Upload files to see distribution</p>';
    return;
  }

  let startAngle = -Math.PI / 2;
  entries.forEach(([cat, count], i) => {
    const sweep = (count / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, startAngle, startAngle + sweep);
    ctx.arc(cx, cy, innerR, startAngle + sweep, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.fill();
    startAngle += sweep;
  });

  // Center text
  ctx.fillStyle = '#0F172A';
  ctx.font = '800 24px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy - 8);
  ctx.font = '600 11px Inter, sans-serif';
  ctx.fillStyle = '#64748B';
  ctx.fillText('files', cx, cy + 12);

  // Legend
  if (legend) {
    legend.innerHTML = entries.map(([cat, count], i) => 
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="width:10px;height:10px;border-radius:3px;background:${colors[i % colors.length]};flex-shrink:0;"></span>
        <span style="color:var(--text-primary);font-weight:600;">${cat}</span>
        <span style="color:var(--text-muted);margin-left:auto;">${count} (${Math.round(count/total*100)}%)</span>
      </div>`
    ).join('');
  }
}

// ── Bar Chart: Security Overview ──
function renderSecurityChart(files, threats) {
  const canvas = document.getElementById('securityChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.parentElement.clientWidth - 48 || 400;
  const h = 180;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const encrypted = files.filter(f => f.encrypted).length;
  const clean = files.filter(f => f.scanResult === 'clean').length;
  const warned = files.filter(f => f.scanResult === 'warnings').length;
  const malware = threats.filter(t => t.type === 'malware').length;
  const overflow = threats.filter(t => t.type === 'overflow').length;
  const injection = threats.filter(t => t.type === 'injection' || t.type === 'xss').length;

  const data = [
    { label: 'Encrypted', value: encrypted, color: '#3B82F6' },
    { label: 'Clean', value: clean, color: '#22C55E' },
    { label: 'Warnings', value: warned, color: '#F59E0B' },
    { label: 'Malware', value: malware, color: '#EF4444' },
    { label: 'Overflow', value: overflow, color: '#8B5CF6' },
    { label: 'Injection', value: injection, color: '#EC4899' },
  ];

  const maxVal = Math.max(...data.map(d => d.value), 1);
  const barW = Math.min(40, (w - 60) / data.length - 12);
  const chartH = h - 50;
  const startX = 40;
  const gap = (w - startX - 20) / data.length;

  // Y axis labels
  ctx.fillStyle = '#94A3B8';
  ctx.font = '500 10px Inter, sans-serif';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 4; i++) {
    const y = 10 + (chartH / 4) * i;
    const val = Math.round(maxVal * (1 - i / 4));
    ctx.fillText(val, startX - 8, y + 4);
    ctx.strokeStyle = 'rgba(0,0,0,0.05)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(startX, y);
    ctx.lineTo(w - 10, y);
    ctx.stroke();
  }

  // Bars
  data.forEach((d, i) => {
    const x = startX + gap * i + (gap - barW) / 2;
    const barH = (d.value / maxVal) * chartH;
    const y = 10 + chartH - barH;

    // Bar with rounded top
    const radius = Math.min(6, barW / 2);
    ctx.beginPath();
    ctx.moveTo(x, 10 + chartH);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.lineTo(x + barW - radius, y);
    ctx.quadraticCurveTo(x + barW, y, x + barW, y + radius);
    ctx.lineTo(x + barW, 10 + chartH);
    ctx.closePath();
    ctx.fillStyle = d.color;
    ctx.fill();

    // Value on top
    if (d.value > 0) {
      ctx.fillStyle = '#0F172A';
      ctx.font = '700 11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(d.value, x + barW / 2, y - 6);
    }

    // Label below
    ctx.fillStyle = '#64748B';
    ctx.font = '500 9px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(d.label, x + barW / 2, h - 6);
  });
}

function refreshAll() {
  refreshDashboard();
  renderActivityLog();
  renderFileTable();
  renderSharedTable();
  renderThreatLog();
  updateSecurityStats();
  updateProfilePage();
  renderNotifications();
  updateStorageQuota();
}

function updateStorageQuota() {
  if (!currentUser) return;
  const files = getUserFiles();
  const totalBytes = files.reduce((sum, f) => sum + (f.size || 0), 0);
  const maxBytes = 100 * 1024 * 1024; // 100 MB quota
  const pct = Math.min((totalBytes / maxBytes) * 100, 100);

  const usedEl = document.getElementById('storageUsed');
  const fillEl = document.getElementById('storageFill');
  if (usedEl) usedEl.textContent = `${formatSize(totalBytes)} / 100 MB`;
  if (fillEl) {
    fillEl.style.width = pct + '%';
    // Change color at thresholds
    if (pct > 90) fillEl.style.background = 'linear-gradient(90deg, #EF4444, #DC2626)';
    else if (pct > 70) fillEl.style.background = 'linear-gradient(90deg, #F59E0B, #D97706)';
    else fillEl.style.background = 'linear-gradient(90deg, #3B82F6, #6366F1)';
  }
}

// ═══════════════════════════════════════════════
//  NOTIFICATION SYSTEM
// ═══════════════════════════════════════════════

function getNotifications() {
  return store.get('sv_notifications') || [];
}

function saveNotifications(n) {
  store.set('sv_notifications', n);
}

function addNotification(icon, message) {
  if (!currentUser) return;
  const notifs = getNotifications();
  notifs.unshift({
    id: Date.now().toString(36),
    icon, message,
    user: currentUser.username,
    time: new Date().toISOString(),
    read: false
  });
  if (notifs.length > 50) notifs.length = 50;
  saveNotifications(notifs);
  renderNotifications();
}

function renderNotifications() {
  if (!currentUser) return;
  const notifs = getNotifications().filter(n => n.user === currentUser.username);
  const list = document.getElementById('notifList');
  const badge = document.getElementById('notifBadge');
  if (!list || !badge) return;

  const unread = notifs.filter(n => !n.read).length;
  badge.textContent = unread;
  badge.style.display = unread > 0 ? 'flex' : 'none';

  if (!notifs.length) {
    list.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px;font-size:12px;">No notifications yet</p>';
    return;
  }

  list.innerHTML = notifs.slice(0, 20).map(n => {
    const ago = getTimeAgo(new Date(n.time));
    return `<div class="notif-item ${n.read ? '' : 'unread'}">
      <span class="notif-icon">${n.icon}</span>
      <span class="notif-text">${n.message}</span>
      <span class="notif-time">${ago}</span>
    </div>`;
  }).join('');
}

function getTimeAgo(date) {
  const s = Math.floor((Date.now() - date) / 1000);
  if (s < 60) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}

function toggleNotifPanel(e) {
  e.stopPropagation();
  const panel = document.getElementById('notifPanel');
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  
  if (!isOpen) {
    // Mark all as read
    const notifs = getNotifications();
    notifs.forEach(n => { if (n.user === currentUser?.username) n.read = true; });
    saveNotifications(notifs);
    setTimeout(() => {
      const badge = document.getElementById('notifBadge');
      if (badge) { badge.style.display = 'none'; badge.textContent = '0'; }
    }, 300);
  }
}

function clearNotifications() {
  const notifs = getNotifications().filter(n => n.user !== currentUser?.username);
  saveNotifications(notifs);
  renderNotifications();
  document.getElementById('notifPanel').style.display = 'none';
}

// Close notif panel on outside click
document.addEventListener('click', () => {
  const panel = document.getElementById('notifPanel');
  if (panel) panel.style.display = 'none';
});

// ═══════════════════════════════════════════════
//  DARK/LIGHT MODE TOGGLE
// ═══════════════════════════════════════════════

function toggleDarkMode() {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('sv_darkMode', isDark ? 'true' : 'false');
  updateThemeButton();
  // Re-render charts with correct colors
  if (currentUser) {
    setTimeout(() => refreshDashboard(), 100);
  }
}

function updateThemeButton() {
  const btn = document.getElementById('themeToggleBtn');
  if (!btn) return;
  const isDark = document.documentElement.classList.contains('dark');
  btn.textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
}

// Restore theme on page load
(function initTheme() {
  if (localStorage.getItem('sv_darkMode') === 'true') {
    document.documentElement.classList.add('dark');
  }
  updateThemeButton();
})();

// ═══════════════════════════════════════════════
//  MOBILE SIDEBAR
// ═══════════════════════════════════════════════

function toggleMobileSidebar() {
  const sidebar = document.getElementById('mainSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const hamburger = document.getElementById('mobileHamburger');
  if (!sidebar) return;
  
  const isOpen = sidebar.classList.toggle('open');
  overlay.classList.toggle('active', isOpen);
  hamburger.classList.toggle('active', isOpen);
}

// Auto-close sidebar on nav click (mobile)
document.addEventListener('click', (e) => {
  if (e.target.closest('.nav-item') && window.innerWidth <= 768) {
    const sidebar = document.getElementById('mainSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const hamburger = document.getElementById('mobileHamburger');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    if (hamburger) hamburger.classList.remove('active');
  }
});

function switchView(view) {
  const views = ['Dashboard', 'Files', 'Upload', 'Shared', 'Security', 'Profile', 'Admin', 'Settings'];
  views.forEach(v => {
    const viewEl = document.getElementById('view' + v);
    const navEl = document.getElementById('nav' + v);
    if (viewEl) viewEl.classList.add('hidden');
    if (navEl) navEl.classList.remove('active');
  });

  const cap = view.charAt(0).toUpperCase() + view.slice(1);
  const viewEl = document.getElementById('view' + cap);
  const navEl = document.getElementById('nav' + cap);
  if (viewEl) viewEl.classList.remove('hidden');
  if (navEl) navEl.classList.add('active');

  // Refresh data for the active view
  if (view === 'dashboard') refreshDashboard();
  if (view === 'files') renderFileTable();
  if (view === 'shared') renderSharedTable();
  if (view === 'security') { renderThreatLog(); updateSecurityStats(); }
  if (view === 'profile') updateProfilePage();
  if (view === 'admin') refreshAdminPanel();
  renderActivityLog();
}

// ═══════════════════════════════════════════════
//  ADMIN PANEL — Client-Side RBAC Management
// ═══════════════════════════════════════════════

function isCurrentUserAdmin() {
  return currentUser?.role === 'admin';
}

function generatePdfReport() {
  if (!isCurrentUserAdmin()) return;
  const adminContent = document.getElementById('viewAdmin').cloneNode(true);
  
  // Remove buttons and UI controls from the print view
  adminContent.querySelectorAll('.btn, select, input').forEach(el => el.remove());
  
  const printWindow = window.open('', '', 'width=900,height=800');
  printWindow.document.write(`
    <html>
      <head>
        <title>ZenCrypt Security Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
          body { font-family: 'Inter', sans-serif; background: white; color: #111; padding: 40px; }
          .page-header h2 { font-size: 28px; margin-bottom: 5px; }
          .page-header p { color: #666; margin-bottom: 30px; font-style: italic; }
          .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
          .stat-card { border: 1px solid #e5e7eb; padding: 15px; border-radius: 8px; text-align: center; }
          .stat-icon { font-size: 24px; margin-bottom: 10px; }
          .stat-value { font-size: 24px; font-weight: 800; margin-bottom: 5px; }
          .stat-label { font-size: 11px; color: #666; text-transform: uppercase; font-weight: 600; }
          .card { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 24px; padding: 20px; break-inside: avoid; }
          .card-header h3 { font-size: 18px; margin-top: 0; margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; }
          th, td { border: 1px solid #e5e7eb; padding: 10px; text-align: left; }
          th { background: #f9fafb; font-weight: 600; color: #4b5563; }
          .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
          .badge-red { background: #fee2e2; color: #991b1b; }
          .badge-yellow { background: #fef3c7; color: #92400e; }
          .badge-green { background: #dcfce7; color: #166534; }
          .badge-blue { background: #dbeafe; color: #1e40af; }
          .report-footer { margin-top: 50px; text-align: center; font-size: 12px; color: #9ca3af; border-top: 1px solid #eee; padding-top: 20px; }
        </style>
      </head>
      <body>
        ${adminContent.innerHTML}
        <div class="report-footer">
          Generated securely by ZenCrypt System on ${new Date().toLocaleString()}
        </div>
        <script>
          setTimeout(() => { window.print(); window.close(); }, 500);
        </script>
      </body>
    </html>
  `);
  printWindow.document.close();
}

// Render admin panel (works in both standalone and server mode)
async function refreshAdminPanel() {
  if (!isCurrentUserAdmin()) {
    toast('Access denied — Admin role required', 'error');
    switchView('dashboard');
    return;
  }

  // Try server API first, fall back to localStorage
  if (window.USE_SERVER_API && typeof API !== 'undefined') {
    try {
      const [statsData, usersData, filesData, logsData] = await Promise.all([
        API.adminGetStats(),
        API.adminGetUsers(),
        API.adminGetFiles(),
        API.adminGetLogs(),
      ]);
      renderAdminStats(statsData);
      renderAdminUserTable(usersData.users);
      renderAdminFileTable(filesData.files);
      renderAdminLogs(logsData.logs);
      return;
    } catch (err) {
      console.warn('[Admin] Server API failed, using localStorage:', err.message);
    }
  }

  // Fallback: localStorage mode
  renderAdminLocalMode();
}

function renderAdminStats(data) {
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('adminStatUsers', data.users.total);
  el('adminStatAdmins', data.users.admins);
  el('adminStatFiles', data.files.total);
  el('adminStatThreats', data.threats.total);
  const fc = document.getElementById('adminFilesCount');
  if (fc) fc.textContent = data.files.total + ' files';
}

function renderAdminUserTable(users) {
  const tbody = document.getElementById('adminUserTableBody');
  if (!users || !users.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px;">No users found</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => {
    const isSelf = u.username === currentUser.username;
    const roleBadge = u.role === 'admin'
      ? '<span class="badge badge-yellow">⚡ Admin</span>'
      : '<span class="badge badge-blue">👤 User</span>';
    const tfaBadge = u.two_factor_enabled
      ? '<span class="badge badge-green">✅</span>'
      : '<span class="badge badge-red">❌</span>';
    const date = new Date(u.created_at).toLocaleDateString();

    const roleSelect = isSelf ? roleBadge : `
      <select onchange="adminChangeRole(${u.id}, this.value)" style="background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:12px;">
        <option value="user" ${u.role === 'user' ? 'selected' : ''}>👤 User</option>
        <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>⚡ Admin</option>
      </select>`;

    const deleteBtn = isSelf ? '<span style="color:var(--text-dim);font-size:11px;">You</span>'
      : `<button class="action-btn" title="Delete User" onclick="adminDeleteUser(${u.id}, '${escapeHtml(u.username)}')">🗑️</button>`;

    return `<tr>
      <td>${u.id}</td>
      <td><strong>${escapeHtml(u.username)}</strong> ${isSelf ? '(you)' : ''}</td>
      <td>${escapeHtml(u.email)}</td>
      <td>${roleSelect}</td>
      <td>${tfaBadge}</td>
      <td>${date}</td>
      <td>${deleteBtn}</td>
    </tr>`;
  }).join('');
}

function renderAdminFileTable(files) {
  const tbody = document.getElementById('adminFileTableBody');
  if (!files || !files.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px;">No files in system</td></tr>';
    return;
  }

  tbody.innerHTML = files.map(f => {
    const icon = getFileIcon(f.original_name);
    const encBadge = f.encrypted
      ? '<span class="badge badge-green">🔒</span>'
      : '<span class="badge badge-yellow">🔓</span>';
    const scanBadge = f.scan_result === 'clean'
      ? '<span class="badge badge-green">Clean</span>'
      : '<span class="badge badge-yellow">⚠️</span>';
    return `<tr>
      <td><span class="file-icon">${icon}</span>${escapeHtml(f.original_name)}</td>
      <td>${escapeHtml(f.owner_name || 'Unknown')}</td>
      <td>${formatSize(f.size)}</td>
      <td>${encBadge}</td>
      <td>${scanBadge}</td>
      <td>${new Date(f.created_at).toLocaleDateString()}</td>
      <td>
        <button class="action-btn" title="Delete" onclick="deleteFile('${f.id}')">🗑️</button>
      </td>
    </tr>`;
  }).join('');
}

function renderAdminLogs(logs) {
  const el = document.getElementById('adminActivityLog');
  if (!logs || !logs.length) {
    el.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px;">No activity logged</p>';
    return;
  }
  el.innerHTML = logs.slice(0, 50).map(l =>
    `<div class="log-entry"><span class="log-time">${l.created_at || l.time} — <strong>${escapeHtml(l.username || l.user || '')}</strong></span><span class="log-msg">${escapeHtml(l.action || l.msg || '')} ${l.details ? '— ' + escapeHtml(l.details) : ''}</span></div>`
  ).join('');
}

// Standalone (localStorage) mode admin view
function renderAdminLocalMode() {
  const users = getUsers();
  const userList = Object.values(users);
  const files = getUserFiles();
  const threats = getThreats();

  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('adminStatUsers', userList.length);
  el('adminStatAdmins', userList.filter(u => u.role === 'admin').length);
  el('adminStatFiles', files.length);
  el('adminStatThreats', threats.length);

  // Render user table from localStorage
  const tbody = document.getElementById('adminUserTableBody');
  tbody.innerHTML = userList.map(u => {
    const isSelf = u.username === currentUser.username;
    const roleBadge = u.role === 'admin'
      ? '<span class="badge badge-yellow">⚡ Admin</span>'
      : '<span class="badge badge-blue">👤 User</span>';
    const date = u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—';

    const roleSelect = isSelf ? roleBadge : `
      <select onchange="localChangeRole('${u.username}', this.value)" style="background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:12px;">
        <option value="user" ${u.role !== 'admin' ? 'selected' : ''}>👤 User</option>
        <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>⚡ Admin</option>
      </select>`;

    const deleteBtn = isSelf ? '<span style="color:var(--text-dim);font-size:11px;">You</span>'
      : `<button class="action-btn" title="Delete User" onclick="localDeleteUser('${u.username}')">🗑️</button>`;

    return `<tr>
      <td>—</td>
      <td><strong>${escapeHtml(u.username)}</strong> ${isSelf ? '(you)' : ''}</td>
      <td>${escapeHtml(u.email || 'N/A')}</td>
      <td>${roleSelect}</td>
      <td>${u.twoFactor ? '<span class="badge badge-green">✅</span>' : '<span class="badge badge-red">❌</span>'}</td>
      <td>${date}</td>
      <td>${deleteBtn}</td>
    </tr>`;
  }).join('');

  // Admin file table
  renderAdminFileTable(files.map(f => ({ ...f, original_name: f.name, owner_name: f.owner, scan_result: f.scanResult })));

  // Render local logs
  const logs = getLogs();
  renderAdminLogs(logs.map(l => ({ ...l, created_at: l.time, username: l.user, action: l.msg, details: '' })));
}

// Server mode: Change user role
async function adminChangeRole(userId, newRole) {
  if (!isCurrentUserAdmin()) { toast('Admin access required', 'error'); return; }
  try {
    const result = await API.adminChangeRole(userId, newRole);
    toast(result.message, 'success');
    addLog(`Changed user #${userId} role to ${newRole}`);
    refreshAdminPanel();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Server mode: Delete user
async function adminDeleteUser(userId, username) {
  if (!isCurrentUserAdmin()) { toast('Admin access required', 'error'); return; }
  if (!confirm(`Delete user "${username}"? This will remove all their files. This cannot be undone.`)) return;
  try {
    const result = await API.adminDeleteUser(userId);
    toast(result.message, 'success');
    addLog(`Deleted user: ${username}`);
    refreshAdminPanel();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Standalone mode: Change user role
function localChangeRole(username, newRole) {
  if (!isCurrentUserAdmin()) { toast('Admin access required', 'error'); return; }
  const users = getUsers();
  if (users[username]) {
    users[username].role = newRole;
    saveUsers(users);
    toast(`${username} role changed to ${newRole}`, 'success');
    addLog(`Changed ${username} role to ${newRole}`);
    refreshAdminPanel();
  }
}

// Standalone mode: Delete user
function localDeleteUser(username) {
  if (!isCurrentUserAdmin()) { toast('Admin access required', 'error'); return; }
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  const users = getUsers();
  delete users[username];
  saveUsers(users);
  // Also delete their files
  const allFiles = store.get('sv_files') || {};
  delete allFiles[username];
  store.set('sv_files', allFiles);
  toast(`User ${username} deleted`, 'success');
  addLog(`Deleted user: ${username}`);
  refreshAdminPanel();
}

// ─── MODALS ───
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.classList.remove('active'); });
});

// ═══════════════════════════════════════════════
//  INIT — Auto-login from session
// ═══════════════════════════════════════════════

(function init() {
  const lastUser = localStorage.getItem('sv_session');
  if (lastUser) {
    const users = getUsers();
    if (users[lastUser]) {
      currentUser = users[lastUser];
      loginSuccess(currentUser);
    }
  }
})();

// ═══════════════════════════════════════════════
//  SERVER API INTEGRATION
//  Overrides key functions when backend is running
//  Falls back to localStorage for standalone mode
// ═══════════════════════════════════════════════

(async function initServerMode() {
  // Wait a moment for API module to detect server
  await new Promise(r => setTimeout(r, 500));

  if (!window.USE_SERVER_API) {
    console.log('[ZenCrypt] Running in standalone mode (localStorage)');
    return;
  }

  console.log('[ZenCrypt] Activating server API mode...');

  // ── Override: REGISTER ──
  const _origRegister = handleRegister;
  handleRegister = async function() {
    const user = document.getElementById('regUser').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const pass = document.getElementById('regPass').value;
    const pass2 = document.getElementById('regPass2').value;
    const enable2fa = document.getElementById('enable2faToggle').classList.contains('active');

    if (!user || !email || !pass) { toast('Please fill all fields', 'error'); return; }
    if (pass !== pass2) { toast('Passwords do not match', 'error'); return; }

    try {
      const result = await API.signup({ username: user, email, password: pass, enable2FA: enable2fa });
      if (result.tfaSecret) {
        toast('Account created! 2FA is enabled.', 'success');
      } else {
        toast('Account created successfully!', 'success');
      }
      showLogin();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: LOGIN ──
  const _origLogin = handleLogin;
  handleLogin = async function() {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;

    if (!user || !pass) { toast('Please enter username and password', 'error'); return; }

    try {
      const result = await API.login({ username: user, password: pass });

      if (result.requires2FA) {
        // Store temp token and show 2FA form
        pending2FAUser = { username: user, tempToken: result.tempToken, email: user + '@email.com' };
        currentOTP = result.hint; // Server sends the OTP hint

        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('registerForm').classList.add('hidden');
        document.getElementById('tfaForm').classList.remove('hidden');

        document.getElementById('otpDeliveryMsg').textContent = '📨 OTP sent successfully!';
        document.getElementById('otpDeliveryDetail').textContent = `A 6-digit code was sent to your registered email`;
        document.getElementById('otpDisplayCode').textContent = result.hint;

        startOTPTimer();

        const inputs = document.querySelectorAll('#tfaInputs input');
        inputs.forEach(i => { i.value = ''; });
        inputs[0].focus();

        toast('📨 OTP code sent! Check your email/SMS', 'info');
        return;
      }

      // Direct login (no 2FA)
      currentUser = result.user;
      localStorage.setItem('sv_session', result.user.username);
      document.getElementById('authSection').classList.add('hidden');
      document.getElementById('appSection').classList.remove('hidden');
      document.getElementById('sidebarUsername').textContent = result.user.username;
      document.getElementById('userAvatar').textContent = result.user.username[0].toUpperCase();
      addLog('Logged in successfully (server mode)');
      toast('Welcome back, ' + result.user.username + '!', 'success');
      refreshAll();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: VERIFY 2FA ──
  const _origVerify = verify2FA;
  verify2FA = async function() {
    const inputs = document.querySelectorAll('#tfaInputs input');
    const code = Array.from(inputs).map(i => i.value).join('');

    if (code.length !== 6) { toast('Please enter all 6 digits', 'error'); return; }

    try {
      const result = await API.verify2FA({
        tempToken: pending2FAUser.tempToken,
        code,
      });

      if (otpTimerInterval) { clearInterval(otpTimerInterval); otpTimerInterval = null; }
      currentUser = result.user;
      localStorage.setItem('sv_session', result.user.username);
      document.getElementById('authSection').classList.add('hidden');
      document.getElementById('appSection').classList.remove('hidden');
      document.getElementById('sidebarUsername').textContent = result.user.username;
      document.getElementById('userAvatar').textContent = result.user.username[0].toUpperCase();
      pending2FAUser = null;
      addLog('Logged in with 2FA (server mode)');
      toast('✅ Two-factor verification successful!', 'success');
      refreshAll();
    } catch (err) {
      otpAttempts++;
      inputs.forEach(i => { i.value = ''; });
      inputs[0].focus();
      toast(err.message, 'error');
    }
  };

  // ── Override: UPLOAD ──
  const _origProcessUpload = processUploadedFile;
  processUploadedFile = async function(file) {
    const resultsDiv = document.getElementById('uploadScanResults');
    const scanCard = document.createElement('div');
    scanCard.className = 'card';
    scanCard.style.animation = 'fadeUp 0.4s ease';
    scanCard.innerHTML = `
      <div class="card-header"><h3>🔍 Uploading: ${escapeHtml(file.name)}</h3><span class="badge badge-blue">Uploading</span></div>
      <div class="card-body">
        <div class="scan-progress"><div class="fill" style="width:30%"></div></div>
        <p style="font-size:12px;color:var(--text-muted);" class="scan-msg">Uploading to server...</p>
      </div>`;
    resultsDiv.prepend(scanCard);

    const fill = scanCard.querySelector('.fill');
    const msg = scanCard.querySelector('.scan-msg');
    const badge = scanCard.querySelector('.badge');

    try {
      fill.style.width = '60%';
      msg.textContent = 'Server scanning for threats & encrypting...';

      const result = await API.uploadFile(file);

      fill.style.width = '100%';

      if (result.threats && result.threats.length > 0) {
        msg.textContent = `⚠️ ${result.threats.length} warning(s) — uploaded with caution`;
        msg.style.color = 'var(--warning)';
        fill.style.background = 'var(--warning)';
        badge.className = 'badge badge-yellow'; badge.textContent = 'Warnings';
        toast(`"${file.name}" uploaded with warnings`, 'warning');
      } else {
        msg.textContent = '✅ Uploaded & encrypted on server';
        msg.style.color = 'var(--success)';
        fill.style.background = 'var(--success)';
        badge.className = 'badge badge-green'; badge.textContent = 'Secure';
        toast(`"${file.name}" uploaded securely`, 'success');
      }

      addLog(`Uploaded: ${file.name} (server)`);
      refreshAll();
    } catch (err) {
      fill.style.width = '100%';
      fill.style.background = 'var(--danger)';
      msg.textContent = `❌ ${err.message}`;
      msg.style.color = 'var(--danger)';
      badge.className = 'badge badge-red'; badge.textContent = 'Failed';
      toast(err.message, 'error');
    }
  };

  // ── Override: DOWNLOAD ──
  const _origDownload = downloadFile;
  downloadFile = async function(id) {
    try {
      const { blob, filename } = await API.downloadFile(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      addLog(`Downloaded: ${filename} (server)`);
      toast(`Downloading "${filename}"`, 'success');
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: VIEW/READ FILE ──
  const _origView = viewFile;
  viewFile = async function(id) {
    try {
      const content = await API.readFileContent(id);
      const fileInfo = await API.getFile(id);
      currentViewFileId = id;
      document.getElementById('viewModalTitle').textContent = '📄 ' + fileInfo.file.original_name;
      document.getElementById('viewModalContent').textContent = content;
      openModal('fileViewModal');
      addLog(`Viewed: ${fileInfo.file.original_name}`);
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: DELETE ──
  const _origDelete = deleteFile;
  deleteFile = async function(id) {
    if (!confirm('Delete this file? This cannot be undone.')) return;
    try {
      await API.deleteFile(id);
      addLog('Deleted file (server)');
      toast('File deleted', 'info');
      refreshAll();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: SHARE ──
  const _origShare = shareFile;
  shareFile = async function() {
    const username = document.getElementById('shareUsername').value.trim();
    const permission = document.getElementById('sharePermission').value;
    if (!username) { toast('Enter a username', 'error'); return; }

    try {
      await API.shareFile(currentShareFileId, { username, permission });
      addLog(`Shared file with ${username} (${permission})`);
      toast(`Shared with ${username}`, 'success');
      document.getElementById('shareUsername').value = '';
      refreshAll();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: FILE LIST (server mode) ──
  const _origRenderTable = renderFileTable;
  renderFileTable = async function(filterText = '') {
    try {
      const { files } = await API.listFiles();
      const tbody = document.getElementById('fileTableBody');
      const filter = filterText.toLowerCase();
      const filtered = filter ? files.filter(f => f.original_name.toLowerCase().includes(filter)) : files;

      if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:48px;">
          No files found. <a style="color:var(--blue-400);cursor:pointer" onclick="switchView('upload')">Upload</a> or
          <a style="color:var(--blue-400);cursor:pointer" onclick="openModal('createFileModal')">create</a> a file.
        </td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(f => {
        const icon = getFileIcon(f.original_name);
        const size = formatSize(f.size);
        const status = f.encrypted
          ? '<span class="badge badge-green">🔒 Encrypted</span>'
          : '<span class="badge badge-yellow">🔓 Plain</span>';
        const date = new Date(f.updated_at || f.created_at).toLocaleDateString();

        return `<tr>
          <td><span class="file-icon">${icon}</span>${escapeHtml(f.original_name)}</td>
          <td>${size}</td>
          <td><span class="badge badge-blue">${f.mime_type.split('/').pop()}</span></td>
          <td>${status}</td>
          <td>${date}</td>
          <td>
            <div class="action-btns">
              <button class="action-btn" title="Read" onclick="viewFile('${f.id}')">👁️</button>
              <button class="action-btn" title="Download" onclick="downloadFile('${f.id}')">⬇️</button>
              <button class="action-btn" title="Share" onclick="openShareModal('${f.id}')">🔗</button>
              <button class="action-btn" title="Metadata" onclick="viewMetadata('${f.id}')">📋</button>
              <button class="action-btn" title="Delete" onclick="deleteFile('${f.id}')">🗑️</button>
            </div>
          </td>
        </tr>`;
      }).join('');
    } catch {
      _origRenderTable(filterText); // Fallback to localStorage
    }
  };

  // ── Override: DASHBOARD ──
  const _origDashboard = refreshDashboard;
  refreshDashboard = async function() {
    try {
      const data = await API.getDashboard();
      const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
      el('statFiles', data.stats.totalFiles);
      el('statEncrypted', data.stats.encrypted);
      el('statShared', data.stats.shared);
      el('statThreats', data.stats.threats);
    } catch {
      _origDashboard();
    }
  };

  // ── Override: PROFILE ──
  const _origProfile = updateProfilePage;
  updateProfilePage = async function() {
    try {
      const data = await API.getProfile();
      const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
      el('profileAvatarLg', data.user.username[0].toUpperCase());
      el('profileName', data.user.username);
      el('profileEmail', data.user.email);
      el('profileJoined', new Date(data.user.created_at).toLocaleDateString());
      el('profile2FA', data.user.two_factor_enabled ? '✅ Enabled' : '❌ Disabled');
      el('pStatFiles', data.stats.totalFiles);
      el('pStatEncrypted', data.stats.encrypted);
      el('pStatShared', data.stats.shared);
      el('pStatThreats', data.stats.threats);
      el('pStatStorage', formatSize(data.stats.totalSize));
    } catch {
      _origProfile();
    }
  };

  // ── Override: METADATA ──
  const _origMetadata = viewMetadata;
  viewMetadata = async function(id) {
    try {
      const data = await API.getFileMetadata(id);
      const f = data.file;
      const perms = data.permissions.map(p => `${p.username}: ${p.permission}`).join(', ') || 'Owner only';
      const grid = document.getElementById('metadataGrid');
      grid.innerHTML = [
        ['File Name', escapeHtml(f.original_name)], ['File ID', f.id],
        ['Size', formatSize(f.size)], ['Type', f.mime_type],
        ['Owner', f.owner_name || 'You'], ['Encryption', f.encrypted ? '🔒 AES-256-CBC' : '🔓 None'],
        ['Created', new Date(f.created_at).toLocaleString()], ['Modified', new Date(f.updated_at).toLocaleString()],
        ['Scan Result', f.scan_result === 'clean' ? '✅ Clean' : '⚠️ Warnings'], ['Permissions', perms],
      ].map(([l, v]) => `<div class="meta-item"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');
      openModal('metadataModal');
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Override: LOGOUT ──
  const _origLogout = handleLogout;
  handleLogout = function() {
    API.logout();
    _origLogout();
  };

  console.log('[ZenCrypt] ✅ Server API integration active');
  console.log('[ZenCrypt] API endpoints: signup, login, 2fa, upload, download, read, delete, share, metadata, dashboard, profile, security');
})();
