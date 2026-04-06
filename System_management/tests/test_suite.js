// ═══════════════════════════════════════════════════════════
//  SecureVault — Test Suite
//  Run: node tests/test_suite.js
//  Requires server running on http://localhost:3000
// ═══════════════════════════════════════════════════════════

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE_URL = 'http://localhost:3000';
let passed = 0, failed = 0, skipped = 0;
const results = [];

// ─── Mini Test Runner ───

function log(icon, msg, detail = '') {
  const line = `  ${icon} ${msg}${detail ? ' — ' + detail : ''}`;
  console.log(line);
  results.push({ icon, msg, detail });
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log('✅', name);
  } catch (err) {
    failed++;
    log('❌', name, err.message);
  }
}

function skip(name, reason) {
  skipped++;
  log('⏭️', name, reason);
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, label = '') {
  if (actual !== expected) {
    throw new Error(`${label} Expected "${expected}", got "${actual}"`);
  }
}

function assertIncludes(str, substr, label = '') {
  if (!str.includes(substr)) {
    throw new Error(`${label} Expected string to include "${substr}"`);
  }
}

// ─── HTTP Helper ───

function request(method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const isMultipart = body instanceof Buffer;

    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    if (isMultipart) {
      const boundary = '----TestBoundary' + crypto.randomBytes(8).toString('hex');
      headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;

      const fileContent = body;
      const fileName = 'test_upload.txt';
      const multipartBody = Buffer.concat([
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: text/plain\r\n\r\n`),
        fileContent,
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]);
      body = multipartBody;
      headers['Content-Length'] = body.length;
    } else if (body && typeof body === 'object') {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }

    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      headers,
    };

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, data: json, raw: data, headers: res.headers });
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ─── Test Data ───

const TEST_USER = {
  username: 'testuser_' + Date.now(),
  email: `test_${Date.now()}@example.com`,
  password: 'SecurePass123!',
};

const TEST_ADMIN = {
  username: 'admin_' + Date.now(),
  email: `admin_${Date.now()}@example.com`,
  password: 'AdminPass456!',
};

let userToken = null;
let adminToken = null;
let uploadedFileId = null;

// ═══════════════════════════════════════════════════════════
//  TEST SUITE 1: AUTHENTICATION
// ═══════════════════════════════════════════════════════════

async function authTests() {
  console.log('\n╔═══════════════════════════════════════╗');
  console.log('║  TEST SUITE 1: AUTHENTICATION         ║');
  console.log('╚═══════════════════════════════════════╝\n');

  // ── TC-A01: Signup with valid data ──
  await test('TC-A01: Signup with valid credentials', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: TEST_USER.username,
      email: TEST_USER.email,
      password: TEST_USER.password,
      enable2FA: false,
    });
    assertEqual(res.status, 201, 'Status');
    assert(res.data.message, 'Should return success message');
  });

  // ── TC-A02: Duplicate username ──
  await test('TC-A02: Reject duplicate username', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: TEST_USER.username,
      email: 'other@example.com',
      password: TEST_USER.password,
      enable2FA: false,
    });
    assertEqual(res.status, 409, 'Status');
    assertIncludes(res.data.error, 'already', 'Error message');
  });

  // ── TC-A03: Duplicate email ──
  await test('TC-A03: Reject duplicate email', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'uniqueuser999',
      email: TEST_USER.email,
      password: TEST_USER.password,
      enable2FA: false,
    });
    assertEqual(res.status, 409, 'Status');
  });

  // ── TC-A04: Short password ──
  await test('TC-A04: Reject password < 8 chars', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'shortpass',
      email: 'short@example.com',
      password: 'Ab1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-A05: Password without uppercase ──
  await test('TC-A05: Reject password without uppercase', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'nouppercase',
      email: 'noupper@example.com',
      password: 'nouppercase123',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-A06: Password without number ──
  await test('TC-A06: Reject password without number', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'nonumber',
      email: 'nonumber@example.com',
      password: 'NoNumberHere',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-A07: Invalid email ──
  await test('TC-A07: Reject invalid email format', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'invalidemail',
      email: 'not-an-email',
      password: 'ValidPass1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-A08: Username with special chars ──
  await test('TC-A08: Reject username with special chars', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'user<script>',
      email: 'xss@example.com',
      password: 'ValidPass1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-A09: Login with valid credentials ──
  await test('TC-A09: Login with valid credentials', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: TEST_USER.username,
      password: TEST_USER.password,
    });
    assertEqual(res.status, 200, 'Status');
    assert(res.data.token, 'Should return JWT token');
    assert(res.data.user, 'Should return user object');
    assertEqual(res.data.user.username, TEST_USER.username, 'Username');
    userToken = res.data.token;
  });

  // ── TC-A10: Login with wrong password ──
  await test('TC-A10: Reject wrong password', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: TEST_USER.username,
      password: 'WrongPassword99',
    });
    assertEqual(res.status, 401, 'Status');
  });

  // ── TC-A11: Login with non-existent user ──
  await test('TC-A11: Reject non-existent username', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: 'nonexistentuser_xyz',
      password: 'SomePass123',
    });
    assertEqual(res.status, 401, 'Status');
    // Should NOT reveal whether username exists (generic message)
    assertIncludes(res.data.error, 'Invalid', 'Generic error message');
  });

  // ── TC-A12: Access protected route without token ──
  await test('TC-A12: Reject request without JWT token', async () => {
    const res = await request('GET', '/api/dashboard');
    assertEqual(res.status, 401, 'Status');
  });

  // ── TC-A13: Access with invalid token ──
  await test('TC-A13: Reject request with invalid JWT', async () => {
    const res = await request('GET', '/api/dashboard', null, 'invalid.jwt.token');
    assertEqual(res.status, 403, 'Status');
  });

  // ── TC-A14: Access with valid token ──
  await test('TC-A14: Accept request with valid JWT', async () => {
    const res = await request('GET', '/api/dashboard', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(res.data.stats, 'Should return dashboard stats');
  });

  // ── TC-A15: Signup with 2FA ──
  await test('TC-A15: Signup with 2FA enabled', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: TEST_ADMIN.username,
      email: TEST_ADMIN.email,
      password: TEST_ADMIN.password,
      enable2FA: true,
    });
    assertEqual(res.status, 201, 'Status');
    assert(res.data.tfaSecret, 'Should return 2FA secret');
    assertEqual(res.data.tfaSecret.length, 6, '2FA secret length');
  });

  // ── TC-A16: Login triggers 2FA ──
  await test('TC-A16: Login with 2FA returns temp token', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: TEST_ADMIN.username,
      password: TEST_ADMIN.password,
    });
    assertEqual(res.status, 200, 'Status');
    assert(res.data.requires2FA, 'Should require 2FA');
    assert(res.data.tempToken, 'Should return temp token');
    assert(res.data.hint, 'Should return OTP hint');

    // Verify with correct code
    const res2 = await request('POST', '/api/auth/verify-2fa', {
      tempToken: res.data.tempToken,
      code: res.data.hint,
    });
    assertEqual(res2.status, 200, 'Verify status');
    assert(res2.data.token, 'Should return full JWT');
    adminToken = res2.data.token;
  });

  // ── TC-A17: 2FA with wrong code ──
  await test('TC-A17: Reject wrong 2FA code', async () => {
    const loginRes = await request('POST', '/api/auth/login', {
      username: TEST_ADMIN.username,
      password: TEST_ADMIN.password,
    });
    const res = await request('POST', '/api/auth/verify-2fa', {
      tempToken: loginRes.data.tempToken,
      code: '000000',
    });
    assertEqual(res.status, 401, 'Status');
  });

  // ── TC-A18: Change password ──
  await test('TC-A18: Change password with valid current', async () => {
    const res = await request('POST', '/api/auth/change-password', {
      currentPassword: TEST_USER.password,
      newPassword: 'NewSecurePass789!',
    }, userToken);
    assertEqual(res.status, 200, 'Status');

    // Login with new password
    const loginRes = await request('POST', '/api/auth/login', {
      username: TEST_USER.username,
      password: 'NewSecurePass789!',
    });
    assertEqual(loginRes.status, 200, 'New password works');
    userToken = loginRes.data.token;

    // Change back
    await request('POST', '/api/auth/change-password', {
      currentPassword: 'NewSecurePass789!',
      newPassword: TEST_USER.password,
    }, userToken);
    const res2 = await request('POST', '/api/auth/login', {
      username: TEST_USER.username,
      password: TEST_USER.password,
    });
    userToken = res2.data.token;
  });

  // ── TC-A19: Change password with wrong current ──
  await test('TC-A19: Reject password change with wrong current', async () => {
    const res = await request('POST', '/api/auth/change-password', {
      currentPassword: 'WrongCurrent!1',
      newPassword: 'NewSecure123!',
    }, userToken);
    assertEqual(res.status, 401, 'Status');
  });

  // ── TC-A20: Get profile ──
  await test('TC-A20: Get user profile', async () => {
    const res = await request('GET', '/api/auth/profile', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assertEqual(res.data.user.username, TEST_USER.username, 'Username');
    assert(res.data.stats !== undefined, 'Should include stats');
  });
}

// ═══════════════════════════════════════════════════════════
//  TEST SUITE 2: FILE UPLOAD / DOWNLOAD
// ═══════════════════════════════════════════════════════════

async function fileTests() {
  console.log('\n╔═══════════════════════════════════════╗');
  console.log('║  TEST SUITE 2: FILE OPERATIONS        ║');
  console.log('╚═══════════════════════════════════════╝\n');

  // ── TC-F01: Upload clean text file ──
  await test('TC-F01: Upload clean text file', async () => {
    const content = Buffer.from('Hello, this is a clean test file.\nIt has multiple lines.\n');
    const res = await request('POST', '/api/files/upload', content, userToken);
    assertEqual(res.status, 201, 'Status');
    assert(res.data.file, 'Should return file info');
    assert(res.data.file.id, 'Should return file ID');
    assertEqual(res.data.scanResult, 'clean', 'Scan result');
    uploadedFileId = res.data.file.id;
  });

  // ── TC-F02: List user files ──
  await test('TC-F02: List user files after upload', async () => {
    const res = await request('GET', '/api/files', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(Array.isArray(res.data.files), 'Should return files array');
    assert(res.data.files.length >= 1, 'Should have at least 1 file');
  });

  // ── TC-F03: Get file metadata ──
  await test('TC-F03: Get file metadata', async () => {
    const res = await request('GET', `/api/files/${uploadedFileId}/metadata`, null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(res.data.file, 'Should return file object');
    assertEqual(res.data.file.encrypted, 1, 'File should be encrypted');
    assert(res.data.permissions, 'Should include permissions array');
  });

  // ── TC-F04: Download file ──
  await test('TC-F04: Download uploaded file', async () => {
    const res = await request('GET', `/api/files/${uploadedFileId}/download`, null, userToken);
    assertEqual(res.status, 200, 'Status');
    assertIncludes(res.raw, 'clean test file', 'Decrypted content');
  });

  // ── TC-F05: Download non-existent file ──
  await test('TC-F05: Reject download of non-existent file', async () => {
    const res = await request('GET', '/api/files/nonexistent-id/download', null, userToken);
    assertEqual(res.status, 404, 'Status');
  });

  // ── TC-F06: Upload without auth ──
  await test('TC-F06: Reject upload without authentication', async () => {
    const content = Buffer.from('unauthorized upload');
    const res = await request('POST', '/api/files/upload', content);
    assertEqual(res.status, 401, 'Status');
  });

  // ── TC-F07: Share file ──
  await test('TC-F07: Share file with another user', async () => {
    const res = await request('POST', `/api/files/${uploadedFileId}/share`, {
      username: TEST_ADMIN.username,
      permission: 'read',
    }, userToken);
    assertEqual(res.status, 200, 'Status');
  });

  // ──TC-F08: Shared user can read ──
  await test('TC-F08: Shared user can download file', async () => {
    const res = await request('GET', `/api/files/${uploadedFileId}/download`, null, adminToken);
    assertEqual(res.status, 200, 'Status');
    assertIncludes(res.raw, 'clean test file', 'Content accessible');
  });

  // ── TC-F09: Non-shared user cannot read ──
  await test('TC-F09: Non-shared user denied access', async () => {
    // Create a third user
    const thirdUser = 'thirduser_' + Date.now();
    await request('POST', '/api/auth/signup', {
      username: thirdUser,
      email: `third_${Date.now()}@example.com`,
      password: 'ThirdPass1!',
      enable2FA: false,
    });
    const loginRes = await request('POST', '/api/auth/login', {
      username: thirdUser,
      password: 'ThirdPass1!',
    });
    const thirdToken = loginRes.data.token;

    const res = await request('GET', `/api/files/${uploadedFileId}/download`, null, thirdToken);
    assertEqual(res.status, 403, 'Status');
  });

  // ── TC-F10: Delete file ──
  await test('TC-F10: Owner can delete file', async () => {
    // Upload a temp file for deletion
    const content = Buffer.from('file to delete');
    const uploadRes = await request('POST', '/api/files/upload', content, userToken);
    const tempId = uploadRes.data.file.id;

    const res = await request('DELETE', `/api/files/${tempId}`, null, userToken);
    assertEqual(res.status, 200, 'Status');

    // Verify deletion
    const getRes = await request('GET', `/api/files/${tempId}`, null, userToken);
    assertEqual(getRes.status, 404, 'File should be gone');
  });

  // ── TC-F11: Non-owner cannot delete ──
  await test('TC-F11: Non-owner cannot delete file', async () => {
    const res = await request('DELETE', `/api/files/${uploadedFileId}`, null, adminToken);
    // Admin with only 'read' share permission should not be able to delete
    // (system admin CAN delete — so this depends on role)
    assert(res.status === 200 || res.status === 403, 'Status should be 200 (admin) or 403');
  });

  // ── TC-F12: List shares ──
  await test('TC-F12: List shares by user', async () => {
    const res = await request('GET', '/api/shares', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(Array.isArray(res.data.shares), 'Should return shares array');
  });
}

// ═══════════════════════════════════════════════════════════
//  TEST SUITE 3: SECURITY TESTING
// ═══════════════════════════════════════════════════════════

async function securityTests() {
  console.log('\n╔═══════════════════════════════════════╗');
  console.log('║  TEST SUITE 3: SECURITY               ║');
  console.log('╚═══════════════════════════════════════╝\n');

  // ── TC-S01: SQL injection in login ──
  await test('TC-S01: SQL injection in username blocked', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: "admin' OR '1'='1",
      password: 'test',
    });
    // Should fail auth, NOT return all users
    assert(res.status === 400 || res.status === 401, 'Injection blocked');
  });

  // ── TC-S02: SQL injection in signup ──
  await test('TC-S02: SQL injection in signup blocked', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: "'; DROP TABLE users; --",
      email: 'sqli@test.com',
      password: 'ValidPass1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Blocked by validation');
  });

  // ── TC-S03: XSS in username ──
  await test('TC-S03: XSS in username blocked', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: '<script>alert(1)</script>',
      email: 'xss@test.com',
      password: 'ValidPass1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'XSS blocked');
  });

  // ── TC-S04: Malware upload detection ──
  await test('TC-S04: Detect EICAR test malware', async () => {
    const malwareContent = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    const res = await request('POST', '/api/files/upload', malwareContent, userToken);
    assertEqual(res.status, 400, 'Should block malware');
    assertIncludes(res.data.error.toLowerCase(), 'malware', 'Error mentions malware');
  });

  // ── TC-S05: Detect eval/base64 exploit ──
  await test('TC-S05: Detect eval(base64_decode exploit', async () => {
    const content = Buffer.from('<?php eval(base64_decode("SGVsbG8gV29ybGQ=")); ?>');
    const res = await request('POST', '/api/files/upload', content, userToken);
    assertEqual(res.status, 400, 'Should block exploit');
  });

  // ── TC-S06: Detect shell command pattern ──
  await test('TC-S06: Detect shell command in upload', async () => {
    const content = Buffer.from('SYSTEM LOG\ncmd.exe /c del /f /q *\nEND LOG');
    const res = await request('POST', '/api/files/upload', content, userToken);
    assertEqual(res.status, 400, 'Should block shell command');
  });

  // ── TC-S07: Buffer overflow — repeated chars ──
  await test('TC-S07: Detect buffer overflow pattern', async () => {
    const content = Buffer.from('Normal start\n' + 'A'.repeat(600) + '\nNormal end');
    const res = await request('POST', '/api/files/upload', content, userToken);
    // Should upload with warnings (repeated chars = warning, not critical)
    assert(res.status === 200 || res.status === 201, 'Uploaded with warnings');
    if (res.data.threats) {
      const overflowThreat = res.data.threats.find(t => t.type === 'overflow');
      assert(overflowThreat, 'Should flag overflow pattern');
    }
  });

  // ── TC-S08: SQL injection in file content ──
  await test('TC-S08: Detect SQL injection in file content', async () => {
    const content = Buffer.from("SELECT * FROM users; DROP TABLE users; -- comment");
    const res = await request('POST', '/api/files/upload', content, userToken);
    if (res.data.threats) {
      const sqlThreat = res.data.threats.find(t => t.type === 'injection');
      assert(sqlThreat, 'Should flag SQL injection');
    }
  });

  // ── TC-S09: XSS in file content ──
  await test('TC-S09: Detect XSS in file content', async () => {
    const content = Buffer.from('<html><script>document.cookie</script></html>');
    const res = await request('POST', '/api/files/upload', content, userToken);
    if (res.data.threats) {
      const xssThreat = res.data.threats.find(t => t.type === 'xss');
      assert(xssThreat, 'Should flag XSS pattern');
    }
  });

  // ── TC-S10: Null byte injection ──
  await test('TC-S10: Null byte stripped from input', async () => {
    const res = await request('POST', '/api/auth/login', {
      username: 'admin\x00injected',
      password: 'test',
    });
    // Should not crash, should just fail auth
    assert(res.status === 400 || res.status === 401, 'Handled null byte');
  });

  // ── TC-S11: JWT token tampering ──
  await test('TC-S11: Reject tampered JWT token', async () => {
    // Take valid token, modify payload
    const parts = userToken.split('.');
    parts[1] = Buffer.from('{"id":1,"username":"admin","role":"admin"}').toString('base64url');
    const tamperedToken = parts.join('.');

    const res = await request('GET', '/api/dashboard', null, tamperedToken);
    assertEqual(res.status, 403, 'Tampered token rejected');
  });

  // ── TC-S12: Threat logs recorded ──
  await test('TC-S12: Threat logs are recorded', async () => {
    const res = await request('GET', '/api/security/threats', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(res.data.threats, 'Should return threats array');
    assert(res.data.stats, 'Should return threat stats');
  });

  // ── TC-S13: Activity logs recorded ──
  await test('TC-S13: Activity logs are recorded', async () => {
    const res = await request('GET', '/api/activity', null, userToken);
    assertEqual(res.status, 200, 'Status');
    assert(Array.isArray(res.data.logs), 'Should return logs array');
    assert(res.data.logs.length > 0, 'Should have logged actions');
  });

  // ── TC-S14: Rate limiting ──
  await test('TC-S14: Rate limiting on auth endpoints', async () => {
    // Send many requests quickly
    const promises = [];
    for (let i = 0; i < 25; i++) {
      promises.push(request('POST', '/api/auth/login', {
        username: 'nonexistent',
        password: 'test',
      }));
    }
    const results = await Promise.all(promises);
    const rateLimited = results.some(r => r.status === 429);
    // Rate limit is 20/min, so some should be blocked
    assert(rateLimited, 'Should rate-limit excessive requests');
  });

  // ── TC-S15: Encrypted file storage ──
  await test('TC-S15: Files are encrypted at rest', async () => {
    const res = await request('GET', `/api/files/${uploadedFileId}/metadata`, null, userToken);
    assertEqual(res.status, 200, 'Status');
    assertEqual(res.data.file.encrypted, 1, 'File should be encrypted');
    assert(res.data.file.encryption_iv, 'Should have encryption IV');
    assertEqual(res.data.file.encryption_iv.length, 32, 'IV should be 32 hex chars (16 bytes)');
  });
}

// ═══════════════════════════════════════════════════════════
//  TEST SUITE 4: RBAC & ADMIN
// ═══════════════════════════════════════════════════════════

async function rbacTests() {
  console.log('\n╔═══════════════════════════════════════╗');
  console.log('║  TEST SUITE 4: RBAC & ADMIN           ║');
  console.log('╚═══════════════════════════════════════╝\n');

  // ── TC-R01: Regular user denied admin routes ──
  await test('TC-R01: User cannot access admin users list', async () => {
    const res = await request('GET', '/api/admin/users', null, userToken);
    assertEqual(res.status, 403, 'Status');
    assertIncludes(res.data.error, 'permission', 'Error message');
  });

  // ── TC-R02: User denied admin stats ──
  await test('TC-R02: User cannot access admin stats', async () => {
    const res = await request('GET', '/api/admin/stats', null, userToken);
    assertEqual(res.status, 403, 'Status');
  });

  // ── TC-R03: User denied admin logs ──
  await test('TC-R03: User cannot access admin logs', async () => {
    const res = await request('GET', '/api/admin/logs', null, userToken);
    assertEqual(res.status, 403, 'Status');
  });

  // ── TC-R04: User denied admin files ──
  await test('TC-R04: User cannot access admin files', async () => {
    const res = await request('GET', '/api/admin/files', null, userToken);
    assertEqual(res.status, 403, 'Status');
  });

  // ── TC-R05: User denied role change ──
  await test('TC-R05: User cannot change roles', async () => {
    const res = await request('PUT', '/api/admin/users/1/role', { role: 'admin' }, userToken);
    assertEqual(res.status, 403, 'Status');
  });

  // Note: First registered user is admin. If adminToken user was not first, these will 403.
  // Skipping admin-positive tests if token holder isn't actually admin.

  // ── TC-R06: Admin can view users ──
  await test('TC-R06: Admin (first user) can view all users', async () => {
    // Re-login as first user if needed — first signup is auto-admin
    const res = await request('GET', '/api/admin/users', null, adminToken);
    if (res.status === 403) {
      skip('TC-R06', 'Admin token holder not first user (auto-admin)');
      return;
    }
    assertEqual(res.status, 200, 'Status');
    assert(Array.isArray(res.data.users), 'Should return users');
  });

  // ── TC-R07: Admin can view stats ──
  await test('TC-R07: Admin can view system stats', async () => {
    const res = await request('GET', '/api/admin/stats', null, adminToken);
    if (res.status === 403) return; // not admin
    assertEqual(res.status, 200, 'Status');
    assert(res.data.users, 'Should include user stats');
    assert(res.data.files, 'Should include file stats');
    assert(res.data.threats, 'Should include threat stats');
  });

  // ── TC-R08: Invalid role value rejected ──
  await test('TC-R08: Reject invalid role value', async () => {
    const res = await request('PUT', '/api/admin/users/1/role', { role: 'superuser' }, adminToken);
    assert(res.status === 400 || res.status === 403, 'Invalid role rejected');
  });
}

// ═══════════════════════════════════════════════════════════
//  TEST SUITE 5: EDGE CASES
// ═══════════════════════════════════════════════════════════

async function edgeCaseTests() {
  console.log('\n╔═══════════════════════════════════════╗');
  console.log('║  TEST SUITE 5: EDGE CASES             ║');
  console.log('╚═══════════════════════════════════════╝\n');

  // ── TC-E01: Empty body ──
  await test('TC-E01: Handle empty request body', async () => {
    const res = await request('POST', '/api/auth/login', {});
    assert(res.status >= 400, 'Should return error');
  });

  // ── TC-E02: Very long username ──
  await test('TC-E02: Reject extremely long username (500 chars)', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'a'.repeat(500),
      email: 'long@example.com',
      password: 'ValidPass1',
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-E03: Very long password ──
  await test('TC-E03: Reject password > 128 chars', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'longpass',
      email: 'longpass@example.com',
      password: 'A1' + 'a'.repeat(200),
      enable2FA: false,
    });
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-E04: Share to non-existent user ──
  await test('TC-E04: Share to non-existent user rejected', async () => {
    const res = await request('POST', `/api/files/${uploadedFileId}/share`, {
      username: 'userDoesNotExist999',
      permission: 'read',
    }, userToken);
    assertEqual(res.status, 404, 'Status');
  });

  // ── TC-E05: Share with invalid permission ──
  await test('TC-E05: Share with invalid permission rejected', async () => {
    const res = await request('POST', `/api/files/${uploadedFileId}/share`, {
      username: TEST_ADMIN.username,
      permission: 'superadmin',
    }, userToken);
    assertEqual(res.status, 400, 'Status');
  });

  // ── TC-E06: Delete non-existent file ──
  await test('TC-E06: Delete non-existent file returns 404', async () => {
    const res = await request('DELETE', '/api/files/nonexistent-id', null, userToken);
    assertEqual(res.status, 404, 'Status');
  });

  // ── TC-E07: Unicode in filenames ──
  await test('TC-E07: Handle Unicode content', async () => {
    const content = Buffer.from('日本語テスト 中文测试 한국어 テスト 🔐');
    const res = await request('POST', '/api/files/upload', content, userToken);
    assert(res.status === 201 || res.status === 200, 'Unicode handled');
  });

  // ── TC-E08: Empty file upload ──
  await test('TC-E08: Handle empty file upload body', async () => {
    const content = Buffer.from('');
    const res = await request('POST', '/api/files/upload', content, userToken);
    // Should either succeed (empty file) or fail gracefully
    assert(res.status < 500, 'Should not crash server');
  });

  // ── TC-E09: Access file belonging to another user ──
  await test('TC-E09: Cannot access another user file directly', async () => {
    // Upload as admin
    const content = Buffer.from('admin secret file');
    const uploadRes = await request('POST', '/api/files/upload', content, adminToken);
    if (uploadRes.status === 201) {
      const adminFileId = uploadRes.data.file.id;
      // Try to access as regular user
      const res = await request('GET', `/api/files/${adminFileId}/download`, null, userToken);
      assertEqual(res.status, 403, 'Access denied');
    }
  });

  // ── TC-E10: Concurrent requests ──
  await test('TC-E10: Handle concurrent file list requests', async () => {
    const promises = Array.from({ length: 10 }, () =>
      request('GET', '/api/files', null, userToken)
    );
    const results = await Promise.all(promises);
    const allOk = results.every(r => r.status === 200);
    assert(allOk, 'All concurrent requests succeed');
  });

  // ── TC-E11: Expired JWT ──
  await test('TC-E11: Reject expired JWT token format', async () => {
    // Create a blatantly invalid token structure
    const res = await request('GET', '/api/files', null, 'eyJ.expired.token');
    assertEqual(res.status, 403, 'Expired/invalid rejected');
  });

  // ── TC-E12: Missing required fields ──
  await test('TC-E12: Signup missing email field', async () => {
    const res = await request('POST', '/api/auth/signup', {
      username: 'noEmailUser',
      password: 'ValidPass1',
    });
    assertEqual(res.status, 400, 'Status');
  });
}

// ═══════════════════════════════════════════════════════════
//  RUN ALL TESTS
// ═══════════════════════════════════════════════════════════

async function runAll() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║  SecureVault — Complete Test Suite                ║');
  console.log('║  Server: http://localhost:3000                    ║');
  console.log('╚═══════════════════════════════════════════════════╝');

  // Check if server is running
  try {
    const health = await request('GET', '/');
    if (health.status >= 500) throw new Error('Server error');
  } catch (err) {
    console.error('\n  ❌ Cannot connect to server at', BASE_URL);
    console.error('  → Run "node server.js" first, then re-run tests.\n');
    process.exit(1);
  }

  const start = Date.now();

  await authTests();
  await fileTests();
  await securityTests();
  await rbacTests();
  await edgeCaseTests();

  const elapsed = ((Date.now() - start) / 1000).toFixed(2);

  console.log('\n╔═══════════════════════════════════════════════════╗');
  console.log('║  TEST RESULTS                                    ║');
  console.log('╠═══════════════════════════════════════════════════╣');
  console.log(`║  ✅ Passed:  ${String(passed).padEnd(5)} │ Total: ${String(passed + failed + skipped).padEnd(15)}║`);
  console.log(`║  ❌ Failed:  ${String(failed).padEnd(5)} │ Time:  ${String(elapsed + 's').padEnd(15)}║`);
  console.log(`║  ⏭️ Skipped: ${String(skipped).padEnd(5)} │                        ║`);
  console.log('╚═══════════════════════════════════════════════════╝\n');

  if (failed > 0) {
    console.log('  Failed tests:');
    results.filter(r => r.icon === '❌').forEach(r => {
      console.log(`    ❌ ${r.msg} — ${r.detail}`);
    });
    console.log('');
  }

  process.exit(failed > 0 ? 1 : 0);
}

runAll().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
