// ═══════════════════════════════════════════════════════════
//  ZenCrypt — API Client
//  Connects frontend to the Express backend (server.js)
//  Falls back to localStorage if server is unreachable
// ═══════════════════════════════════════════════════════════

const API = {
  baseURL: window.location.origin,
  token: localStorage.getItem('sv_jwt') || null,
  serverAvailable: false,

  // ─── HEADERS ───
  headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  },

  authHeaders() {
    const h = {};
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  },

  // ─── SAVE / CLEAR TOKEN ───
  setToken(token) {
    this.token = token;
    localStorage.setItem('sv_jwt', token);
  },

  clearToken() {
    this.token = null;
    localStorage.removeItem('sv_jwt');
  },

  // ─── CHECK SERVER ───
  async checkServer() {
    try {
      const res = await fetch(`${this.baseURL}/api/dashboard`, {
        method: 'GET',
        headers: this.headers(),
        signal: AbortSignal.timeout(2000),
      });
      this.serverAvailable = res.ok || res.status === 401;
      return this.serverAvailable;
    } catch {
      this.serverAvailable = false;
      return false;
    }
  },

  // ─── GENERIC REQUEST ───
  async request(method, path, body = null) {
    const opts = { method, headers: this.headers() };
    if (body && method !== 'GET') opts.body = JSON.stringify(body);

    const res = await fetch(`${this.baseURL}${path}`, opts);
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  },

  // ═══════════════════════════════════════════════
  //  AUTH ENDPOINTS
  // ═══════════════════════════════════════════════

  // POST /api/auth/signup
  async signup({ username, email, password, enable2FA }) {
    const data = await this.request('POST', '/api/auth/signup', {
      username, email, password, enable2FA,
    });
    return data;
  },

  // POST /api/auth/login
  async login({ username, password }) {
    const data = await this.request('POST', '/api/auth/login', {
      username, password,
    });

    if (data.requires2FA) {
      // Store temp token for 2FA verification
      return { requires2FA: true, tempToken: data.tempToken, hint: data.hint };
    }

    // Full login — save JWT
    this.setToken(data.token);
    return { success: true, user: data.user, token: data.token };
  },

  // POST /api/auth/verify-2fa
  async verify2FA({ tempToken, code }) {
    const data = await this.request('POST', '/api/auth/verify-2fa', {
      tempToken, code,
    });
    this.setToken(data.token);
    return { success: true, user: data.user, token: data.token };
  },

  // POST /api/auth/change-password
  async changePassword({ currentPassword, newPassword }) {
    return this.request('POST', '/api/auth/change-password', {
      currentPassword, newPassword,
    });
  },

  // POST /api/auth/toggle-2fa
  async toggle2FA() {
    return this.request('POST', '/api/auth/toggle-2fa');
  },

  // GET /api/auth/profile
  async getProfile() {
    return this.request('GET', '/api/auth/profile');
  },

  // Logout (client-side)
  logout() {
    this.clearToken();
  },

  // ═══════════════════════════════════════════════
  //  FILE ENDPOINTS
  // ═══════════════════════════════════════════════

  // POST /api/files/upload — Upload file (multipart)
  async uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${this.baseURL}/api/files/upload`, {
      method: 'POST',
      headers: this.authHeaders(),
      body: formData,
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Upload failed');
    return data;
  },

  // GET /api/files — List all user files
  async listFiles() {
    return this.request('GET', '/api/files');
  },

  // GET /api/files/:id — Read file metadata
  async getFile(fileId) {
    return this.request('GET', `/api/files/${fileId}`);
  },

  // GET /api/files/:id/download — Download file content
  async downloadFile(fileId) {
    const res = await fetch(`${this.baseURL}/api/files/${fileId}/download`, {
      headers: this.authHeaders(),
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Download failed');
    }

    const blob = await res.blob();
    const contentDisposition = res.headers.get('Content-Disposition');
    let filename = 'download';
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="(.+)"/);
      if (match) filename = match[1];
    }

    return { blob, filename };
  },

  // GET /api/files/:id/content — Read file content as text
  async readFileContent(fileId) {
    const res = await fetch(`${this.baseURL}/api/files/${fileId}/download`, {
      headers: this.authHeaders(),
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Read failed');
    }

    return res.text();
  },

  // DELETE /api/files/:id — Delete file
  async deleteFile(fileId) {
    return this.request('DELETE', `/api/files/${fileId}`);
  },

  // GET /api/files/:id/metadata — Get file metadata + permissions
  async getFileMetadata(fileId) {
    return this.request('GET', `/api/files/${fileId}/metadata`);
  },

  // POST /api/files/:id/share — Share file with user
  async shareFile(fileId, { username, permission }) {
    return this.request('POST', `/api/files/${fileId}/share`, {
      username, permission,
    });
  },

  // ═══════════════════════════════════════════════
  //  PUBLIC ENDPOINTS
  // ═══════════════════════════════════════════════

  // GET /api/public/users — List all public users
  async getPublicUsers() {
    return this.request('GET', '/api/public/users');
  },

  // ═══════════════════════════════════════════════
  //  SHARES ENDPOINT
  // ═══════════════════════════════════════════════

  // GET /api/shares — List files shared by current user
  async listShares() {
    return this.request('GET', '/api/shares');
  },

  // ═══════════════════════════════════════════════
  //  SECURITY & DASHBOARD ENDPOINTS
  // ═══════════════════════════════════════════════

  // GET /api/security/threats — Threat logs and stats
  async getSecurityData() {
    return this.request('GET', '/api/security/threats');
  },

  // GET /api/activity — User activity log
  async getActivity() {
    return this.request('GET', '/api/activity');
  },

  // GET /api/dashboard — Dashboard stats
  async getDashboard() {
    return this.request('GET', '/api/dashboard');
  },

  // ═══════════════════════════════════════════════
  //  ADMIN ENDPOINTS (require role: admin)
  // ═══════════════════════════════════════════════

  // GET /api/admin/users — List all users
  async adminGetUsers() {
    return this.request('GET', '/api/admin/users');
  },

  // PUT /api/admin/users/:id/role — Change user role
  async adminChangeRole(userId, role) {
    return this.request('PUT', `/api/admin/users/${userId}/role`, { role });
  },

  // DELETE /api/admin/users/:id — Delete user
  async adminDeleteUser(userId) {
    return this.request('DELETE', `/api/admin/users/${userId}`);
  },

  // GET /api/admin/files — All files system-wide
  async adminGetFiles() {
    return this.request('GET', '/api/admin/files');
  },

  // GET /api/admin/logs — All activity logs
  async adminGetLogs() {
    return this.request('GET', '/api/admin/logs');
  },

  // GET /api/admin/stats — System-wide stats
  async adminGetStats() {
    return this.request('GET', '/api/admin/stats');
  },
};

// ═══════════════════════════════════════════════
//  AUTO-DETECT SERVER ON LOAD
// ═══════════════════════════════════════════════

(async function detectServer() {
  const isServerMode = window.location.protocol === 'http:' || window.location.protocol === 'https:';

  if (isServerMode) {
    const available = await API.checkServer();
    if (available) {
      console.log('[ZenCrypt] 🟢 Server mode — connected to backend API');
      console.log('[ZenCrypt] API Base:', API.baseURL);
      window.USE_SERVER_API = true;
    } else {
      console.log('[ZenCrypt] 🟡 Server not responding — using localStorage mode');
      window.USE_SERVER_API = false;
    }
  } else {
    console.log('[ZenCrypt] 📁 File mode — using localStorage (no server)');
    window.USE_SERVER_API = false;
  }
})();

// ═══════════════════════════════════════════════
//  API ENDPOINT REFERENCE
// ═══════════════════════════════════════════════
//
//  ┌─────────────────────────────────────────────────────────────┐
//  │  AUTH ENDPOINTS                                             │
//  ├─────────┬───────────────────────────┬───────────────────────┤
//  │ Method  │ Endpoint                  │ Description           │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │ POST    │ /api/auth/signup          │ Register new user     │
//  │ POST    │ /api/auth/login           │ Login (returns JWT)   │
//  │ POST    │ /api/auth/verify-2fa      │ Verify OTP code       │
//  │ POST    │ /api/auth/change-password │ Update password        │
//  │ POST    │ /api/auth/toggle-2fa      │ Enable/disable 2FA   │
//  │ GET     │ /api/auth/profile         │ Get user profile      │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │  FILE ENDPOINTS                                             │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │ POST    │ /api/files/upload         │ Upload file (multipart)│
//  │ GET     │ /api/files                │ List all user files   │
//  │ GET     │ /api/files/:id            │ Get file info         │
//  │ GET     │ /api/files/:id/download   │ Download file         │
//  │ GET     │ /api/files/:id/metadata   │ File metadata + perms │
//  │ DELETE  │ /api/files/:id            │ Delete file           │
//  │ POST    │ /api/files/:id/share      │ Share with user       │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │  ADMIN ENDPOINTS (role: admin required)                     │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │ GET     │ /api/admin/users          │ List all users        │
//  │ PUT     │ /api/admin/users/:id/role │ Change user role      │
//  │ DELETE  │ /api/admin/users/:id      │ Delete user account   │
//  │ GET     │ /api/admin/files          │ All files (system)    │
//  │ GET     │ /api/admin/logs           │ All activity logs     │
//  │ GET     │ /api/admin/stats          │ System-wide stats     │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │  OTHER ENDPOINTS                                            │
//  ├─────────┼───────────────────────────┼───────────────────────┤
//  │ GET     │ /api/shares               │ List shared files     │
//  │ GET     │ /api/security/threats     │ Threat logs & stats   │
//  │ GET     │ /api/activity             │ Activity log          │
//  │ GET     │ /api/dashboard            │ Dashboard stats       │
//  └─────────┴───────────────────────────┴───────────────────────┘
//
//  RBAC Middleware Chain:
//    authenticateToken → requireRole('admin') → handler
//
//  All endpoints (except signup/login) require:
//    Authorization: Bearer <JWT_TOKEN>
//
