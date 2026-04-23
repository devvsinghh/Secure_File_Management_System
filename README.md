# Secure File Management System

## Overview

Secure File Management System, branded in the interface as `ZenCrypt`, is a web-based application for storing, organizing, and sharing files with multiple layers of security. It is designed to reduce common risks in file handling by combining authentication, encryption, malware detection, access control, and audit logging in a single system.

The project solves a practical problem: users often need a simple way to upload and manage files without giving up visibility, control, or security. This system addresses that by protecting file access, scanning uploads for suspicious content, encrypting stored files, and recording important activity for monitoring and review.

## Features

- Secure user registration and login
- JWT-based authentication for protected API access
- Password hashing with `bcryptjs`
- Optional two-factor authentication (2FA) using OTP verification
- File upload with validation and size restrictions
- File download with server-side decryption
- AES-256-CBC encryption for stored files
- Secure file metadata storage in SQLite
- File listing, viewing, and deletion
- File sharing between users
- Permission levels for shared files: `read`, `write`, and `admin`
- Role-based access control (RBAC) with `admin` and `user` roles
- Malware and suspicious-pattern scanning on uploaded files
- Detection of potentially dangerous file types
- Basic protection against SQL injection, XSS, and buffer-overflow-style input patterns
- Activity logging and threat logging
- Dashboard statistics for users
- Admin dashboard for managing users, files, logs, and system statistics
- Static frontend served directly by the Express backend
- Client-side fallback mode using `localStorage` when the backend is unavailable

## Tech Stack

### Backend

- Node.js
- Express.js
- better-sqlite3
- JSON Web Tokens (`jsonwebtoken`)
- `bcryptjs`
- `multer`
- `express-validator`
- `helmet`
- `cors`
- Native Node.js modules: `crypto`, `fs`, `path`

### Frontend

- HTML5
- CSS3
- Vanilla JavaScript

### Database and Storage

- SQLite (`ZenCrypt.db`)
- Local file storage in the `uploads/` directory

### Testing

- Custom Node.js test suite in `tests/test_suite.js`

## Project Structure

```text
Secure_File_Management_System/
├── api.js                  # Frontend API client for backend communication
├── app.js                  # Main frontend application logic
├── index.html              # Main UI entry point
├── style.css               # Application styling
├── server.js               # Express server, auth, file APIs, security logic
├── package.json            # Project metadata and dependencies
├── tests/
│   └── test_suite.js       # End-to-end style API test suite
├── uploads/                # Uploaded and encrypted files
├── ZenCrypt.db             # SQLite database
├── System_management/      # Additional copy of application files in the repo
└── node_modules/           # Installed dependencies
```

### Main Files Explained

- `server.js`: Handles authentication, authorization, file upload/download, encryption, sharing, logging, and admin routes.
- `app.js`: Powers the client-side interface, dashboard, local interactions, and fallback mode.
- `api.js`: Connects the frontend to the backend API and manages JWT usage on the client.
- `index.html`: Provides the landing page, login/signup UI, dashboard views, admin panel, and modal structure.
- `tests/test_suite.js`: Contains automated tests for authentication, file handling, and protected routes.

## How It Works

1. A user opens the application in the browser at `http://localhost:3000`.
2. The user signs up with a username, email, and password.
3. The backend validates the input and stores the account securely in SQLite.
4. Passwords are hashed with `bcryptjs` before storage.
5. If 2FA is enabled, the user must complete OTP verification during login.
6. After successful authentication, the backend issues a JWT token.
7. The frontend stores the token and includes it in future protected API requests.
8. When a file is uploaded, the backend validates the request, checks file size, and blocks risky file extensions.
9. The server scans file content for suspicious signatures and attack patterns such as malware markers, injection strings, and XSS-like content.
10. If critical threats are detected, the upload is rejected.
11. If the file passes validation, the backend encrypts it with AES-256-CBC and stores it in the `uploads/` directory.
12. File metadata such as owner, size, MIME type, scan result, and encryption IV is stored in SQLite.
13. Users can view their files, download them, delete them, and share them with other users.
14. Shared files are controlled through explicit permission levels.
15. Admin users can review all users, files, logs, and system-wide security statistics.
16. Activity logs and threat logs provide traceability for security and operational events.

## Installation & Setup

### Prerequisites

- Node.js
- npm

### Clone the Repository

```bash
git clone https://github.com/devvsinghh/Secure_File_Management_System.git
cd Secure_File_Management_System
```

### Install Dependencies

```bash
npm install
```

### Run the Application

```bash
npm start
```

The server starts on:

```text
http://localhost:3000
```

### Run the Test Suite

Start the server first, then run:

```bash
node tests/test_suite.js
```

## Usage

### For Regular Users

- Create an account or log in with existing credentials.
- Enable 2FA if you want an additional authentication layer.
- Upload files through the web interface.
- View files in your personal dashboard.
- Download files when needed.
- Delete files you own or administer.
- Share files with other users by assigning a permission level.
- Review personal activity logs and threat history from the dashboard.

### For Admin Users

- View all registered users
- Change user roles
- Delete users
- Inspect all stored files
- Review activity logs
- Review threat statistics across the system

## Security Features

- `bcryptjs` password hashing for user credentials
- JWT-based session handling for authenticated routes
- Optional OTP-based two-factor authentication
- AES-256-CBC encryption for uploaded file contents
- SQLite parameterized queries to reduce SQL injection risk
- Request validation with `express-validator`
- Secure HTTP headers with `helmet`
- CORS handling through `cors`
- Upload size limits via `multer`
- Blocking of dangerous executable file types such as `.exe`, `.bat`, `.cmd`, `.ps1`, and `.msi`
- Rate limiting for sensitive endpoints such as signup, login, and 2FA verification
- Threat logging for suspicious uploads
- Activity logging with user and IP context
- Role-based access control for admin-only operations
- File-level sharing permissions for controlled collaboration

## Future Improvements

- Replace the demo-style OTP flow with real email or authenticator-app delivery
- Move JWT and encryption secrets to environment variables instead of generating them at runtime
- Add refresh tokens and persistent session management
- Introduce stronger file-type verification based on MIME sniffing and content analysis
- Add folder persistence and management to the backend API
- Add file versioning and restore functionality
- Support cloud object storage for production deployments
- Add automated unit/integration tests to an npm test script
- Add Docker support and environment-based configuration for easier deployment
- Implement audit export and compliance reporting

## Author

- Repository owner: [devvsinghh](https://github.com/devvsinghh)

