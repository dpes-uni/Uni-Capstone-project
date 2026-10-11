# AI-Assisted Anomaly Detection & Adaptive MFA Cybersecurity Solution

A capstone project implementing an **AI-assisted anomaly detection and adaptive multi-factor authentication (MFA)** cybersecurity solution, with Assure Docs serving as the supporting identity verification application environment.

## Overview

This project implements a layered security approach combining:
- **Rule-based risk analysis** for login attempts
- **AI/ML-based anomaly detection** (Python service) 
- **Adaptive MFA** with step-up verification and re-authentication flows
- **Session monitoring** with risk accumulation and decay
- **Context-change detection** for suspicious activity
- **Comprehensive security event logging**

The solution protects user accounts by continuously assessing risk during authentication and active sessions and  prompts for additional verification when anomalous behavior is detected.

## Key Features

### Authentication & Authorization
Users have to register with the required OTP verification via email.Users need to register with the required OTP verification via email.
- Validate credentials during login + require email OTP for all successful logins
- Instant access to files and folders based on user roles (Student, Agent, Institution, Administrator)
JWT access tokens (15 minutes) + rotating refresh tokens (7 days)
- Signup flow for the admin with unique OTP and private key protection

### Adaptive Risk Assessment
- **Rule based engine**: Logins are scored according to new device/IP, failed logins, trusted device status
The service is built on Python and uses the Random Forest classifier for anomaly detection.
Combined decision: Higher score of the Rule-based and AI assessment is used to decide the risk level
- Risk thresholds: medium (30) and high (61) risk levels can be set using environment variables
- Logins from impossible travel locations are logged as flags

### Session Security
- 24/7 monitoring of sessions with behavioral tracking
- Risk accumulation based on suspicious events based on time decay.
- Device detection, browser detection, OS detection, IP detection, location detection, VPN detection (context change detection)
- **Re-authentication required**: If triggered, within 10 minutes the user must re-authenticate.
- Step-up verification: Action-level MFA on sensitive operations (2 minutes verification window)
When the user logs out or times out, the session will be automatically cleaned up.

### Security Controls
If logon attempts are made more than a certain number of times, the account is locked.The account is locked if the logon attempts are made more than a certain number of times (configurable).
The use of device fingerprinting and trusted device management.Use of device fingerprinting and trusted device management.
- Blocking of IP addresses and VPNs/Proxy detection
Successful login history is used to help trust location learning.Successful login history is used for trusted location learning.
- Rapid-action detection (behavioral biometrics)
- Security event logging for audit trails

### Application Functionality
- Dashboard: Activity and risk statistics for logins
Assessments workspace: Document verification cases and track them (Assure Docs context)
Administrator overview: System-wide statistics and active session monitoring.
- **Role management**: Change role (with step-up protection for role changes)

## Technology Stack

- **Backend**: Node.js + Express + MongoDB (MERN stack)
- **Frontend**: React + Vite
- **AI Service**: Python + Flask + scikit-learn (Random Forest classifier)
- **Communication**: RESTful APIs with JSON payloads
- **Containerization**: Docker Compose for orchestration

## Getting Started

### Prerequisites
- **Node.js 18+** and npm
- **MongoDB** (local installation or MongoDB Atlas)
- **Python 3.9+** (for AI service, optional for basic functionality)
- **Docker & Docker Compose** (optional, for containerized deployment)

### Backend Setup
```bash
cd backend
npm install
cp .env.example .env
```

Configure `.env` with at minimum:
```env
MONGO_URI=mongodb://127.0.0.1:27017/assure_docs
JWT_SECRET=some_long_random_string
CLIENT_URL=http://localhost:5173
```

Start MongoDB if not running:
```bash
# Local MongoDB
mongod

# OR using Docker (if installed)
docker-compose up -d mongodb
```

Start the API:
```bash
npm run dev      # Auto-restarts on file changes
# or
npm start        # Plain Node.js
```

Optional - seed demo account:
```bash
npm run seed     # Creates demo@assuredocs.test / Password123!
```

### AI Service Setup 
```bash
cd ai
pip install -r requirements.txt  # If using virtual environment
python src/main.py               # Starts on http://127.0.0.1:8000
```
Set `AI_SERVICE_URL` in backend `.env` if running locally.

### Frontend Setup
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```
Vite will be available at http://localhost:5173 (proxies `/api` to backend on port 5001).

### Docker Compose (Full Stack)
```bash
docker-compose up --build
```
Services:
- MongoDB: `mongodb://localhost:27017`
- Backend API: `http://localhost:5001`
- AI Service: `http://localhost:8000`
- Frontend: `http://localhost:5173`

## Usage Guide

### Regular User Flow
1. **Signup**: Provide name, email, password, role → receive email OTP → verify OTP to create account
2. **Login**: Enter email/password → receive email OTP (always required) → verify OTP to access account
3. **Dashboard**: View login activity, risk statistics, and session information
4. **Assessments**: Create and manage document verification cases
5. **Profile Updates**: Modify name/role (requires step-up verification for role changes)

### Administrator Flow
1. **Admin Signup**: Visit `/admin/signup`, provide details + private `ADMIN_SIGNUP_KEY` → receive email OTP → verify
2. **Admin Login**: Same as regular user but gains access to admin endpoints
3. **Admin Dashboard**: System overview, active sessions, user management

### Security Flows Triggered by Anomalous Behavior
- **Context Change** (new device/location): Login requires OTP (always) + may trigger re-authentication requirement
- **High Risk Score** (≥61): Session marked for re-authentication (10-minute window to verify via `/auth/reauth/*`)
- **Critical Risk Score** (≥81): Same as high risk but with stricter action thresholds
- **Sensitive Actions**: Role changes, document verification, etc. require step-up verification (2-minute window)

## API Reference

### Authentication (`/api/auth/*`)
- `POST /register` - Begin signup (returns OTP for dev mode or sends via email)
- `POST /register/verify` - Complete signup with OTP
- `POST /login` - Step 1: credentials + risk assessment (always requires OTP via next step)
- `POST /verify-mfa` - Step 2: submit login OTP
- `POST /refresh` - Rotate access/refresh tokens
- `POST /logout` - End session, revoke refresh token
- `GET /me` - Current user profile
- `POST /reauth/request` - Initiate re-authentication (when session high/critical risk)
- `POST /reauth/verify` - Complete re-authentication with OTP
- `POST /stepup/request` - Request step-up verification for sensitive actions
- `POST /stepup/verify` - Complete step-up verification with OTP

### User (`/api/users/*`) - Protected
- `GET /dashboard-summary` - Stats for dashboard view
- `GET /login-activity` - Full login history with risk scores
- `PATCH /me` - Update profile (name/role)

### Administrator (`/api/admin/*`) - Protected + Admin Role
- `GET /overview` - System statistics
- `GET /session-status` - Current session risk state
- `GET /active-sessions` - Monitor all active sessions
- `PATCH /users/:id/role` - Change user role (requires step-up verification)

### Assessments (`/api/assessments/*`) - Protected
- `GET /assessments` - List user's assessments
- `POST /assessments` - Create new assessment
- `PATCH /assessments/:id` - Update assessment status/notes
- `DELETE /assessments/:id` - Delete assessment

### Health & Monitoring
- `GET /api/health` - Basic service status
- `GET /api/health/ready` - MongoDB connection status
- `GET /api/metrics` - Prometheus metrics

## Token Model

### Access Token
- **Format**: JWT (stateless)
- **Expiry**: 15 minutes
- **Storage**: 
  - `Authorization: Bearer <token>` header (used by frontend)
  - httpOnly cookie named `token` (duplicate for robustness)
- **Usage**: Sent with each request to protected endpoints

### Refresh Token
- **Format**: Opaque string (hashed in MongoDB)
- **Expiry**: 7 days
- **Storage**: httpOnly cookie named `refreshToken` only (never exposed to JavaScript)
- **Rotation**: New token issued on each use via `/api/auth/refresh`, old token revoked
- **Revocation**: On logout, explicit revocation, or password/security events

### Security Properties
- Refresh tokens are hashed before storage (like passwords)
- Access tokens contain only user ID and issuance/expiry claims
- Tokens are invalidated on password change or security events
- No sensitive data stored in tokens

## Documentation

- [AI Architecture](docs/AI_ARCHITECTURE.md) - Design of the Python-based AI/ML risk assessment service
- AI Setup - Instructions for configuring and running the anomaly detection service
- Data Dictionary - Schema definitions for login attempts, session events, and security events
- Model Evaluation - Performance metrics and validation results for the ML model
- API Reference - Detailed endpoint specifications (see API section above)


## Configuration

Key environment variables in backend `.env`:

| Variable | Purpose | Default |
|----------|---------|---------|
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/assure_docs` |
| `JWT_SECRET` | Secret for signing access tokens | *Required* |
| `JWT_REFRESH_SECRET` | Secret for signing refresh tokens | *Required* |
| `AI_SERVICE_URL` | URL of Python AI service | `http://127.0.0.1:8000` |
| `SMTP_*` | Email configuration (leave blank for dev mode) | *Blank* |
| `CLIENT_URL` | Frontend URL for CORS/email links | `http://localhost:5173` |
| `RISK_MEDIUM_THRESHOLD` | Score triggering medium risk | `30` |
| `RISK_HIGH_THRESHOLD` | Score triggering high risk | `61` |
| `RISK_CRITICAL_THRESHOLD` | Score triggering critical risk | `81` |
| `OTP_EXPIRY_MINUTES` | Validity period for OTP codes | `10` |
| `SESSION_RISK_DECAY_PER_SECOND` | Risk decay rate per second | `0.05` |
| `REAUTH_REQUIRED_WINDOW_MS` | Time to complete re-authentication | `600000` (10 min) |
| `STEP_UP_VERIFY_WINDOW_MS` | Time to complete step-up verification | `120000` (2 min) |

## Development Notes

### Email Handling
- **Development Mode**: When SMTP not configured, OTP codes and verification links are:
  1. Printed to backend console
  2. Returned in API responses (for dev/testing only)
- **Production Mode**: Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, and set `REQUIRE_SMTP=true`

### Docker Compose Services
The `docker-compose.yml` defines five services:
1. `mongodb` - Database persistence
2. `backend` - Node.js/Express API
3. `ai-service` - Python anomaly detection
4. `frontend` - React/Vite application
5. `redis` - Optional cache/session store

### Testing
- Backend: `npm test` (Jest)
- Frontend: `npm run test` (Vitest)
- Tests cover authentication flows, risk assessment, and API endpoints

## Project Context

This is a capstone project on the research and implementation of anomaly detection and adaptive MFA (Multi-Factor Authentication) cybersecurity controls using AI. The Assure Docs identity verification platform is designed to be:
- A realistic application environment to test security features
A demonstration context of the protection of user data provided by these controls.
A testbed for exploring trade-offs between usability and security in adaptive authentication.

It's not about the document verification functionality of Assure Docs, but the layered security approach of rule-based analysis, ML-based anomaly detection and adaptive verification flows.