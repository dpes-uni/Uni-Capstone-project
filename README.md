# Assure Docs — MERN Backend & Frontend

A working **MongoDB + Express + React + Node.js** implementation of the *Assure Docs* identity
verification platform, built around the "AI-assisted anomaly detection and adaptive MFA" concept
from the original capstone brief.

It includes:

- Full authentication: signup, email verification, login, logout
- **Adaptive MFA** — a rule-based risk engine scores every login (new device, new IP, recent
  failed attempts) and only asks for a one-time email passcode when a login looks risky
- Account lockout after repeated failed attempts
- A protected **dashboard** with login activity and account stats
- A protected **assessments** workspace (create/track document verification cases)
- A dev-mode fallback so the whole thing runs **without any external email provider** — the
  verification link / OTP code is printed to the backend console and returned in the API
  response so you can copy-paste it straight into the UI

```
assure-docs/
├── backend/     Express + MongoDB API
├── frontend/    React (Vite) single-page app
└── README.md    ← you are here
```

---

## 1. Prerequisites

- **Node.js 18+** and npm — check with `node -v` and `npm -v`
- **MongoDB** running somewhere reachable, either:
  - a local install (`mongod` running on `localhost:27017`), **or**
  - a free [MongoDB Atlas](https://www.mongodb.com/atlas) cluster (get a connection string)

You do **not** need an email/SMTP account to run this locally — see "Dev-mode email" below.

---

## 2. Backend setup

```bash
cd backend
npm install
cp .env.example .env
```

Open `.env` and set at minimum:

```
MONGO_URI=mongodb://127.0.0.1:27017/assure_docs
JWT_SECRET=some_long_random_string
CLIENT_URL=http://localhost:5173
```

(Leave `SMTP_*` blank to use dev-mode email — see below.)

Start MongoDB if it isn't already running, e.g.:

```bash
mongod --dbpath /path/to/your/data/folder
```

Then start the API:

```bash
npm run dev      # auto-restarts on file changes (nodemon)
# or
npm start        # plain node
```

You should see:

```
Assure Docs API
----------------------------------------
Environment : development
Listening   : http://localhost:5000
Health check: http://localhost:5000/api/health
----------------------------------------
```

Optional — seed a demo account with sample assessments:

```bash
npm run seed
```

This creates `demo@assuredocs.test` / `Password123!` (already verified) plus three sample
assessments.

---

## 3. Frontend setup

Open a **second terminal**:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Vite will print a local URL, normally:

```
http://localhost:5173
```

Open that in your browser. The dev server proxies all `/api/*` requests to the backend on port
5000 (configured in `vite.config.js`), so you don't need to change anything else for local
development.

---

## 4. Using the app

1. Go to `http://localhost:5173` and click **Get started** to sign up.
2. Because no SMTP server is configured by default, the signup response includes a **dev
   verification link** shown directly on the page — click it to verify your account.
3. Sign in. On your **first** login from a new browser/device, the risk engine will flag it as
   medium/high risk and route you to a one-time-passcode screen. The code is shown on screen in
   dev mode (and printed in the backend terminal) — enter it to finish signing in.
4. Once verified, that device is remembered, so future logins from the same browser skip the
   extra step (as long as nothing else about the login looks unusual).
5. Explore the **Dashboard** (login activity, risk stats) and **Assessments** (create/track
   document verification cases) pages.

### Sending real emails (optional)

To send real emails instead of dev-mode links/codes, fill in the `SMTP_*` values in
`backend/.env` (e.g. a Gmail app password, Mailtrap, SendGrid SMTP, etc.) and restart the
backend. Once `SMTP_HOST`, `SMTP_USER` and `SMTP_PASS` are all set, the API automatically
switches from dev-mode logging to actually sending mail.

---

## 5. How adaptive MFA works

On every login attempt the backend (`backend/src/utils/riskEngine.js`) checks:

| Signal                          | Points |
|----------------------------------|--------|
| Device never seen before         | +40    |
| IP address never seen before     | +25    |
| 3+ recent failed login attempts  | +25    |
| 1–2 recent failed attempts       | +10    |

- **Score < 30** → low risk → signed in immediately, device remembered
- **Score 30–69** → medium risk → one-time passcode required
- **Score ≥ 70** → high risk → one-time passcode required

Thresholds are configurable via `RISK_MEDIUM_THRESHOLD` / `RISK_HIGH_THRESHOLD` in
`backend/.env`. This mirrors the rule-based half of the `ai/` module's design described in
`docs/AI_ARCHITECTURE.md` in the original project, implemented in plain JavaScript so the whole
stack runs without a separate Python process. The Python/ML module in `ai/` can later be wired in
as an additional signal alongside (or instead of) this rule engine.

---

## 6. API overview

All endpoints are prefixed with `/api`.

| Method | Endpoint                        | Auth | Description |
|--------|----------------------------------|------|--------------|
| GET    | `/health`                         | –    | Health check |
| POST   | `/auth/register`                  | –    | Create account, sends verification email |
| GET    | `/auth/verify-email/:token`       | –    | Verify email address |
| POST   | `/auth/resend-verification`       | –    | Resend verification email |
| POST   | `/auth/login`                     | –    | Step 1 of login (password check + risk score) |
| POST   | `/auth/verify-mfa`                | –    | Step 2 of login (submit OTP code) |
| POST   | `/auth/logout`                    | –    | Clear session cookie |
| GET    | `/auth/me`                        | ✅   | Current user profile |
| GET    | `/users/dashboard-summary`        | ✅   | Stats + recent activity for the dashboard |
| GET    | `/users/login-activity`           | ✅   | Full login activity log |
| PATCH  | `/users/me`                       | ✅   | Update name/role |
| GET    | `/assessments`                    | ✅   | List your assessments |
| POST   | `/assessments`                    | ✅   | Create an assessment |
| PATCH  | `/assessments/:id`                | ✅   | Update status/notes |
| DELETE | `/assessments/:id`                | ✅   | Delete an assessment |

Protected routes accept the JWT either as `Authorization: Bearer <token>` (what the React app
uses) or as an `httpOnly` cookie set automatically on login.

---

## 7. Troubleshooting

- **"MongoDB connection error"** — make sure `mongod` is running, or that your Atlas
  `MONGO_URI` (including username/password) is correct and your IP is allow-listed on Atlas.
- **CORS errors in the browser console** — confirm `CLIENT_URL` in `backend/.env` matches the
  URL you're loading the frontend from (default `http://localhost:5173`).
- **Frontend can't reach the API** — confirm the backend is running on port 5000 and
  `frontend/.env`'s `VITE_API_URL` is either `/api` (proxy mode) or a full URL to your backend.
- **"Please verify your email before signing in"** — use the dev verification link shown after
  signup, or check the backend terminal for the printed link.
- **Didn't get an OTP screen on a second device** — that's expected once a device/IP is
  trusted; delete the user in MongoDB (or use a fresh browser/incognito window) to see the flow
  again.

---

## 8. Production notes

This is a capstone-grade reference implementation. Before deploying it for real users, consider:

- Serving the frontend as a static build (`npm run build` in `frontend/`) behind a CDN or the
  Express server itself, rather than the Vite dev server
- Moving the JWT out of `localStorage` and relying solely on the `httpOnly` cookie already set
  by the backend, to reduce XSS exposure
- Adding refresh tokens / shorter-lived access tokens
- Configuring a real SMTP provider (see section 4) and removing the `devVerificationLink` /
  `devOtpCode` fields from API responses in production (they are already only included when
  `NODE_ENV !== 'production'` or email delivery fails)
- Adding automated tests (a `tests/` folder is already present in the original project layout)


## Administrator signup + Gmail OTP

The project now includes a protected administrator signup flow:

1. Open `/admin/signup`.
2. Enter administrator details and the private `ADMIN_SIGNUP_KEY`.
3. The backend generates a 6-digit OTP and sends it through Gmail SMTP.
4. Open `/admin/verify-otp` and enter the OTP.
5. Only after successful OTP verification is the `admin` user created in MongoDB with `isVerified: true`.
6. Sign in through `/admin/login`. The existing adaptive MFA can still require another OTP for unusual logins.

### Gmail setup

Use a Google account with 2-Step Verification enabled and create a Google App Password. Put the App Password in `backend/.env` as `SMTP_PASS`. Do not use your normal Gmail password.

Example:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourgmail@gmail.com
SMTP_PASS=your_16_character_google_app_password
SMTP_FROM="Assure Docs <yourgmail@gmail.com>"
ADMIN_SIGNUP_KEY=use-a-long-private-admin-signup-key
ADMIN_OTP_EXPIRES_MINUTES=10
```

Also set `MONGO_URI` to your MongoDB database. Never commit `.env` or the Gmail App Password to Git.

For production, keep the admin signup key private or replace public admin signup with an invitation-only workflow.


## Email OTP authentication

Assure Docs now requires a Gmail/email OTP every time a user successfully signs in and before a new user account is created.

### Signup
1. User enters name, email, role and password.
2. Backend creates a pending signup OTP record in MongoDB.
3. A 6-digit OTP is sent to the same email address through Gmail SMTP.
4. The account is created and marked verified only after the OTP is correct.

### Sign in
1. User enters email and password.
2. Credentials are checked.
3. A new 6-digit OTP is generated and sent to the same email address on every successful credential check.
4. No session token is issued until the OTP is verified.

This applies to both normal users and administrators. The administrator signup flow also continues to require `ADMIN_SIGNUP_KEY` before sending its OTP.

### Gmail SMTP
Copy `backend/.env.example` to `backend/.env` and configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM`. For Gmail, use a Google App Password rather than the normal Gmail password.

## Gmail OTP setup (required)

The authentication flow now sends a fresh 6-digit OTP to the email address entered during **every signup and every sign-in**. The OTP is not displayed in the browser.

1. Enable 2-Step Verification on the Gmail account that will send Assure Docs emails.
2. Create a Google App Password for that account.
3. Copy `backend/.env.example` to `backend/.env`.
4. Set these values:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourgmail@gmail.com
SMTP_PASS=your_16_character_google_app_password
SMTP_FROM="Assure Docs <yourgmail@gmail.com>"
REQUIRE_SMTP=true
```

5. Set your MongoDB and admin signup settings in the same `.env` file.
6. Restart the backend with `npm run dev`.

The backend verifies the Gmail SMTP connection at startup. If Gmail is not configured or the App Password is invalid, the server stops with a clear error instead of showing a development OTP.

**Security:** never commit `backend/.env`, your Gmail password, or your Google App Password to Git.
