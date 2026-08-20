const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const assessmentRoutes = require('./routes/assessmentRoutes');
const adminRoutes = require('./routes/adminRoutes');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const logger = require('./utils/logger');

const app = express();

// --- core middleware ---
// Security headers: CSP, X-Frame-Options, HSTS (prod), X-Content-Type-Options, etc.
// CSP is relaxed outside production so the Vite dev server / API docs render without friction.
app.use(
  helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    crossOriginEmbedderPolicy: false,
    strictTransportSecurity:
      process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
  })
);
app.use(
  cors({
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    credentials: true,
  })
);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// HTTP request logging routed through the structured logger.
if (process.env.NODE_ENV !== 'test') {
  app.use(
    morgan(
      process.env.NODE_ENV === 'production' ? 'combined' : 'dev',
      {
        stream: {
          write: (message) => logger.http(message.trim()),
        },
      }
    )
  );
}

// --- rate limiting for auth endpoints (brute force protection) ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
});
app.use('/api/auth', authLimiter);

// --- health checks ---
const DB_STATES = ['disconnected', 'connected', 'connecting', 'disconnecting'];

// Liveness: the process is up. Includes dependency status for observability
// without failing the probe (the backend can still serve some routes without
// Mongo/AI, and the login controller falls back to rule-based risk scoring).
app.get('/api/health', async (req, res) => {
  const mongoose = require('mongoose');

  let aiStatus = 'unknown';
  try {
    const aiService = require('./services/aiService');
    aiStatus = (await aiService.isHealthy()) ? 'healthy' : 'unavailable';
  } catch (err) {
    logger.warn('health: AI check failed', { error: err.message });
    aiStatus = 'unavailable';
  }

  res.json({
    status: 'ok',
    service: 'assure-docs-backend',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    database: { state: DB_STATES[mongoose.connection.readyState] || 'unknown' },
    aiService: aiStatus,
    memory: {
      rssMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      heapUsedMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    },
  });
});

// Readiness: true only when the services the app depends on are reachable.
// Used by the Docker healthcheck / orchestrators.
app.get('/api/health/ready', async (req, res) => {
  const mongoose = require('mongoose');
  const dbReady = mongoose.connection.readyState === 1;

  if (!dbReady) {
    return res
      .status(503)
      .json({ status: 'not_ready', database: { state: DB_STATES[mongoose.connection.readyState] || 'unknown' } });
  }

  return res.json({ status: 'ready', database: { state: 'connected' } });
});

// --- routes ---
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/assessments', assessmentRoutes);
app.use('/api/admin', adminRoutes);

// --- 404 + error handling ---
app.use(notFound);
app.use(errorHandler);

module.exports = app;
