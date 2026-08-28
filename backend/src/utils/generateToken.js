const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');
const logger = require('./logger');

const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN_MS =
  (Number(process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS || 7) * 24 * 60 * 60 * 1000) ||
  7 * 24 * 60 * 60 * 1000;

const COOKIE_NAME = 'token';
const REFRESH_COOKIE_NAME = 'refreshToken';

function generateAuthToken(userId) {
  return jwt.sign({ sub: userId.toString() }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

function generateRandomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function deviceFingerprint(req) {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const acceptLang = req.headers['accept-language'] || '';
  return hashToken(`${userAgent}::${acceptLang}`);
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

/** Set the short-lived access token as an httpOnly cookie (fallback for clients without localStorage). */
function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
}

/** Issue a refresh token, store its hash, and send it as an httpOnly cookie. Returns the raw token. */
async function issueRefreshToken(res, userId, { req }) {
  const { rawToken, doc } = await RefreshToken.issue(userId, {
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'] || 'unknown',
    expiresInMs: REFRESH_TOKEN_EXPIRES_IN_MS,
  });

  res.cookie(REFRESH_COOKIE_NAME, rawToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: REFRESH_TOKEN_EXPIRES_IN_MS,
  });

  return rawToken;
}

/** Clear the refresh cookie (and the access-token cookie). */
function clearAuthCookies(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'lax' });
  res.clearCookie(REFRESH_COOKIE_NAME, { httpOnly: true, sameSite: 'lax' });
}

/** Read the raw refresh token from the cookie or Authorization header. */
function getRefreshToken(req) {
  if (req.cookies && req.cookies[REFRESH_COOKIE_NAME]) {
    return req.cookies[REFRESH_COOKIE_NAME];
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('RefreshBearer ')) {
    return authHeader.slice('RefreshBearer '.length);
  }
  return null;
}

module.exports = {
  generateAuthToken,
  generateRandomToken,
  hashToken,
  deviceFingerprint,
  getClientIp,
  setAuthCookie,
  issueRefreshToken,
  clearAuthCookies,
  getRefreshToken,
  ACCESS_TOKEN_EXPIRES_IN,
};
