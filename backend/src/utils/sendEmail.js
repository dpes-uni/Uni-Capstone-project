const nodemailer = require('nodemailer');
const logger = require('./logger');

let transporter = null;

function isSmtpConfigured() {
  return Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
  );
}

function createTransporter() {
  if (!isSmtpConfigured()) return null;

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

/** Verify Gmail SMTP during server startup when real email delivery is required. */
async function verifyEmailTransport() {
  const required = String(process.env.REQUIRE_SMTP || 'true').toLowerCase() === 'true';

  if (!isSmtpConfigured()) {
    if (required) {
      throw new Error(
        'Gmail SMTP is not configured. Set SMTP_USER and SMTP_PASS in backend/.env. SMTP_PASS must be a Google App Password.'
      );
    }
    return false;
  }

  transporter = createTransporter();
  await transporter.verify();
  logger.info(`Gmail SMTP ready: ${process.env.SMTP_USER}`);
  return true;
}

/** Send a real email. OTPs are never returned to the browser in real-email mode. */
async function sendEmail({ to, subject, html, text }) {
  if (!transporter) {
    if (String(process.env.REQUIRE_SMTP || 'true').toLowerCase() === 'true') {
      throw new Error('Gmail SMTP is not configured. Add SMTP settings to backend/.env and restart the server.');
    }
    transporter = createTransporter();
  }

  if (!transporter) {
    if (process.env.NODE_ENV !== 'production') {
      logger.warn('Email not delivered (SMTP not configured). The OTP was returned as devOtpCode in the API response.');
    }
    return { delivered: false };
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    html,
    text,
  });

  return { delivered: true };
}

module.exports = { sendEmail, verifyEmailTransport, isSmtpConfigured };
