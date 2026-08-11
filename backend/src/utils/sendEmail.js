const nodemailer = require('nodemailer');

let transporter = null;
const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

if (smtpConfigured) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

/**
 * Sends an email if SMTP is configured, otherwise logs it to the console.
 * Always returns { delivered: boolean } so callers can decide whether to
 * also surface the content directly in the API response (dev convenience).
 */
async function sendEmail({ to, subject, html, text }) {
  if (!smtpConfigured) {
    console.log('\n----- DEV MODE EMAIL (SMTP not configured) -----');
    console.log(`To     : ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Body   : ${text || html}`);
    console.log('--------------------------------------------------\n');
    return { delivered: false };
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || '"Assure Docs" <no-reply@assuredocs.test>',
      to,
      subject,
      html,
      text,
    });
    return { delivered: true };
  } catch (err) {
    console.error('Failed to send email, falling back to console log:', err.message);
    console.log(`To: ${to} | Subject: ${subject} | Body: ${text || html}`);
    return { delivered: false };
  }
}

module.exports = { sendEmail, smtpConfigured };
