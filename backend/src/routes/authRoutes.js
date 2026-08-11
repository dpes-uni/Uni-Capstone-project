const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const {
  register,
  verifyEmail,
  resendVerification,
  login,
  verifyMfa,
  logout,
  me,
} = require('../controllers/authController');

const router = express.Router();

router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('A valid email is required').normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long'),
    body('role').optional().isIn(['student', 'agent', 'institution']),
  ],
  validate,
  register
);

router.get('/verify-email/:token', verifyEmail);

router.post(
  '/resend-verification',
  [body('email').isEmail().withMessage('A valid email is required').normalizeEmail()],
  validate,
  resendVerification
);

router.post(
  '/login',
  [
    body('email').isEmail().withMessage('A valid email is required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  login
);

router.post(
  '/verify-mfa',
  [
    body('loginId').notEmpty().withMessage('loginId is required'),
    body('code').isLength({ min: 6, max: 6 }).withMessage('Code must be 6 digits'),
  ],
  validate,
  verifyMfa
);

router.post('/logout', logout);
router.get('/me', protect, me);

module.exports = router;
