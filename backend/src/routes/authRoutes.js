const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const {
  register,
  verifySignup,
  verifyEmail,
  resendVerification,
  login,
  verifyMfa,
  adminSignup,
  verifyAdminSignup,
  refresh,
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

router.post(
  '/register/verify',
  [
    body('signupId').notEmpty().withMessage('signupId is required'),
    body('code').matches(/^\d{6}$/).withMessage('OTP must be exactly 6 digits'),
  ],
  validate,
  verifySignup
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
    body('adminOnly').optional().isBoolean().withMessage('adminOnly must be boolean'),
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

router.post(
  '/admin-signup',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('A valid email is required').normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
    body('signupKey').notEmpty().withMessage('Administrator signup key is required'),
  ],
  validate,
  adminSignup
);

router.post(
  '/admin-signup/verify',
  [
    body('signupId').notEmpty().withMessage('signupId is required'),
    body('code').matches(/^\d{6}$/).withMessage('OTP must be exactly 6 digits'),
  ],
  validate,
  verifyAdminSignup
);

router.post('/logout', logout);
router.post('/refresh', refresh);
router.get('/me', protect, me);

module.exports = router;
