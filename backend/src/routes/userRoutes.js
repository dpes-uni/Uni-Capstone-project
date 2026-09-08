const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const {
  getLoginActivity,
  getDashboardSummary,
  updateProfile,
  getSessionTimeout,
} = require('../controllers/userController');

const router = express.Router();

router.use(protect);

router.get('/login-activity', getLoginActivity);
router.get('/dashboard-summary', getDashboardSummary);
router.get('/session-timeout', getSessionTimeout);
router.patch(
  '/me',
  [
    body('name').optional().trim().notEmpty(),
    body('role').optional().isIn(['student', 'agent', 'institution']),
  ],
  validate,
  updateProfile
);

module.exports = router;
