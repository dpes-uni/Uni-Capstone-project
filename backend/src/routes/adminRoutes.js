const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');
const { getOverview, updateUserRole } = require('../controllers/adminController');

const router = express.Router();
router.use(protect, requireRole('admin'));

router.get('/overview', getOverview);
router.patch(
  '/users/:id/role',
  [body('role').isIn(['admin', 'student', 'agent', 'institution']).withMessage('Invalid role')],
  validate,
  updateUserRole
);

module.exports = router;
