const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect, stepUpProtect } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');
const {
  getOverview,
  getSessionStatus,
  updateUserRole,
  listAssessments,
  getAssessmentDocument,
  reviewAssessment,
} = require('../controllers/adminController');

const router = express.Router();
router.use(protect, requireRole('admin'));

router.get('/overview', getOverview);
router.get('/session-status', getSessionStatus);
router.patch(
  '/users/:id/role',
  stepUpProtect,
  [body('role').isIn(['admin', 'student', 'agent', 'institution']).withMessage('Invalid role')],
  validate,
  updateUserRole
);

// Document verification queue: list everyone's assessments, view a document,
// verify/reject it.
router.get('/assessments', listAssessments);
router.get('/assessments/:id/document', stepUpProtect, getAssessmentDocument);
router.patch(
  '/assessments/:id/review',
  stepUpProtect,
  [
    body('status').isIn(['verified', 'rejected', 'in_review']).withMessage('Invalid status'),
    body('notes').optional().isLength({ max: 2000 }),
  ],
  validate,
  reviewAssessment
);

module.exports = router;
