const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const { protect } = require('../middleware/auth');
const {
  listAssessments,
  getAssessment,
  createAssessment,
  updateAssessment,
  deleteAssessment,
} = require('../controllers/assessmentController');

const router = express.Router();

router.use(protect);

router.get('/', listAssessments);
router.get('/:id', getAssessment);

router.post(
  '/',
  [
    body('applicantName').trim().notEmpty().withMessage('Applicant name is required'),
    body('documentType')
      .optional()
      .isIn(['passport', 'national_id', 'drivers_license', 'academic_transcript', 'other']),
    body('notes').optional().isLength({ max: 2000 }),
  ],
  validate,
  createAssessment
);

router.patch(
  '/:id',
  [
    body('status').optional().isIn(['pending', 'in_review', 'verified', 'rejected']),
    body('notes').optional().isLength({ max: 2000 }),
  ],
  validate,
  updateAssessment
);

router.delete('/:id', deleteAssessment);

module.exports = router;
