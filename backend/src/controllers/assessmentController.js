const Assessment = require('../models/Assessment');

// @route GET /api/assessments
async function listAssessments(req, res, next) {
  try {
    const { status } = req.query;
    const filter = { owner: req.user._id };
    if (status) filter.status = status;

    const assessments = await Assessment.find(filter).sort({ createdAt: -1 });
    res.json({ assessments });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/assessments/:id
async function getAssessment(req, res, next) {
  try {
    const assessment = await Assessment.findOne({ _id: req.params.id, owner: req.user._id });
    if (!assessment) return res.status(404).json({ message: 'Assessment not found' });
    res.json({ assessment });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/assessments
async function createAssessment(req, res, next) {
  try {
    const { applicantName, documentType, notes } = req.body;

    // Simple deterministic-ish demo risk score so the UI has something
    // meaningful to display; a real system would call the AI risk service.
    const riskScore = Math.floor(Math.random() * 100);

    const assessment = await Assessment.create({
      owner: req.user._id,
      applicantName,
      documentType,
      notes,
      riskScore,
      status: riskScore > 70 ? 'in_review' : 'pending',
    });

    res.status(201).json({ message: 'Assessment created', assessment });
  } catch (err) {
    next(err);
  }
}

// @route PATCH /api/assessments/:id
async function updateAssessment(req, res, next) {
  try {
    const { status, notes } = req.body;
    const assessment = await Assessment.findOne({ _id: req.params.id, owner: req.user._id });
    if (!assessment) return res.status(404).json({ message: 'Assessment not found' });

    if (status) assessment.status = status;
    if (notes !== undefined) assessment.notes = notes;

    await assessment.save();
    res.json({ message: 'Assessment updated', assessment });
  } catch (err) {
    next(err);
  }
}

// @route DELETE /api/assessments/:id
async function deleteAssessment(req, res, next) {
  try {
    const assessment = await Assessment.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    if (!assessment) return res.status(404).json({ message: 'Assessment not found' });
    res.json({ message: 'Assessment deleted' });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  listAssessments,
  getAssessment,
  createAssessment,
  updateAssessment,
  deleteAssessment,
};
