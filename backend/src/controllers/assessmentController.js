const path = require('path');
const fs = require('fs');
const Assessment = require('../models/Assessment');
const { UPLOAD_DIR } = require('../middleware/upload');

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
    if (assessment.documentFile && assessment.documentFile.storedName) {
      fs.unlink(path.join(UPLOAD_DIR, assessment.documentFile.storedName), () => {});
    }
    res.json({ message: 'Assessment deleted' });
  } catch (err) {
    next(err);
  }
}

// @route POST /api/assessments/:id/document
// Owner-only: upload (or replace) the identity document for their own
// assessment. Uploading resets the status back to "in_review" so it
// reappears in the admin verification queue.
async function uploadDocument(req, res, next) {
  try {
    const assessment = await Assessment.findOne({ _id: req.params.id, owner: req.user._id });
    if (!assessment) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(404).json({ message: 'Assessment not found' });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Remove the previous file, if replacing an earlier upload.
    if (assessment.documentFile && assessment.documentFile.storedName) {
      fs.unlink(path.join(UPLOAD_DIR, assessment.documentFile.storedName), () => {});
    }

    assessment.documentFile = {
      originalName: req.file.originalname,
      storedName: req.file.filename,
      mimeType: req.file.mimetype,
      size: req.file.size,
      uploadedAt: new Date(),
    };
    assessment.status = 'in_review';
    assessment.reviewedBy = undefined;
    assessment.reviewedAt = undefined;

    await assessment.save();
    res.json({ message: 'Document uploaded', assessment });
  } catch (err) {
    next(err);
  }
}

// @route GET /api/assessments/:id/document
// Owner-only: view/download the document they uploaded.
async function getOwnDocument(req, res, next) {
  try {
    const assessment = await Assessment.findOne({ _id: req.params.id, owner: req.user._id });
    if (!assessment || !assessment.documentFile || !assessment.documentFile.storedName) {
      return res.status(404).json({ message: 'Document not found' });
    }

    const filePath = path.join(UPLOAD_DIR, assessment.documentFile.storedName);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'Document file missing on server' });
    }

    res.setHeader('Content-Type', assessment.documentFile.mimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${assessment.documentFile.originalName}"`);
    fs.createReadStream(filePath).pipe(res);
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
  uploadDocument,
  getOwnDocument,
};
