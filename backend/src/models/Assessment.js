const mongoose = require('mongoose');

const assessmentSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    applicantName: { type: String, required: true, trim: true, maxlength: 120 },
    documentType: {
      type: String,
      enum: ['passport', 'national_id', 'drivers_license', 'academic_transcript', 'other'],
      default: 'other',
    },
    referenceId: { type: String, required: true, unique: true },
    status: {
      type: String,
      enum: ['pending', 'in_review', 'verified', 'rejected'],
      default: 'pending',
    },
    riskScore: { type: Number, min: 0, max: 100, default: 0 },
    notes: { type: String, maxlength: 2000, default: '' },
  },
  { timestamps: true }
);

assessmentSchema.pre('validate', function generateReference(next) {
  if (!this.referenceId) {
    this.referenceId = `AD-${Date.now().toString(36).toUpperCase()}-${Math.floor(
      Math.random() * 9000 + 1000
    )}`;
  }
  next();
});

module.exports = mongoose.model('Assessment', assessmentSchema);
