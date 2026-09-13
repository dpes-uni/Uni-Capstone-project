const mongoose = require('mongoose');

const sessionEventSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userRole: { type: String, default: 'student' },
    sessionDurationMinutes: { type: Number, default: 0 },
    documentsViewed: { type: Number, default: 0 },
    documentsDownloaded: { type: Number, default: 0 },
    documentsUploaded: { type: Number, default: 0 },
    verificationActions: { type: Number, default: 0 },
    failedActions: { type: Number, default: 0 },
    rapidActions: { type: Boolean, default: false },
    unusualActivity: { type: Boolean, default: false },
  },
  { timestamps: true }
);

module.exports = mongoose.model('SessionEvent', sessionEventSchema);
