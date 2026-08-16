const User = require('../models/User');
const LoginActivity = require('../models/LoginActivity');

async function getOverview(req, res, next) {
  try {
    const [users, recentActivity, counts] = await Promise.all([
      User.find({}).select('name email role isVerified lastLoginAt createdAt').sort({ createdAt: -1 }).limit(100),
      LoginActivity.find({}).populate('user', 'name email role').sort({ createdAt: -1 }).limit(25),
      User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]),
    ]);

    const byRole = counts.reduce((acc, row) => {
      acc[row._id] = row.count;
      return acc;
    }, {});

    res.json({
      stats: {
        totalUsers: users.length,
        admins: byRole.admin || 0,
        clients: (byRole.student || 0) + (byRole.agent || 0) + (byRole.institution || 0),
        verified: users.filter((u) => u.isVerified).length,
      },
      users,
      recentActivity,
    });
  } catch (err) {
    next(err);
  }
}

async function updateUserRole(req, res, next) {
  try {
    const { role } = req.body;
    if (!['admin', 'student', 'agent', 'institution'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role.' });
    }
    if (String(req.user._id) === String(req.params.id) && role !== 'admin') {
      return res.status(400).json({ message: 'You cannot remove your own admin role.' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ message: 'User role updated.', user: user.toSafeObject() });
  } catch (err) {
    next(err);
  }
}

module.exports = { getOverview, updateUserRole };
