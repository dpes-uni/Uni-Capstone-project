function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: administrator privileges required.' });
    }
    next();
  };
}

module.exports = { requireRole };
