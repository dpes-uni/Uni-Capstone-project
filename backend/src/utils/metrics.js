const client = require('prom-client');

const collectDefaultMetrics = process.env.NODE_ENV !== 'test' ? client.collectDefaultMetrics : () => {};

collectDefaultMetrics({ register: client.register });

// Application-specific metrics
const loginAttemptsTotal = new client.Counter({
  name: 'assure_docs_login_attempts_total',
  help: 'Total number of login attempts processed',
  labelNames: ['outcome', 'risk_level'],
});

const loginVerificationTotal = new client.Counter({
  name: 'assure_docs_mfa_verifications_total',
  help: 'Total number of MFA/OTP verifications',
  labelNames: ['outcome'],
});

const loginRiskScore = new client.Histogram({
  name: 'assure_docs_login_risk_score',
  help: 'Risk score distribution for login attempts',
  buckets: [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
});

const httpRequestDuration = new client.Histogram({
  name: 'assure_docs_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.005, 0.01, 0.05, 0.1, 0.3, 0.5, 1, 3, 5, 10],
});

/** Record an HTTP request duration. Use with express middleware. */
function recordHttpRequest(req, res, next) {
  if (process.env.NODE_ENV === 'test') {
    next();
    return;
  }
  const end = httpRequestDuration.startTimer({
    method: req.method,
    route: req.route ? req.route.path : req.path,
  });
  res.on('finish', () => {
    end({ status_code: res.statusCode });
  });
  next();
}

module.exports = {
  client,
  loginAttemptsTotal,
  loginVerificationTotal,
  loginRiskScore,
  recordHttpRequest,
};