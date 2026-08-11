import React from 'react';

const features = [
  {
    title: 'Risk-based login scoring',
    text: 'Every login is scored 0-100 based on device recognition, IP history and recent failed attempts.',
  },
  {
    title: 'Step-up verification',
    text: 'Medium and high risk logins trigger a one-time passcode sent by email before a session is issued.',
  },
  {
    title: 'Account lockout protection',
    text: 'Repeated failed attempts temporarily lock an account to slow down brute-force attacks.',
  },
  {
    title: 'Trusted device memory',
    text: 'Devices used for a successful login are remembered, so future logins from them are lower risk.',
  },
  {
    title: 'Verification assessments',
    text: 'Create and track document verification cases with statuses from pending through to a final decision.',
  },
  {
    title: 'Login activity log',
    text: 'Every attempt — successful or not — is recorded with its risk score and reasons for the dashboard.',
  },
];

export default function Features() {
  return (
    <div className="page features-page">
      <header className="page-header">
        <h1>Everything you need to verify with confidence</h1>
        <p>A rule-based risk engine, adaptive MFA, and a simple case-tracking workflow.</p>
      </header>

      <div className="feature-grid">
        {features.map((f) => (
          <div className="feature-card" key={f.title}>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
