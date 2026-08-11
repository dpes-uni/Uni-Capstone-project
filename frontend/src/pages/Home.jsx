import React from 'react';
import { Link } from 'react-router-dom';

const highlights = [
  {
    title: 'Adaptive MFA',
    text: 'A rule-based risk engine scores every login attempt and only asks for a one-time passcode when something looks unusual.',
  },
  {
    title: 'Anomaly detection',
    text: 'New devices, new IP addresses, and repeated failed attempts are tracked per account so risky logins stand out.',
  },
  {
    title: 'Document assessments',
    text: 'Track identity and document verification requests from submission through to a final decision.',
  },
];

export default function Home() {
  return (
    <div className="page home-page">
      <section className="hero">
        <h1>Verify identities with confidence, not friction.</h1>
        <p>
          Assure Docs pairs a rule-based risk engine with adaptive multi-factor authentication, so
          trusted logins stay fast and only suspicious ones get a second check.
        </p>
        <div className="hero-actions">
          <Link to="/signup" className="btn btn-primary btn-lg">Create free account</Link>
          <Link to="/features" className="btn btn-outline btn-lg">See how it works</Link>
        </div>
      </section>

      <section className="highlight-grid">
        {highlights.map((h) => (
          <div className="highlight-card" key={h.title}>
            <h3>{h.title}</h3>
            <p>{h.text}</p>
          </div>
        ))}
      </section>

      <section className="cta-strip">
        <h2>Built as a university capstone project</h2>
        <p>
          MongoDB, Express, React and Node.js power the platform, with a Python risk-scoring module
          designed to plug in alongside the built-in rule engine.
        </p>
      </section>
    </div>
  );
}
