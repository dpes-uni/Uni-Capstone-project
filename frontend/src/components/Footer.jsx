import React from 'react';

export default function Footer() {
  return (
    <footer className="footer">
      <p>© {new Date().getFullYear()} Assure Docs — University Capstone Project.</p>
      <p className="footer-sub">AI-assisted anomaly detection & adaptive MFA identity verification platform.</p>
    </footer>
  );
}
