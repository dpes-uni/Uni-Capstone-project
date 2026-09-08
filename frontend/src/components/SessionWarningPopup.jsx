import React from 'react';

const SessionWarningPopup = ({ showWarning, timeUntilExpire, onLogOut, onKeepSignedIn }) => {
  if (!showWarning) {
    return null;
  }

  return (
    <div className="session-warning-overlay" onClick={onLogOut}>
      <div className="session-warning-popup" onClick={(e) => e.stopPropagation()}>
        <h3>Session Expiring Soon</h3>
        <p>Your session will expire in <strong>{Math.ceil(timeUntilExpire / 1000)}</strong> seconds</p>
        <p>Please save any unsaved work before you are logged out.</p>
        <div className="warning-actions">
          <button className="btn-primary" onClick={onLogOut}>Log out now</button>
          <button className="btn-secondary" onClick={onKeepSignedIn}>Stay signed in</button>
        </div>
      </div>
    </div>
  );
};

SessionWarningPopup.defaultProps = {
  showWarning: false,
  timeUntilExpire: 0,
  onLogOut: () => {},
  onKeepSignedIn: () => {},
};

export default SessionWarningPopup;