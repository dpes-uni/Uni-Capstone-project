import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <nav className="navbar">
      <Link to="/" className="nav-logo">
        Assure<span>Docs</span>
      </Link>

      <button className="nav-toggle" onClick={() => setOpen(!open)} aria-label="Toggle menu">
        ☰
      </button>

      <ul className={`nav-links ${open ? 'open' : ''}`}>
        <li><Link to="/features" onClick={() => setOpen(false)}>Features</Link></li>
        <li><Link to="/assessments" onClick={() => setOpen(false)}>Assessments</Link></li>
        {user && <li><Link to="/dashboard" onClick={() => setOpen(false)}>Dashboard</Link></li>}
      </ul>

      <div className="nav-actions">
        {user ? (
          <>
            <span className="nav-user">Hi, {user.name.split(' ')[0]}</span>
            <button className="btn btn-outline" onClick={handleLogout}>Sign out</button>
          </>
        ) : (
          <>
            <Link to="/login" className="btn btn-outline">Sign in</Link>
            <Link to="/signup" className="btn btn-primary">Get started</Link>
          </>
        )}
      </div>
    </nav>
  );
}
