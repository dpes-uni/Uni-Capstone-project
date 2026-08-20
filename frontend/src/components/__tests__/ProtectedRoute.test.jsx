import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ProtectedRoute from '../ProtectedRoute.jsx';

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    Navigate: ({ to }) => <div data-testid="navigate-to">{to}</div>,
  };
});

vi.mock('../../context/AuthContext.jsx', () => ({
  useAuth: vi.fn(),
}));

import { useAuth } from '../../context/AuthContext.jsx';

const renderWithRouter = (ui) =>
  render(<MemoryRouter initialEntries={['/client']}>{ui}</MemoryRouter>);

describe('ProtectedRoute', () => {
  beforeEach(() => {
    useAuth.mockReset();
  });

  it('shows a loading state while the session is being checked', () => {
    useAuth.mockReturnValue({ user: null, loading: true });
    renderWithRouter(<ProtectedRoute>secret</ProtectedRoute>);
    expect(screen.getByText(/checking your session/i)).toBeTruthy();
  });

  it('redirects to /login when unauthenticated', () => {
    useAuth.mockReturnValue({ user: null, loading: false });
    renderWithRouter(<ProtectedRoute>secret</ProtectedRoute>);
    expect(screen.getByTestId('navigate-to').textContent).toBe('/login');
  });

  it('renders children for an authorized role', () => {
    useAuth.mockReturnValue({ user: { role: 'client' }, loading: false });
    renderWithRouter(<ProtectedRoute roles={['client', 'admin']}>secret</ProtectedRoute>);
    expect(screen.getByText('secret')).toBeTruthy();
  });

  it('redirects an admin away from client-only routes', () => {
    useAuth.mockReturnValue({ user: { role: 'admin' }, loading: false });
    renderWithRouter(<ProtectedRoute roles={['client']}>secret</ProtectedRoute>);
    expect(screen.getByTestId('navigate-to').textContent).toBe('/admin');
  });
});