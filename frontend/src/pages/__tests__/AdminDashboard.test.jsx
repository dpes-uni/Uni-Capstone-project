import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AdminDashboard from '../AdminDashboard.jsx';
import api from '../../api/axios.js';

vi.mock('../../api/axios.js', () => ({
  default: { get: vi.fn(), patch: vi.fn() },
}));

vi.mock('../../context/AuthContext.jsx', () => ({
  useAuth: vi.fn(),
}));

const renderPage = async () => {
  api.get
    .mockResolvedValueOnce({
      data: {
        stats: { totalUsers: 10, clients: 8, admins: 2, verified: 9 },
        users: [],
        recentActivity: [],
      },
    })
    .mockResolvedValue({
      data: { assessments: [] },
    });
  render(<AdminDashboard />);
  await waitFor(() => {
    expect(screen.getByText('Administrator Dashboard')).toBeInTheDocument();
  });
};

describe('AdminDashboard — AI Security Demo button', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.open = vi.fn();
  });

  it('opens /admin/ai-demo in a new tab when clicked', async () => {
    await renderPage();
    const button = screen.getByRole('button', { name: /AI Security Demo/i });
    fireEvent.click(button);
    expect(window.open).toHaveBeenCalledWith('/admin/ai-demo', '_blank', 'noopener,noreferrer');
  });
});
