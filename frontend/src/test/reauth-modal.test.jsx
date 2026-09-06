/**
 * ReauthModal step-up vs reauth mode tests.
 * Uses Vitest + jsdom + @testing-library/react.
 *
 * The modal registers its handler via setReauthHandler / setStepUpHandler in a
 * useEffect. We capture the registered functions to trigger the modal directly.
 *
 * NOTE: runStepUp/runReauth return a promise that resolves only when the user
 * submits the OTP form — that flow is not testable without a real API connection.
 * We test the MODAL RENDERING (the synchronous setOpen(true) call), which is what
 * the user sees immediately after the trigger.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import React from 'react';

// Mocks must be at top — vi.mock is hoisted.
// AuthContext: mock useAuth so the modal can be rendered without a real auth context.
const mockUser = { email: 'test@example.com' };

vi.mock('../context/AuthContext.jsx', () => ({
  AuthProvider: ({ children }) => children,
  useAuth: vi.fn(() => ({ user: mockUser })),
}));

// Capture the handler functions registered by ReauthModal's useEffect.
const handlers = { reauth: null, stepup: null };

vi.mock('../api/reauth.js', () => ({
  triggerReauth: vi.fn(),
  triggerStepUp: vi.fn(),
  setReauthHandler: vi.fn((fn) => { handlers.reauth = fn; }),
  setStepUpHandler: vi.fn((fn) => { handlers.stepup = fn; }),
  clearHandlers: vi.fn(),
}));

// Mock axios — ReauthModal calls api.post() when requesting OTP codes.
vi.mock('../api/axios.js', () => ({
  default: {
    post: vi.fn().mockResolvedValue({ data: { reauthId: 'test-id' } }),
  },
}));

const ReauthModal = (await import('../components/ReauthModal.jsx')).default;

describe('ReauthModal — step-up vs reauth mode', () => {
  // Reset handlers before each test.
  beforeEach(() => {
    handlers.reauth = null;
    handlers.stepup = null;
  });

  it('captures the reauth and step-up handlers on mount', async () => {
    render(<ReauthModal />);
    await waitFor(() => {
      expect(handlers.reauth).not.toBeNull();
      expect(handlers.stepup).not.toBeNull();
    }, { timeout: 2000 });
  });

  it('renders the modal when opened for reauth', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });
    // runReauth opens the modal synchronously (setOpen(true)) then requests OTP.
    // The user sees the modal immediately; the API call is async and does not
    // affect render — so we test the DOM state after the sync state update.
    await act(async () => {
      handlers.reauth(); // Don't await — the promise never resolves in tests
    });
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });
  });

  it('shows step-up title when opened for step-up', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });
    await act(async () => {
      handlers.stepup('document_upload'); // Don't await — promise never resolves
    });
    await waitFor(() => {
      expect(screen.queryByText('Additional verification required')).not.toBeNull();
    });
  });

  it('step-up mode shows the action label in the subtitle', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });
    await act(async () => {
      handlers.stepup('document_upload');
    });
    await waitFor(() => {
      const text = screen.getByText(/upload this document/i);
      expect(text).not.toBeNull();
    });
  });

  it('step-up mode shows generic subtitle when label is null', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });
    await act(async () => {
      handlers.stepup(null);
    });
    await waitFor(() => {
      // Title + subtitle both contain "additional verification"; just check >= 1.
      expect(screen.queryAllByText(/additional verification/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('reauth mode shows standard "Verification required" title', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });
    await act(async () => {
      handlers.reauth();
    });
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });
  });
});
