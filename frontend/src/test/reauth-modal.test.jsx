/**
 * ReauthModal step-up vs reauth mode tests.
 * Uses Vitest + jsdom + @testing-library/react.
 *
 * The modal registers its handler via setReauthHandler / setStepUpHandler in a
 * useEffect. We capture the registered functions to trigger the modal directly.
 *
 * The handler (runReauth/runStepUp) returns a Promise that:
 *   - Opens the modal immediately
 *   - Fires the OTP request immediately
 *   - Resolves only after successful OTP verification
 *   - Rejects if the user cancels
 *
 * Tests verify this actual sequencing rather than only checking visual output.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
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

// Dynamic post mock — different endpoints return different responses.
const postMock = vi.fn();

vi.mock('../api/axios.js', () => ({
  default: {
    post: postMock,
  },
}));

const ReauthModal = (await import('../components/ReauthModal.jsx')).default;

function setupRequestMock() {
  postMock.mockImplementation((url) => {
    if (url.includes('/reauth/request') || url.includes('/stepup/request')) {
      return Promise.resolve({ data: { reauthId: 'test-reauth-id', devOtpCode: '123456' } });
    }
    if (url.includes('/reauth/verify') || url.includes('/stepup/verify')) {
      return Promise.resolve({ data: {} });
    }
    return Promise.resolve({ data: {} });
  });
}

function resetRequestMock() {
  postMock.mockReset();
  setupRequestMock();
}

describe('ReauthModal — handler triggers request immediately', () => {
  beforeEach(() => {
    handlers.reauth = null;
    handlers.stepup = null;
    resetRequestMock();
  });

  afterEach(() => {
    postMock.mockReset();
  });

  it('captures the reauth and step-up handlers on mount', async () => {
    render(<ReauthModal />);
    await waitFor(() => {
      expect(handlers.reauth).not.toBeNull();
      expect(handlers.stepup).not.toBeNull();
    }, { timeout: 2000 });
  });

  it('reauth handler opens modal and calls /auth/reauth/request', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.reauth().catch(() => {});

    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith('/auth/reauth/request');
    });
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });

    // Modal stays open — handler promise is pending, waiting for OTP verification
    expect(screen.queryByText('Verification required')).not.toBeNull();
    expect(screen.queryByText('Could not start verification.')).toBeNull();
  });

  it('step-up handler opens modal and calls /auth/stepup/request', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.stepup('document_upload').catch(() => {});

    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith('/auth/stepup/request');
    });
    await waitFor(() => {
      expect(screen.queryByText('Additional verification required')).not.toBeNull();
    });

    // Modal stays open — handler promise is pending
    expect(screen.queryByText('Additional verification required')).not.toBeNull();
    expect(screen.queryByText('Could not start verification.')).toBeNull();
  });

  it('successful reauth verifies using the returned reauthId', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.reauth();

    // Modal opens immediately
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });

    // Dev OTP code displayed
    expect(screen.getByText(/123456/)).toBeInTheDocument();

    // Submit the form with the OTP
    const input = screen.getByLabelText('Verification code');
    await act(async () => {
      fireEvent.change(input, { target: { value: '123456' } });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    });

    // Modal closes on success
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).toBeNull();
    });

    // Verified with the correct endpoint and reauthId
    expect(postMock).toHaveBeenCalledWith('/auth/reauth/verify',
      expect.objectContaining({ reauthId: 'test-reauth-id', code: '123456' }));

    // Handler promise resolved
    await expect(handlerPromise).resolves.toBeUndefined();
  });

  it('successful step-up verifies using the returned reauthId', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.stepup('document_upload');

    await waitFor(() => {
      expect(screen.queryByText('Additional verification required')).not.toBeNull();
    });

    expect(screen.getByText(/123456/)).toBeInTheDocument();

    const input = screen.getByLabelText('Verification code');
    await act(async () => {
      fireEvent.change(input, { target: { value: '123456' } });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    });

    await waitFor(() => {
      expect(screen.queryByText('Additional verification required')).toBeNull();
    });

    expect(postMock).toHaveBeenCalledWith('/auth/stepup/verify',
      expect.objectContaining({ reauthId: 'test-reauth-id', code: '123456' }));

    await expect(handlerPromise).resolves.toBeUndefined();
  });

  it('cancellation rejects the handler promise', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.reauth();
    // Pre-attach catch to avoid unhandled rejection between cancel and assertion.
    handlerPromise.catch(() => {});

    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Log out instead/i }));
    });

    await waitFor(() => {
      expect(screen.queryByText('Verification required')).toBeNull();
    });

    await expect(handlerPromise).rejects.toThrow('verification-cancelled');
  });

  it('failed OTP verification keeps the modal open and shows the error', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.reauth).not.toBeNull(), { timeout: 2000 });

    const handlerPromise = handlers.reauth().catch(() => {});

    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });

    // Override verify to fail
    postMock.mockImplementation((url) => {
      if (url.includes('/reauth/request')) return Promise.resolve({ data: { reauthId: 'test-reauth-id', devOtpCode: '123456' } });
      if (url.includes('/reauth/verify')) return Promise.reject({ response: { data: { message: 'Invalid code' } } });
      return Promise.resolve({ data: {} });
    });

    const input = screen.getByLabelText('Verification code');
    await act(async () => {
      fireEvent.change(input, { target: { value: '000000' } });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    });

    // Modal should still be open
    await waitFor(() => {
      expect(screen.queryByText('Verification required')).not.toBeNull();
    });
    expect(screen.getByText('Invalid code')).toBeInTheDocument();

    expect(postMock).toHaveBeenCalledWith('/auth/reauth/verify',
      expect.objectContaining({ reauthId: 'test-reauth-id', code: '000000' }));
  });

  it('step-up mode shows the action label in the subtitle', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });

    handlers.stepup('document_upload').catch(() => {});

    await waitFor(() => {
      const text = screen.getByText(/upload this document/i);
      expect(text).not.toBeNull();
    });
  });

  it('step-up mode shows generic subtitle when label is null', async () => {
    render(<ReauthModal />);
    await waitFor(() => expect(handlers.stepup).not.toBeNull(), { timeout: 2000 });

    handlers.stepup(null).catch(() => {});

    await waitFor(() => {
      expect(screen.queryAllByText(/additional verification/i).length).toBeGreaterThanOrEqual(1);
    });
  });
});
