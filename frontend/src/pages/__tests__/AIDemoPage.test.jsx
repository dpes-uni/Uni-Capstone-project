import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import AIDemoPage from '../AIDemoPage.jsx';
import api from '../../api/axios.js';

vi.mock('../../api/axios.js', () => ({
  default: { get: vi.fn(), patch: vi.fn() },
}));

const ADMIN_SESSION = {
  id: 'user:admin-001',
  user: { id: 'admin-001', username: 'admin@example.com', role: 'admin' },
  startedAt: new Date(Date.now() - 23 * 60000).toISOString(),
  lastActivity: Date.now(),
  sessionStatus: {
    active: true,
    requiresReauthentication: false,
    riskDecision: 'continue',
    recommendedAction: null,
  },
  aiRisk: {
    score: 20,
    level: 'low',
    unusualActivity: false,
    confidence: 0.95,
    reason: 'Session ML prediction: unusual_activity=False, confidence=95.0%',
    assessedAt: new Date('2026-01-01T10:00:00Z').toISOString(),
    status: 'assessed',
  },
  accumulatedRisk: 20,
  effectiveRiskLevel: 'low',
  baseline: {
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
    ip: '192.168.1.42',
    country: 'United States',
    city: 'Springfield',
    vpnDetected: false,
  },
  sessionContext: {
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
    ip: '192.168.1.42',
    country: 'United States',
    city: 'Springfield',
    vpnDetected: false,
  },
  contextChanges: {
    deviceChanged: false,
    browserChanged: false,
    osChanged: false,
    ipChanged: false,
    locationChanged: false,
    vpnChanged: false,
  },
  activity: {
    documentsViewed: 5,
    documentsDownloaded: 2,
    documentsUploaded: 1,
    verificationActions: 3,
    failedActions: 0,
    rapidActions: false,
  },
};

const STUDENT_SESSION = {
  ...ADMIN_SESSION,
  id: 'user:student-001',
  user: { id: 'student-001', username: 'student@example.com', role: 'student' },
  sessionStatus: {
    active: true,
    requiresReauthentication: true,
    riskDecision: 'reauth_required',
    recommendedAction: 'Require Additional Verification',
  },
  aiRisk: {
    score: 80,
    level: 'high',
    unusualActivity: true,
    confidence: 0.88,
    reason: 'Session ML prediction: unusual_activity=True, confidence=88.0%',
    assessedAt: new Date('2026-01-01T10:05:00Z').toISOString(),
    status: 'assessed',
  },
  accumulatedRisk: 80,
  effectiveRiskLevel: 'high',
  sessionContext: {
    device: 'Mobile',
    browser: 'Safari',
    operatingSystem: 'iOS',
    ip: '10.0.0.7',
    country: 'United Kingdom',
    city: 'London',
    vpnDetected: true,
  },
  contextChanges: {
    deviceChanged: true,
    browserChanged: true,
    osChanged: true,
    ipChanged: true,
    locationChanged: true,
    vpnChanged: true,
  },
};

const renderWithApi = (response) => {
  api.get.mockResolvedValueOnce({ data: response });
  render(<AIDemoPage />);
};

describe('AIDemoPage — loading state', () => {
  it('shows a loading indicator while fetching session data', () => {
    api.get.mockReturnValue(new Promise(() => {}));
    render(<AIDemoPage />);
    expect(screen.getByText(/Loading live monitored sessions/i)).toBeInTheDocument();
    expect(screen.getByTestId('data-mode')).toHaveTextContent('DATA MODE: LIVE SESSION');
  });
});

describe('AIDemoPage — no active sessions', () => {
  it('shows No Active Monitored Sessions when the Map is empty', async () => {
    renderWithApi({ active: true, count: 0, sessions: [] });
    await waitFor(() => {
      expect(screen.getAllByText('No Active Monitored Sessions').length).toBeGreaterThan(0);
    });
  });

  it('shows the Refresh control when no sessions are loaded', async () => {
    renderWithApi({ active: true, count: 0, sessions: [] });
    await waitFor(() => {
      expect(screen.getByTestId('refresh')).toBeInTheDocument();
    });
  });
});

describe('AIDemoPage — error state', () => {
  it('shows an error message when the API request fails', async () => {
    api.get.mockRejectedValueOnce({});
    render(<AIDemoPage />);
    await waitFor(() => {
      expect(screen.getByText('Unable to load live monitored sessions.')).toBeInTheDocument();
    });
    expect(screen.getByTestId('refresh')).toBeInTheDocument();
  });
});

describe('AIDemoPage — single active session', () => {
  it('renders the active session count', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText(/Active Monitored Sessions: 1/i)).toBeInTheDocument();
    });
  });

  it('renders the admin session in the selector', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('admin').length).toBeGreaterThan(0);
    expect(screen.getByText('AI Risk: 20 / low')).toBeInTheDocument();
    expect(screen.getByText('Effective Risk: low')).toBeInTheDocument();
  });

  it('defaults to the first real session', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('AI Risk Score').length).toBeGreaterThan(0);
  });

  it('shows the assessed AI score and level', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('20').length).toBeGreaterThan(0);
    expect(screen.getByText('Assessed')).toBeInTheDocument();
  });

  it('shows the unusual activity prediction and confidence', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('Unusual Activity Prediction')).toBeInTheDocument();
    expect(screen.getByText('false')).toBeInTheDocument();
    expect(screen.getByText('0.95')).toBeInTheDocument();
  });

  it('shows baseline and current session context', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('tab-session-context'));
    await waitFor(() => {
      expect(screen.getByTestId('panel-session-context')).toBeInTheDocument();
    });
    expect(screen.getByText('Baseline Context')).toBeInTheDocument();
    expect(screen.getByText('Current Session Context')).toBeInTheDocument();
    expect(screen.getAllByText('Desktop').length).toBeGreaterThan(0);
    expect(screen.getAllByText('192.168.1.42').length).toBeGreaterThan(0);
    expect(screen.getAllByText('United States').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Springfield').length).toBeGreaterThan(0);
  });

  it('shows real contextChanges with Unchanged flags', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('tab-session-context'));
    await waitFor(() => {
      expect(screen.getByTestId('panel-session-context')).toBeInTheDocument();
    });
    expect(screen.getByText('No context changes detected')).toBeInTheDocument();
    expect(screen.getAllByText('Unchanged').length).toBeGreaterThan(0);
    expect(screen.queryByText('Changed')).not.toBeInTheDocument();
  });

  it('shows real AI Input Features and AI MODEL OUTPUT sections', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('tab-ai-input'));
    await waitFor(() => {
      expect(screen.getByTestId('panel-ai-input')).toBeInTheDocument();
    });
    expect(screen.getByText('Documents Viewed')).toBeInTheDocument();
    expect(screen.getByText('Documents Downloaded')).toBeInTheDocument();
    expect(screen.getByText('Documents Uploaded')).toBeInTheDocument();
    expect(screen.getByText('AI MODEL OUTPUT')).toBeInTheDocument();
  });
});

describe('AIDemoPage — multiple active sessions', () => {
  it('shows two different users in the response', async () => {
    renderWithApi({ active: true, count: 2, sessions: [ADMIN_SESSION, STUDENT_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(
      screen.getByText((content, element) =>
        element?.tagName === 'BUTTON' && element.textContent.includes('student@example.com'),
      ),
    ).toBeInTheDocument();
  });

  it('shows admin and student roles', async () => {
    renderWithApi({ active: true, count: 2, sessions: [ADMIN_SESSION, STUDENT_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('admin').length).toBeGreaterThan(0);
    expect(screen.getAllByText('student').length).toBeGreaterThan(0);
  });

  it('selecting a student session changes the displayed data', async () => {
    renderWithApi({ active: true, count: 2, sessions: [ADMIN_SESSION, STUDENT_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(
      screen.getByText((content, element) =>
        element?.tagName === 'BUTTON' && element.textContent.includes('Effective Risk: low'),
      ),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('session-select-user:student-001'));
    await waitFor(() => {
      expect(
        screen.getByText((content, element) =>
          element?.tagName === 'BUTTON' && element.textContent.includes('Effective Risk: high'),
        ),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText((content, element) =>
        element?.tagName === 'BUTTON' && element.textContent.includes('Reauthentication Required'),
      ),
    ).toBeInTheDocument();
  });

  it('does not return fabricated demo data', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.queryByText('demo.admin@university.edu')).not.toBeInTheDocument();
    expect(screen.queryByText('INITIAL_DEMO')).not.toBeInTheDocument();
  });
});

describe('AIDemoPage — AI not assessed state', () => {
  it('shows Not assessed when the AI has not assessed the session', async () => {
    const notAssessed = {
      ...ADMIN_SESSION,
      aiRisk: {
        score: null,
        level: null,
        unusualActivity: null,
        confidence: null,
        reason: null,
        assessedAt: null,
        status: 'not_assessed',
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [notAssessed] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('Not assessed').length).toBeGreaterThan(0);
  });
});

describe('AIDemoPage — secrets are not exposed', () => {
  it('does not return tokens, passwords, OTPs or secrets', async () => {
    renderWithApi({ active: true, count: 1, sessions: [ADMIN_SESSION] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    const json = JSON.stringify(screen.getByTestId('data-mode').closest('.page').textContent);
    expect(json).not.toContain('JWT_SECRET');
    expect(json).not.toContain('refreshToken');
    expect(json).not.toContain('password');
    expect(json).not.toContain('otp');
    expect(json).not.toContain('salt');
    expect(json).not.toContain('cookie');
  });
});

describe('AIDemoPage — Risk Sources and AI Model Output', () => {
  it('shows the real Rule-Based login risk score and level', async () => {
    const withLoginRisk = {
      ...ADMIN_SESSION,
      loginRisk: {
        ruleBased: { score: 40, level: 'medium' },
        ai: { score: 20, level: 'low' },
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [withLoginRisk] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('Rule-Based')).toBeInTheDocument();
    expect(screen.getByText('40')).toBeInTheDocument();
    expect(screen.getByText('medium risk')).toBeInTheDocument();
    expect(screen.getByText('Login AI')).toBeInTheDocument();
    expect(screen.getAllByText('20').length).toBeGreaterThan(0);
  });

  it('shows Not available for a login risk component that was genuinely unavailable', async () => {
    const withNullAi = {
      ...ADMIN_SESSION,
      loginRisk: {
        ruleBased: { score: 10, level: 'low' },
        ai: { score: null, level: null },
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [withNullAi] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getAllByText('Not available').length).toBeGreaterThan(0);
  });

  it('shows the AI recommended action in the AI Model Output and Recommended Action sections', async () => {
    const withAction = {
      ...ADMIN_SESSION,
      aiRisk: {
        ...ADMIN_SESSION.aiRisk,
        recommendedAction: 'Require Additional Verification',
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [withAction] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('AI Recommended Action')).toBeInTheDocument();
    expect(screen.getAllByText('Require Additional Verification').length).toBeGreaterThan(0);
  });

  it('shows Awaiting first monitored action before any AI assessment', async () => {
    const notAssessed = {
      ...ADMIN_SESSION,
      sessionStatus: {
        active: true,
        requiresReauthentication: false,
        riskDecision: 'unknown',
        recommendedAction: null,
      },
      aiRisk: {
        score: null,
        level: null,
        recommendedAction: null,
        unusualActivity: null,
        confidence: null,
        reason: null,
        assessedAt: null,
        status: 'not_assessed',
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [notAssessed] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('Awaiting first monitored action')).toBeInTheDocument();
  });

  it('shows the full timeout state including re-auth fields', async () => {
    const withTimeout = {
      ...ADMIN_SESSION,
      timeout: {
        idleTimeout: false,
        highRiskTerminate: false,
        reauthRequired: false,
        reauthWindowExpired: false,
        timeUntilReauthExpire: 600000,
        timeUntilExpire: 600000,
      },
    };
    renderWithApi({ active: true, count: 1, sessions: [withTimeout] });
    await waitFor(() => {
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
    });
    expect(screen.getByText('Reauthentication Required')).toBeInTheDocument();
    expect(screen.getByText('Reauth Window Expired')).toBeInTheDocument();
    expect(screen.getByText('Time Until Reauth Expire')).toBeInTheDocument();
  });
});