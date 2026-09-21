import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import AIDemoPage from '../AIDemoPage.jsx';
import api from '../../api/axios.js';

vi.mock('../../api/axios.js', () => ({
  default: { get: vi.fn(), patch: vi.fn() },
}));

const liveSessionResponse = {
  active: true,
  user: { username: 'live.admin@university.edu', role: 'admin' },
  startedAt: new Date(Date.now() - 23 * 60000).toISOString(),
  sessionStatus: {
    active: true,
    requiresReauthentication: false,
    riskDecision: 'continue',
    recommendedAction: null,
  },
  aiRisk: { score: 12, level: 'low' },
  accumulatedRisk: 12,
  effectiveRiskLevel: 'low',
  timeout: { idleTimeout: false, highRiskTerminate: false, timeUntilExpire: 300000 },
  baseline: {
    device: 'Desktop',
    browser: 'Chrome',
    operatingSystem: 'Windows',
    ip: '192.168.1.42',
    country: 'United States',
    city: 'Springfield',
    vpnDetected: false,
  },
  sessionContext: null,
  contextChanges: null,
  activity: {
    documentsViewed: 5,
    documentsDownloaded: 2,
    documentsUploaded: 1,
    verificationActions: 3,
    failedActions: 0,
    rapidActions: false,
  },
};

const renderWithApi = (response) => {
  api.get.mockResolvedValueOnce({ data: response });
  render(<AIDemoPage />);
};

describe('AIDemoPage — loading state', () => {
  it('shows a loading indicator while fetching session status', () => {
    api.get.mockReturnValue(new Promise(() => {}));
    render(<AIDemoPage />);
    expect(screen.getByText(/Loading session status/i)).toBeInTheDocument();
    expect(screen.getByTestId('data-mode')).toHaveTextContent('DATA MODE: LIVE SESSION');
  });
});

describe('AIDemoPage — no active session', () => {
  it('shows No Active Session when active is false', async () => {
    renderWithApi({ active: false });
    await waitFor(() => {
      expect(screen.getByText('No Active Session')).toBeInTheDocument();
    });
    expect(screen.getByText(/no authenticated session/i)).toBeInTheDocument();
  });

  it('shows the Refresh control after no active session', async () => {
    renderWithApi({ active: false });
    await waitFor(() => {
      expect(screen.getByTestId('refresh')).toBeInTheDocument();
    });
  });
});

describe('AIDemoPage — live data rendering', () => {
  it('renders live user and session data from the API', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      expect(screen.getByText('live.admin@university.edu')).toBeInTheDocument();
    });
    expect(screen.getByTestId('data-mode')).toHaveTextContent('DATA MODE: LIVE SESSION');
    expect(screen.getByText('Allow login — continue session')).toBeInTheDocument();
    expect(screen.getByText('live.admin@university.edu')).toBeInTheDocument();
    expect(screen.getByText('admin')).toBeInTheDocument();
    expect(screen.getByText('AI Risk Score')).toBeInTheDocument();
  });

  it('displays Monitor decision for monitor riskDecision (not reauthentication required)', async () => {
    const monitorResponse = {
      ...liveSessionResponse,
      sessionStatus: {
        ...liveSessionResponse.sessionStatus,
        riskDecision: 'monitor',
        requiresReauthentication: false,
        recommendedAction: null,
      },
    };
    renderWithApi(monitorResponse);
    await waitFor(() => {
      expect(screen.getByText('live.admin@university.edu')).toBeInTheDocument();
    });
    expect(screen.getByText('Monitor session — elevated risk observed')).toBeInTheDocument();
    // Monitor must NOT show reauthentication required.
    expect(screen.queryByText('Reauthentication required')).not.toBeInTheDocument();
  });

  it('does not show fabricated or hard-coded demo values', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      expect(screen.getByText('live.admin@university.edu')).toBeInTheDocument();
    });
    expect(screen.queryByText('demo.admin@university.edu')).not.toBeInTheDocument();
    expect(screen.queryByText('INITIAL_DEMO')).not.toBeInTheDocument();
  });

  it('shows session duration from startedAt', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      expect(screen.getByText(/Session duration/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/23m/)).toBeInTheDocument();
  });
});

describe('AIDemoPage — tabs from live data', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all three tabs', async () => {
    renderWithApi({ active: false });
    await waitFor(() => { expect(screen.getByTestId('tab-overview')).toBeInTheDocument(); });
    expect(screen.getByTestId('tab-session-context')).toBeInTheDocument();
    expect(screen.getByTestId('tab-ai-input')).toBeInTheDocument();
  });

  it('defaults to the OVERVIEW tab', async () => {
    renderWithApi({ active: false });
    await waitFor(() => { expect(screen.getByTestId('panel-overview')).toBeInTheDocument(); });
    expect(screen.queryByTestId('panel-session-context')).not.toBeInTheDocument();
    expect(screen.queryByTestId('panel-ai-input')).not.toBeInTheDocument();
  });

  it('switches to SESSION CONTEXT tab', async () => {
    renderWithApi({ active: false });
    await waitFor(() => { expect(screen.getByTestId('tab-session-context')).toBeInTheDocument(); });
    fireEvent.click(screen.getByTestId('tab-session-context'));
    expect(screen.getByTestId('panel-session-context')).toBeInTheDocument();
  });

  it('switches to AI INPUT FEATURES tab', async () => {
    renderWithApi({ active: false });
    await waitFor(() => { expect(screen.getByTestId('tab-ai-input')).toBeInTheDocument(); });
    fireEvent.click(screen.getByTestId('tab-ai-input'));
    expect(screen.getByTestId('panel-ai-input')).toBeInTheDocument();
  });

  it('shows Baseline Comparison with live baseline data', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      fireEvent.click(screen.getByTestId('tab-session-context'));
      expect(screen.getByTestId('panel-session-context')).toBeInTheDocument();
    });
    expect(screen.getByText('Operating System')).toBeInTheDocument();
    expect(screen.getByText('Country')).toBeInTheDocument();
    expect(screen.getByText('VPN status')).toBeInTheDocument();
  });

  it('shows available AI Input Features signals', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      fireEvent.click(screen.getByTestId('tab-ai-input'));
      expect(screen.getByTestId('panel-ai-input')).toBeInTheDocument();
    });
    expect(screen.getByText('User Role')).toBeInTheDocument();
    expect(screen.getByText('Document Count')).toBeInTheDocument();
    expect(screen.getByText('Verification Actions')).toBeInTheDocument();
    expect(screen.getByText('Failed Actions')).toBeInTheDocument();
    expect(screen.getByText('Rapid Actions')).toBeInTheDocument();
  });

  it('shows Feature Pipeline flow', async () => {
    renderWithApi(liveSessionResponse);
    await waitFor(() => {
      fireEvent.click(screen.getByTestId('tab-ai-input'));
      expect(screen.getByTestId('panel-ai-input')).toBeInTheDocument();
    });
    expect(screen.getByTestId('flow-session-data')).toBeInTheDocument();
    expect(screen.getByTestId('flow-feature-prep')).toBeInTheDocument();
    expect(screen.getByTestId('flow-session-predictor')).toBeInTheDocument();
    expect(screen.getByTestId('flow-risk-prediction')).toBeInTheDocument();
  });
});

describe('AIDemoPage — refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders a Refresh button when data is loaded', async () => {
    renderWithApi({ active: false });
    await waitFor(() => {
      expect(screen.getByTestId('refresh')).toBeInTheDocument();
    });
  });

  it('re-fetches session data when Refresh is clicked', async () => {
    renderWithApi({ active: false });
    await waitFor(() => {
      expect(screen.getByText('No Active Session')).toBeInTheDocument();
    });
    api.get.mockResolvedValueOnce({ data: { active: false } });
    fireEvent.click(screen.getByTestId('refresh'));
    await waitFor(() => {
      expect(screen.getByText('No Active Session')).toBeInTheDocument();
    });
    expect(api.get).toHaveBeenCalledTimes(2);
  });
});
