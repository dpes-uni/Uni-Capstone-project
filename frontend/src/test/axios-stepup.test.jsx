/**
 * axios.js step-up detection — 403 stepUpRequired handling, retry protection.
 *
 * The axios interceptor calls `api(config)` to retry the original request after
 * step-up verification. We stub that retry to return a synthetic success so the
 * test can focus on the branching logic — what gets called and what flags are
 * set on the request config.
 *
 * Uses Vitest + jsdom.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock reauth.js — triggerStepUp / triggerReauth become spy functions.
vi.mock('../api/reauth.js', () => ({
  triggerStepUp: vi.fn().mockResolvedValue(undefined),
  triggerReauth: vi.fn().mockResolvedValue(undefined),
  setReauthHandler: vi.fn(),
  setStepUpHandler: vi.fn(),
  clearHandlers: vi.fn(),
}));

import api from '../api/axios.js';
import * as reauthModule from '../api/reauth.js';

// Stub the request adapter so retries don't hit a real network.
const stubbedRequest = vi.fn().mockResolvedValue({ data: { ok: true }, status: 200 });
api.defaults.adapter = stubbedRequest;

describe('axios.js 403 step-up detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stubbedRequest.mockClear();
    stubbedRequest.mockResolvedValue({ data: { ok: true }, status: 200 });
    localStorage.removeItem('ad_token');
    localStorage.setItem('ad_token', 'test-access-token');
  });

  afterEach(() => {
    localStorage.removeItem('ad_token');
  });

  const mockError = (body, status = 403) => ({
    config: { headers: {}, __isRetry: false, __reauthRetry: false, __stepUpRetry: false },
    response: { status, data: body },
  });

  // axios.js adds a single response interceptor — its handlers array entry has
  // { fulfilled, rejected } fields.
  const getRejectedHandler = () => {
    const handlers = api.interceptors.response.handlers;
    if (!handlers || !handlers[0]) {
      throw new Error('interceptors.response.handlers not available');
    }
    return handlers[0].rejected;
  };

  it('calls triggerStepUp on 403 stepUpRequired: true', async () => {
    const error = mockError({ stepUpRequired: true });
    const result = await getRejectedHandler()(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).toHaveBeenCalledOnce();
    // Retry happens — adapter is called.
    expect(stubbedRequest).toHaveBeenCalled();
    expect(result.data).toEqual({ ok: true });
  });

  it('does NOT call triggerStepUp on 403 reauthenticationRequired: true', async () => {
    const error = mockError({ reauthenticationRequired: true });
    await getRejectedHandler()(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).not.toHaveBeenCalled();
  });

  it('step-up takes precedence when both flags are present', async () => {
    const error = mockError({ stepUpRequired: true, reauthenticationRequired: true });
    await getRejectedHandler()(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).toHaveBeenCalledOnce();
    expect(vi.mocked(reauthModule.triggerReauth)).not.toHaveBeenCalled();
  });

  it('retry flag __stepUpRetry prevents a second call', async () => {
    const error = mockError({ stepUpRequired: true });
    error.config.__stepUpRetry = true; // already retried
    await expect(getRejectedHandler()(error)).rejects.toBe(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).not.toHaveBeenCalled();
  });

  it('passes action label from response body to triggerStepUp', async () => {
    const error = mockError({ stepUpRequired: true, action: 'document_upload' });
    await getRejectedHandler()(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).toHaveBeenCalledWith('document_upload');
  });

  it('passes null when no action is provided', async () => {
    const error = mockError({ stepUpRequired: true });
    await getRejectedHandler()(error);
    expect(vi.mocked(reauthModule.triggerStepUp)).toHaveBeenCalledWith(null);
  });

  it('step-up failure dispatches force-logout event', async () => {
    vi.mocked(reauthModule.triggerStepUp).mockRejectedValueOnce(new Error('cancelled'));
    const dispatchEventSpy = vi.spyOn(window, 'dispatchEvent');
    const error = mockError({ stepUpRequired: true });
    await expect(getRejectedHandler()(error)).rejects.toThrow();
    expect(dispatchEventSpy).toHaveBeenCalledWith(expect.objectContaining({ type: 'ad:force-logout' }));
    expect(localStorage.getItem('ad_token')).toBeNull();
  });

  it('normal 200 responses are passed through unchanged', () => {
    const response = { data: { ok: true } };
    const handlers = api.interceptors.response.handlers;
    if (handlers && handlers[0]?.fulfilled) {
      expect(handlers[0].fulfilled(response)).toBe(response);
    }
  });

  it('500 errors do not trigger any auth flow', async () => {
    const error = { config: {}, response: { status: 500, data: {} } };
    await expect(getRejectedHandler()(error)).rejects.toHaveProperty('response.status', 500);
    expect(vi.mocked(reauthModule.triggerStepUp)).not.toHaveBeenCalled();
    expect(vi.mocked(reauthModule.triggerReauth)).not.toHaveBeenCalled();
  });
});
