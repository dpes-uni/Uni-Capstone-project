/**
 * reauth.js unit tests — handler registration, triggerStepUp, singleton inflight.
 * Uses Vitest + jsdom.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  triggerReauth,
  triggerStepUp,
  setReauthHandler,
  setStepUpHandler,
  clearHandlers,
} from '../api/reauth.js';

describe('reauth.js — handler registration', () => {
  beforeEach(() => {
    clearHandlers();
  });

  afterEach(() => {
    clearHandlers();
  });

  it('triggerReauth resolves when the reauth handler completes successfully', async () => {
    let called = false;
    setReauthHandler(async () => {
      called = true;
    });
    const promise = triggerReauth();
    await promise;
    expect(called).toBe(true);
  });

  it('triggerStepUp passes actionLabel to the step-up handler', async () => {
    let receivedLabel = undefined;
    setStepUpHandler(async (label) => {
      receivedLabel = label;
    });
    await triggerStepUp('document_upload');
    expect(receivedLabel).toBe('document_upload');
  });

  it('triggerStepUp works with null label', async () => {
    let receivedLabel = undefined;
    setStepUpHandler(async (label) => {
      receivedLabel = label;
    });
    await triggerStepUp(null);
    expect(receivedLabel).toBe(null);
  });

  it('triggerStepUp rejects when no handler is registered', async () => {
    await expect(triggerStepUp()).rejects.toThrow('stepup handler is not available');
  });

  it('triggerReauth rejects when no handler is registered', async () => {
    await expect(triggerReauth()).rejects.toThrow('reauth handler is not available');
  });

  it('concurrent triggerStepUp calls share the same inflight promise', async () => {
    let callCount = 0;
    setStepUpHandler(async () => {
      callCount++;
    });
    const [p1, p2, p3] = [triggerStepUp('a'), triggerStepUp('b'), triggerStepUp('c')];
    await Promise.all([p1, p2, p3]);
    // Handler was called exactly once; all three callers waited for the same promise.
    expect(callCount).toBe(1);
  });

  it('subsequent triggerStepUp after resolution calls handler again', async () => {
    let callCount = 0;
    setStepUpHandler(async () => {
      callCount++;
    });
    await triggerStepUp();
    await triggerStepUp();
    expect(callCount).toBe(2);
  });

  it('reauth and step-up handlers are independent', async () => {
    let reauthCalled = false;
    let stepupCalled = false;
    setReauthHandler(async () => { reauthCalled = true; });
    setStepUpHandler(async () => { stepupCalled = true; });
    await triggerReauth();
    await triggerStepUp();
    expect(reauthCalled).toBe(true);
    expect(stepupCalled).toBe(true);
  });
});
