// Coordinates the re-authentication / step-up MFA dialog(s) triggered when the
// backend responds with HTTP 403 + `reauthenticationRequired: true` or
// `stepUpRequired: true`. The axios interceptor calls `triggerReauth()` or
// `triggerStepUp(actionLabel)`. <ReauthModal> registers the actual UI handlers
// via `setReauthHandler` and `setStepUpHandler`. Single in-flight promise guards
// prevent concurrent 403s from opening multiple dialogs.

const handlers = {
  reauth: null,
  stepup: null,
};

const inflight = {
  reauth: null,
  stepup: null,
};

export function setReauthHandler(handler) {
  handlers.reauth = handler;
}

export function setStepUpHandler(handler) {
  handlers.stepup = handler;
}

function runOnce(kind, label) {
  const handler = handlers[kind];
  if (!handler) {
    return Promise.reject(new Error(`${kind} handler is not available`));
  }
  if (inflight[kind]) {
    return inflight[kind];
  }

  inflight[kind] = (async () => {
    try {
      await handler(label);
    } finally {
      inflight[kind] = null;
    }
  })();

  return inflight[kind];
}

export function triggerReauth() {
  return runOnce('reauth', null);
}

// `actionLabel` is an optional human-readable description of the action that
// triggered step-up (e.g. "uploading this document"). Used for modal copy only.
export function triggerStepUp(actionLabel = null) {
  return runOnce('stepup', actionLabel);
}

export function clearHandlers() {
  handlers.reauth = null;
  handlers.stepup = null;
  inflight.reauth = null;
  inflight.stepup = null;
}