// Coordinates the single re-authentication dialog triggered when the backend
// responds with HTTP 403 + `reauthenticationRequired: true` on a protected
// request. The axios interceptor calls `triggerReauth()`; the <ReauthModal>
// registers the actual UI handler via `setReauthHandler`. A single in-flight
// promise guards against concurrent 403s opening multiple dialogs.

let reauthHandler = null;
let inflight = null;

export function setReauthHandler(handler) {
  reauthHandler = handler;
}

export function triggerReauth() {
  if (!reauthHandler) {
    return Promise.reject(new Error('Re-authentication handler is not available'));
  }

  if (inflight) {
    return inflight;
  }

  inflight = (async () => {
    try {
      await reauthHandler();
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}
