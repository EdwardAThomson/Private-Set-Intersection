const DEFAULT_ENDPOINT = 'http://localhost:8080/psi';

let activeController = null;

self.onmessage = async (event) => {
  const { type, payload, endpoint } = event.data || {};

  if (type === 'abort') {
    if (activeController) {
      activeController.abort();
      activeController = null;
    }
    return;
  }

  if (type !== 'start' || !payload) {
    self.postMessage({ type: 'error', error: 'Worker received invalid message' });
    return;
  }

  const targetEndpoint = endpoint || DEFAULT_ENDPOINT;
  activeController = new AbortController();

  try {
    const response = await fetch(targetEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: activeController.signal
    });

    if (!response.ok) {
      self.postMessage({
        type: 'error',
        error: `PSI server responded with status ${response.status}`
      });
      return;
    }

    const data = await response.json();
    self.postMessage({ type: 'success', data });
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      self.postMessage({ type: 'aborted' });
    } else {
      const message = error instanceof Error ? error.message : String(error);
      self.postMessage({ type: 'error', error: message });
    }
  } finally {
    activeController = null;
  }
};

export {};
