const DEFAULT_ENDPOINT = 'http://localhost:8080/psi';

const createBackendWorker = () =>
  new Worker(new URL('./backendFetchWorker.js', import.meta.url));

const getConfiguredEndpoint = () => {
  if (typeof window !== 'undefined' && window.__PSI_SERVER_ENDPOINT__) {
    return window.__PSI_SERVER_ENDPOINT__;
  }
  return DEFAULT_ENDPOINT;
};

const toNumber = (value) => {
  const n = typeof value === 'number' ? value : Number(value);
  if (Number.isNaN(n)) {
    throw new Error('Invalid coordinate value: ' + value);
  }
  return n;
};

const parseUnitString = (value) => {
  const parts = String(value).split(/[\s,]+/).filter(Boolean);
  if (parts.length < 2) {
    throw new Error('Cannot parse unit string: ' + value);
  }
  return { x: toNumber(parts[0]), y: toNumber(parts[1]) };
};

const normaliseUnits = (units, prefix) =>
  units.map((unit, index) => {
    if (unit == null) {
      throw new Error('Unit entry is null/undefined');
    }
    if (typeof unit === 'string') {
      const coords = parseUnitString(unit);
      return { id: `${prefix}-${index}`, x: coords.x, y: coords.y };
    }
    if (typeof unit === 'object') {
      let x;
      let y;
      if ('x' in unit && 'y' in unit) {
        x = toNumber(unit.x);
        y = toNumber(unit.y);
      } else if ('unit' in unit) {
        const coords = parseUnitString(unit.unit);
        x = coords.x;
        y = coords.y;
      } else if ('position' in unit) {
        const coords = parseUnitString(unit.position);
        x = coords.x;
        y = coords.y;
      } else {
        let description;
        try {
          description = JSON.stringify(unit);
        } catch {
          description = String(unit);
        }
        throw new Error('Unit object missing x/y fields: ' + description);
      }
      const id = unit.id != null ? String(unit.id) : `${prefix}-${index}`;
      return { id, x, y };
    }
    throw new Error('Unsupported unit type: ' + typeof unit);
  });

const adaptServerResponse = (payload) => {
  if (payload.error) {
    throw new Error(payload.error);
  }

  const bobItems = (payload.bob_message && payload.bob_message.items) || [];
  const aliceItems = (payload.alice_message && payload.alice_message.items) || [];
  const bobResponseItems = (payload.bob_response && payload.bob_response.items) || [];
  const decrypted = Array.isArray(payload.decrypted) ? payload.decrypted : [];
  const timings = payload.timings_ms || {};

  const bobValues = bobItems.map((item) => ({
    unit: item.position,
    ciphertext: item.ciphertext,
    nonce: item.nonce
  }));

  const aliceValues = aliceItems.map((item) => ({
    unit: item.position,
    blindedPoint: item.blindedPoint
  }));

  const bobTransformedValues = bobResponseItems.map((item) => ({
    unit: item.position,
    transformedPoint: item.transformedPoint
  }));

  const results = decrypted.map((unit) => ({ unit }));

  const bobSetup = Number(timings.bob_setup || 0);
  const aliceSetup = Number(timings.alice_setup || 0);
  const bobResponse = Number(timings.bob_response || 0);
  const aliceFinalize = Number(timings.alice_finalize || 0);

  const totalTime = bobSetup + aliceSetup + bobResponse + aliceFinalize;

  return {
    type: 'success',
    results,
    bobValues,
    aliceValues,
    bobTransformedValues,
    performance: {
      totalTime,
      bobSetupTime: bobSetup,
      keyExchangeTime: aliceSetup + bobResponse,
      intersectionTime: aliceFinalize,
      inverseOperations: 0,
      decryptOperations: 0,
      successfulDecryptions: results.length
    },
    rawResponse: payload,
    backend: 'psi_server_cpp'
  };
};

export const runPSIInWorker = (bobUnits, aliceUnits, callbacks) => {
  const { onStart, onSuccess, onError } = callbacks || {};
  let aborted = false;

  if (onStart) onStart();

  let payload;
  try {
    payload = {
      bob_units: normaliseUnits(bobUnits, 'bob'),
      alice_units: normaliseUnits(aliceUnits, 'alice')
    };
  } catch (error) {
    if (onError) onError(error);
    return { abort: () => {} };
  }

  const endpoint = getConfiguredEndpoint();

  const worker = createBackendWorker();
  let settled = false;

  const cleanup = () => {
    if (!settled) {
      settled = true;
      worker.terminate();
    }
  };

  worker.onmessage = (event) => {
    const { type, data, error } = event.data || {};
    if (aborted) {
      cleanup();
      return;
    }

    if (type === 'success') {
      try {
        const adapted = adaptServerResponse(data);
        if (onSuccess) onSuccess(adapted);
      } catch (adaptError) {
        const wrapped =
          adaptError instanceof Error
            ? adaptError
            : new Error(String(adaptError));
        if (onError) onError(wrapped);
      }
      cleanup();
    } else if (type === 'error') {
      const wrapped = new Error(`PSI C++ server request failed: ${error}`);
      console.error('PSI C++ backend unavailable; no JS fallback in this build.');
      if (onError) onError(wrapped);
      cleanup();
    } else if (type === 'aborted') {
      cleanup();
    }
  };

  worker.onerror = (event) => {
    if (aborted) {
      cleanup();
      return;
    }
    const message = event?.message || 'Worker error';
    const wrapped = new Error(`PSI worker error: ${message}`);
    if (onError) onError(wrapped);
    cleanup();
  };

  worker.postMessage({
    type: 'start',
    endpoint,
    payload
  });

  return {
    abort: () => {
      if (settled) {
        return;
      }
      aborted = true;
      worker.postMessage({ type: 'abort' });
      cleanup();
    }
  };
};
