# React Front-End Integration

This guide explains how the reference React application (`reference/` directory) communicates with the C++ PSI service and how to configure the environment.

## Overview
- The C++ binary `psi_server` exposes `POST /psi`, returning JSON payloads aligned with the original JavaScript worker.
- The React adapter (`reference/workerAdapter.js`) sends PSI requests to the HTTP endpoint and automatically falls back to the legacy worker if the server is unreachable.

## Running the C++ Backend
```bash
cmake --build build_temp          # reuse existing build tree
./build_temp/psi_server           # listens on http://localhost:8080/psi
```

> Sandbox note: socket servers are blocked in the hosted environment; run the service locally or on an unrestricted host when testing end-to-end.

## Configuring the React App
- The adapter targets `http://localhost:8080/psi` by default.
- Override only if needed via `window.__PSI_SERVER_ENDPOINT__` (set before the bundle loads) or the optional `REACT_APP_PSI_ENDPOINT` environment variable.

## Fallback Behaviour
If the HTTP request fails (network error, non-2xx response, or user abort), the adapter logs a warning and reroutes the request through the original in-browser worker. Existing UI hooks (`onStart`, `onSuccess`, `onError`) continue to fire with the adapted payload, so no further UI changes are required.

## Testing the Flow
1. Start `psi_server`.
2. Launch the React app (`npm start` inside `reference/`).
3. Interact with the UI and watch the browser console:
   - Successful HTTP requests show normal results, with timings sourced from the C++ backend.
   - If the backend is unavailable, the console warns about the fallback and the worker handles the calculation.

4. Optional: compare latency by toggling the backend on/off and observing the `timings_ms` data returned from the server.

## C++-Only Verification UI
- The `reference_cpp_only/` directory is a clone of the legacy frontend with the JavaScript PSI worker disabled.
- The legacy `psiCalculation.js` module and worker scripts are removed, so no in-browser PSI implementation remains.
- Every PSI request runs through a dedicated Web Worker that posts to `psi_server`; failures raise a visible “PSI C++ backend unreachable” banner and no results are computed.
- Run it the same way as the legacy app (`npm install`, then `npm start`). The endpoint defaults to `http://localhost:8080/psi`; override only if necessary via `window.__PSI_SERVER_ENDPOINT__` or `REACT_APP_PSI_ENDPOINT`.
- Use this build when you need absolute certainty that the UI cannot silently fall back to the JS implementation.
