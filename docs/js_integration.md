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
Set one of the following before starting the React dev server:
- `VITE_PSI_ENDPOINT` (Vite)
- `REACT_APP_PSI_ENDPOINT` (Create React App)
- `window.__PSI_SERVER_ENDPOINT__` (set on `window` before the bundle loads)

If no value is provided, the adapter defaults to `http://localhost:8080/psi`.

Example with Vite:
```bash
VITE_PSI_ENDPOINT=http://localhost:8080/psi npm start
```

## Fallback Behaviour
If the HTTP request fails (network error, non-2xx response, or user abort), the adapter logs a warning and reroutes the request through the original in-browser worker. Existing UI hooks (`onStart`, `onSuccess`, `onError`) continue to fire with the adapted payload, so no further UI changes are required.

## Testing the Flow
1. Start `psi_server`.
2. Launch the React app (`npm start` inside `reference/`).
3. Interact with the UI and watch the browser console:
   - Successful HTTP requests show normal results, with timings sourced from the C++ backend.
   - If the backend is unavailable, the console warns about the fallback and the worker handles the calculation.

4. Optional: compare latency by toggling the backend on/off and observing the `timings_ms` data returned from the server.

