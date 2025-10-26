# Private Set Intersection Demo (C++ Backend Only)

A minimally working demonstration of a Private Set Intersection (PSI).

> **Important:** This copy of the demo is hard-wired to the C++ `psi_server` backend. The original JavaScript worker fallback has been removed, so the UI will fail fast if the server is not reachable.
> The legacy `psiCalculation.js` implementation and worker scripts are intentionally omitted; every PSI request goes over HTTP to the C++ service.

The aim is to prove this can work in a Real Time Strategy game, as shown in the research paper [OpenConflict: Preventing Real Time Map Hacks in Online Games](https://www.shiftleft.org/papers/openconflict/).

There is a live demo here: [PSI Demo @ Vercel](https://psi-demo-delta.vercel.app/) (hopefully not broken! :-) )

## Description
This code is a simple demonstration of how PSI calculations work.

One deficiency of the OpenConflict solution is that it has no protection against players who lie about their positions or visibility. I think the problem of lying is one that can be solved. Essentially, the players would reveal their all their position and visibility sets at the end of the game. Then players can check those against the rules of the game to ensure the calculations were correct and fit with the physics of the game.

Additionally, there would need to be a dispute resolution protocol on order to adjudicate in times when one player disagrees with another. This would happen when one player cheats and then denies it.

The overall top-level strategy is outlined in a blog I wrote in June 2020: [Preventing cheaters in Fog Of War Games](https://edward-thomson.medium.com/preventing-cheaters-in-fog-of-war-games-69f202fbe107).

### Implementation choices

Here are a few of the technical Implementation choices that I made in this app.

* ChaCha20 Stream Cipher
* Blake3 hash function
* Multi-level grid system
* Web worker wrapper for C++ API calls

These were picked for their speed of operation or to otherwise reduce overheads. In the future I probably need to look to Wasm, or otherwise creating a desktop app.

### PSI Explainer
I put together a page that explains more of the details of what PSI is and how it works: [PSI Explainer](./explanations/psi_explainer.md).

## Using This App

### Highlights
- 100% of PSI processing happens on the C++ backend (`psi_server`).
- A small Web Worker proxy handles HTTP calls so UI rendering/input stay responsive.
- Both the visualization and roguelike demos surface backend timings directly in the UI.

### Home Page
A demonstration of the protocol working. The units and visibility are static / simple points. Just hit the "Run" button. 

![PSI Protocol Demo](explanations/Home_Page_Screenshot_20241006.png)

### PSI Visualization
This is a simple visualization of point particles moving inside a box (Bob's units). The visibility circles are static but sweep out a 2D area unlike the static test on the home page. PSI requests run continuously in the background and the Web Worker wrapper keeps the UI responsive.

To reduce the amount of data shipped to the backend, the app converts positions and visibility to cells (1 cell is 50x50 pixels). When the C++ service responds it returns aggregate timings so you can see how long each phase took.

![PSI Visualization](explanations/PSI_Visualization_20241006.png)

There are is a traditional visibility calculation that is helpful to calibrate what should be seen. You should really open the console log to check the results.

### Roguelike Demo
This variant keeps the original roguelike demo but pushes all PSI work through the C++ backend. A status panel shows the latest timings returned by the server while a Web Worker keeps the main thread free for rendering and input.

![PSI Roguelike](explanations/PSI_Roguelike_Screenshot_20250309_232639.png)


## Installation

1. From the repository root, change into the C++-only frontend:

```bash
cd reference_cpp_only
```

2. Install the React dependencies:

```bash
npm install
```

3. Start the C++ backend (from another terminal):

```bash
./build_temp/psi_server
```

4. Launch the React dev server (the endpoint defaults to `http://localhost:8080/psi`):

```bash
npm start
```

This runs the app at http://localhost:3000. If the backend is offline you will immediately see “PSI C++ backend unreachable” messages in the UI.

> Need to target a different host/port? Set `window.__PSI_SERVER_ENDPOINT__` before the bundle loads or export `REACT_APP_PSI_ENDPOINT` before running `npm start`.


## License
This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.


## Acknowledgements
Many thanks to the following people:

- Anuj Gupta, the researcher who shared this idea with me.
- ChatGPT
- Everyone at the Decentralized Gaming Association [DGA Discord](https://discord.com/invite/eZEVrSd)
