# SentinelPatch

SentinelPatch checks whether the known CVEs flagged in your Node.js project's dependencies are actually exploitable in your specific application, instead of listing every known vulnerability in every dependency regardless of whether your code ever reaches the broken part of it.

It works in two stages. First, it builds a real static call graph of your application (using [jelly](https://github.com/cs-au-dk/jelly)) and checks whether a call path actually exists from your app's entry points into the vulnerable function of a flagged dependency — no AI involved, just graph traversal. Only vulnerabilities with a real, proven reachable path go to the second stage: an LLM agent (Gemini, via LangGraph.js) reads the actual source code along that path and judges whether attacker-controlled data really flows there, whether any guard (auth check, input sanitization) blocks it, and whether the path is reachable from production or only from test code — grounding its explanation in the real OSV advisory text via retrieval, not just its own possibly-outdated training knowledge.

## Requirements

- Node.js 20+
- [jelly](https://github.com/cs-au-dk/jelly) installed and available on your `PATH` (used for call-graph generation)
- A Google Gemini API key (free tier works) — required for the exploitability-judgment step; not needed if you only use `skipAgent: true`

## Install

```
npm install sentinelpatch
```

Set your Gemini API key as an environment variable (or in a `.env` file in your own project, loaded via `dotenv` or similar):

```
GEMINI_API_KEY=your_key_here
```

## Usage

```js
import { runScan } from 'sentinelpatch';

const summary = await runScan('/path/to/some-app', {
  skipAgent: false,      // set true to skip the AI exploitability step (faster, no Gemini calls)
  output: 'json',        // 'table' | 'json' | 'markdown' — controls the shape of the returned/printed report
  outFile: null,         // pass a file path to write the report there instead of just returning it
});

console.log(summary.exploitable);
```

`runScan(inputPath, options)` extracts the full dependency tree of the repo at `inputPath`, queries OSV.dev for known CVEs, builds a static call graph, checks which flagged CVEs are actually reachable from the app's entry points, and — for each reachable one — runs an AI agent to judge real-world exploitability. It returns a summary object: vulnerable package count, agent-confirmed exploitable count, the exploitable findings themselves (with reasoning and cited evidence), and the count of inconclusive/unresolved cases.

You can also import `resolveScanContext(path)` directly if you want to call the lower-level pipeline functions yourself instead of the all-in-one `runScan`.

## Where results are stored

Each scanned repository gets its own folder under `~/.sentinelpatch/projects/<project-id>/`, keyed by a hash of the repo's absolute path so two different repos with the same folder name never collide. That folder holds the raw vulnerability report, the generated call graphs, the coverage report, and the agent's verdicts for that repo.

## Development

```
npm test
```

Runs the Jest unit and integration test suite (fast, no external API calls — the one test that touches a real call graph uses a committed fixture).

```
npm run test:agent
```

Runs a real integration test against the live Gemini API (slower, requires `GEMINI_API_KEY`, not run in CI). Requires the fixture repo at `target-repos/vuln-fixture` to have already been scanned once (`node scripts/queryVulnerabilities.js target-repos/vuln-fixture` then `node scripts/buildCallGraphs.js target-repos/vuln-fixture`) so its reachability data exists under `~/.sentinelpatch/`.

## License

ISC
