# SentinelPatch

SentinelPatch checks whether the known CVEs flagged in your Node.js project's dependencies are actually exploitable in your specific application, instead of listing every known vulnerability in every dependency regardless of whether your code ever reaches the broken part of it.

It works in two stages. First, it builds a real static call graph of your application (using [jelly](https://github.com/cs-au-dk/jelly)) and checks whether a call path actually exists from your app's entry points into the vulnerable function of a flagged dependency — no AI involved, just graph traversal. Only vulnerabilities with a real, proven reachable path go to the second stage: an LLM agent (Gemini, via LangGraph.js) reads the actual source code along that path and judges whether attacker-controlled data really flows there, whether any guard (auth check, input sanitization) blocks it, and whether the path is reachable from production or only from test code — grounding its explanation in the real OSV advisory text via retrieval, not just its own possibly-outdated training knowledge.

## Requirements

- Node.js 20+
- [jelly](https://github.com/cs-au-dk/jelly) installed and available on your `PATH` (used for call-graph generation)
- A Google Gemini API key (free tier works) — required for the exploitability-judgment step; not needed if you only use `--skip-agent`

## Install

This project isn't published to the npm registry yet. Run it from a local clone:

```
git clone https://github.com/srinutyson/SentinelPatch
cd sentinelpatch
npm install
npm link
```

`npm link` makes the `sentinelpatch` command available globally on your machine, backed by this local clone.

Create a `.env` file in the project root with your Gemini API key:

```
GEMINI_API_KEY=your_key_here
```

## Usage

```
sentinelpatch scan <path-to-a-repo>
```

Scans the given repository: extracts its full dependency tree, queries OSV.dev for known CVEs, builds a static call graph, checks which flagged CVEs are actually reachable from the app's entry points, and — for each reachable one — runs an AI agent to judge real-world exploitability.

If `<path-to-a-repo>` is omitted, it defaults to the current directory.

### Options

- `--skip-agent` — stop after the reachability check; skip the AI exploitability-judgment step (no Gemini calls, much faster, useful for a quick first pass or when no API key is configured)
- `--output <format>` — `table` (default, human-readable), `json`, or `markdown`
- `--out-file <path>` — write the report to a file instead of printing it to stdout

### Example

```
sentinelpatch scan ./my-app
```

```
Scanning /Users/you/my-app...
Wrote vulnerability report for my-app-a1b2c3d4 to ~/.sentinelpatch/projects/my-app-a1b2c3d4/vulnerabilities.json
Building call graphs...
...
Scan target: /Users/you/my-app
Vulnerable packages found: 2
Exploitable (agent-confirmed): 1
Inconclusive (incomplete coverage): 0

Exploitable findings:
  - GHSA-p6mc-m468-83gw (confidence 1)
    The application exposes a production route that directly passes user-controlled
    input into lodash's _.set() function, with no authentication checks or input
    sanitization guards on the path before reaching it.
```

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
