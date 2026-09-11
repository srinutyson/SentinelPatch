# SentinelPatch — Phase 6 Evaluation Report

## Methodology

10 CVE findings were selected from two real-world repos never previously used to build or debug this tool (`express-mongoose-es6-rest-api-develop`, `node-express-mongoose-master`), spanning all three of the agent's verdict types (`exploitable`, `not-exploitable`, `insufficient-evidence`) and both repos. For each case, ground truth was established independently — reading the real OSV advisory text, tracing the actual application and dependency source, and attempting real reproduction where feasible — without trusting the tool's own citations or reasoning as evidence. Full case-by-case detail is in `eval-cases.json`.

## Headline numbers

- **Naive baseline** (flag every dependency with any matching CVE, the `npm audit`-style approach): 82 vulnerable packages in `express-mongoose-es6-rest-api-develop`, 51 in `node-express-mongoose-master` — 133 packages a developer would need to triage with zero prioritization.
- **After reachability + agent judgment**: 141 CVE findings were resolved to a verdict across both repos (111 + 30); of those, only 10 verdict instances came back `exploitable` — the actual "fix this now" list a developer would see, an over 90% reduction in what requires immediate attention versus the naive baseline.
- **Hand-verified precision on the 10-case sample**: 6 of 10 tool verdicts confirmed correct, 2 confirmed false positives, 1 masked by an agent-reliability failure (schema-validation crash), 1 genuine cross-run contradiction on identical evidence.
- **Precision specifically on `exploitable` calls** (the highest-stakes label, since it's what a developer acts on): of the 4 unambiguous `exploitable` verdicts in this sample (excluding the contradictory case), 2 were correct — a 50% precision on this small, deliberately hard-picked sample. This is reported honestly rather than smoothed over: the two false positives (`GHSA-gxpj-cx7g-858c`, `GHSA-6rw7-vpxm-498p`) both involved real vulnerabilities in real installed versions, but neither one's trigger condition is actually reachable in production for this app — exactly the class of error a naive "flag everything" tool can never catch, but that this tool's agent layer also didn't fully catch on its own.

## What went right

- **Two `exploitable` verdicts held up under hand-verification with a stronger proof chain than the tool itself found**: `GHSA-hrpp-h998-j3pp` (the tool cited only "qs.parse is reachable"; hand-verification traced it all the way to a real `.limit(+limit)` coercion sink and reproduced a ~3-second freeze) and `GHSA-4vj7-5mj6-jm8m` (the tool's citation was generic; hand-verification found the app's specific accidental morgan-format fallback that makes it exploitable).
- **The same CVE (`GHSA-p6mc-m468-83gw`, lodash prototype pollution) correctly received opposite verdicts** in `vuln-fixture` (exploitable — attacker controls the path) versus this new repo (not-exploitable — path is hardcoded) — real evidence the tool judges usage context, not just package presence.
- **4 of 4 `not-exploitable` verdicts in the sample were confirmed correct**, two of them (`GHSA-664h-wqgq-64gw`, `GHSA-pxg6-pf52-xh8x`) more conclusively than the tool's own evidence showed.

## What went wrong, reported honestly

- **Two confirmed false positives on `exploitable` verdicts.** `GHSA-gxpj-cx7g-858c` (debug ReDoS) is gated behind a debug-namespace flag this app never enables. `GHSA-6rw7-vpxm-498p` (qs arrayLimit) is explicitly downgraded by the advisory's own text under default configuration, which neither app deviates from. Both are cases where the agent found a real reachable call path but didn't account for a runtime gating condition or the advisory's own severity caveat.
- **A structured-output reliability failure** (`GHSA-8cf7-32gw-wr33`) prevented the agent from reaching a verdict at all, even though hand-verification suggests the correct answer (not applicable) was likely reachable by the agent if the crash hadn't occurred.
- **A genuine cross-run contradiction** (`GHSA-qwcr-r2fm-qrc7`) — same repo, same cited evidence, two different verdicts across separate runs, one of which visibly contains leaked, unresolved internal reasoning in its final answer.
- **Coverage gaps are real and repo-dependent**: `express-mongoose-es6-rest-api-develop`'s call-graph coverage was incomplete (189 of 300 CVE-package pairs came back `inconclusive`), while `node-express-mongoose-master` achieved full coverage (0 inconclusive). This isn't a tool bug — it reflects how cleanly jelly can analyze a given codebase's structure — but it means reachability coverage isn't guaranteed uniform across arbitrary real-world repos, and that's a real, defensible limitation to state plainly rather than gloss over.

## Conclusion

The reachability-then-judgment design measurably reduces noise (133 naively-flagged packages down to 10 `exploitable` calls) and, in the cases hand-verified here, is right more often than wrong. But it is not perfectly reliable: two of ten hand-verified cases were false positives that required deeper source tracing than the agent itself performed, and one case surfaced a real cross-run non-determinism issue. The honest conclusion is that this tool is a strong triage aid that meaningfully cuts down what a human needs to review, not a replacement for a human review — the hand-verification process itself, going deeper than the tool's own citations in several cases, is direct evidence that expert review still catches things the automated pipeline misses.