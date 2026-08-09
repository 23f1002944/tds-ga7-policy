# TDS 2026 May GA7 — deterministic policy service

One zero-dependency service exposing the five graded endpoints. Every decision is a
pure function of the request body: no LLM, no phrase lists, and no wall-clock reads,
so the same payload always produces the same answer.

| Endpoint | Question | Decides |
| --- | --- | --- |
| `POST /release-gate` | Q1 | Whether a GitHub Actions run may promote a container image |
| `POST /action-firewall` | Q2 | Whether a model-proposed tool call may run |
| `POST /terraform/plan` | Q3 | Whether one normalized Terraform resource change may apply |
| `POST /sanitize-output` | Q4 | Whether model output is safe for a given sink (OWASP LLM05) |
| `POST /corroborate` | Q5 | Whether open-source evidence actually supports a claim |

`GET /health` returns the endpoint list.

## Run it

```bash
npm start                      # Node, defaults to :8787
node --test test/policy.test.js  # 37 unit tests
node scripts/e2e.mjs           # boots the server and probes it over HTTP
npx wrangler deploy            # Cloudflare Workers (src/worker.js)
```

`src/policy.js` holds all of the logic and the router; `src/worker.js` and
`src/server.js` are thin adapters so the identical code runs on Workers and on Node.

## Design notes

**Release gate (Q1).** Permissions must be the exact three-key least-privilege set —
extra scopes and widened scopes both fail. `pull_request_target` never passes.
Actions owned by `actions` may use a version tag; everything else needs a 40-character
lowercase hex commit SHA. All applicable violation codes are returned together, so a
payload with ten faults reports ten codes.

**Action firewall (Q2).** The boundary is schema, scope, approval and safe rendering —
never phrase matching. A valid `search` stays allowed even when the model just read
text saying "ignore all previous instructions". Checks run top-level schema → tool
allowlist → argument schema → tenant scope → recipient domain → approval → HTML safety,
and the first failure is the reported reason. Argument schemas are exact key sets, so an
extra field is a schema fault rather than a silently ignored one.

**Terraform gate (Q3).** Rules are evaluated in the documented order and the first
failure wins. `>=`, `*` and `latest` are unpinned; `6.2.1`, `= 6.2.1` and `~> 6.0` are not.

**Output gate (Q4).** Decoding runs once — percent-escapes, then HTML entities, then
`\uXXXX` — and if the decoded string differs *and* would trip a rule, the answer is
`ENCODED_PAYLOAD` before any channel rule is consulted. Hostnames are compared exactly
after parsing, which is why `https://cdn-gvyms7t.example@attacker.example/` and
`https://evil.test/?next=https://cdn-gvyms7t.example` are both blocked while a
substring check would wave them through. `//host/path` resolves as `https:` because a
browser will fetch it.

**Corroboration engine (Q5).** Freshness is measured against the request's own `asOf`
and `stalenessDays`. Sources sharing an `origin` are mirrors and collapse to the one
with the lexicographically smallest id, so five copies of one feed never look like
corroboration. A stale authoritative disagreement carries no weight; a fresh one
contradicts outright.

## Docker

`Dockerfile` is the shape the release gate approves: multi-stage, digest-pinned base,
BuildKit secret mounts only, and a non-root runtime user.

```bash
DOCKER_BUILDKIT=1 docker build -t tds-ga7-policy .
```
