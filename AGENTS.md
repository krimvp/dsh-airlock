# AGENTS.md

Rules for changing this repository.

## The one invariant

The gate decides over labels. It never decides over an argument string.

A change that adds pattern matching on tool arguments or tool output to a
decision path is out of scope for this project, whatever it catches. The
project exists because that approach is advisory rather than enforcing. Adding
it back would trade the only property this plugin has for the appearance of
broader coverage.

Classification data — which tool belongs to which capability class, which glob
marks a secret path — is not argument matching. That data is configuration
about tools, evaluated before any model output exists.

## Code

Write for the reader who is deciding whether to trust this with a denial.

- TypeScript, ESM, strict mode. The build must pass `npm run build` with no error.
- No runtime dependency beyond the harness peers. The plugin ships zero.
- The guard is synchronous by contract. Nothing on the `ctx.tools.guard()` path may await.
- A listener contains its own errors. A failure in this plugin must degrade the
  plugin, never the agent loop.
- A failure must not become an allow. When the ledger is stale or absent the
  gate abstains, and when it is uncertain it over-approximates.
- Local structural copies of dsh types live in `src/dsh.ts`. The plugin declares
  no dsh package as a dependency. Read every field defensively; a harness
  compatibility break must degrade this plugin rather than crash it.
- Name the harness version any new claim was verified against.

## Documentation

- Short declarative sentences. One idea per sentence.
- No contractions.
- State limits in the README. A reader who discovers a limit you did not
  document has learned that the other claims are unverified too.
- Do not describe an unbuilt feature in the present tense.

## Tests

- `npm test` runs on `node:test`. Add no test framework.
- A new rule needs a test that it denies, and a test that it leaves reading open.
- Any change to label propagation needs a compaction test. The claim that
  summarising cannot launder a label is the load-bearing one.

## Verification

Every claim about a harness seam is checkable against the harness source.
Check it rather than repeating this file.

| Claim | Where it is verified |
| --- | --- |
| `ctx.tools.guard()` is monotonic and cannot force-allow | `packages/core/tools/README.md` |
| A `replace` must cite every shadowed surface node | `packages/core/session/src/surface.ts` |
| `tools/pre-execute` cannot rewrite arguments | `docs/tool-execution-pipeline.md` |
| Tool names and parameter names | `docs/tool-catalog.md` |
| `Agent.id` is the session id | `packages/core/agent/src/index.ts` |

## Commits

- One logical change per commit.
- Subject in the imperative, under 72 characters.
- Explain why in the body when the what is not obvious.
