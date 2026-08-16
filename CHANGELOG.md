# Changelog

Notable changes to `dsh-airlock`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

The first release. Verified against `deepseek-ai/deepseek-harness` at `0.1.0-rc.5`, which
warns of compatibility-breaking changes.

### Added

- **The label ledger**, a projection over `session/event`. It labels each surface-eligible
  event from its own origin, joins that with the labels of the events it cites, and answers
  the label of the context a step is running on. A compaction `replace` propagates labels,
  so summarising untrusted content does not clean it.
- **Gate A**, the monotonic capability gate at `ctx.tools.guard()`. It denies over labels and
  capability classes, and no later listener can turn its denial back into permission. A
  denial names the rule, the label, and the origin event.
- **The ask**, at `tools/pre-execute`. A rule written as `then: ask` returns `{kind:'ask'}`,
  which the harness services through `ctx.approval` after the waterfall and degrades to a
  denial when no approver is mounted. The reason string is self-contained, because an
  approval request carries no tool arguments.
- **The result boundary**, at `tools/post-execute`. A result labelled `secret` is withheld
  with `block`. A result from an untrusted source is framed in a data envelope, with control
  characters, bidi overrides, zero-width characters, and Unicode tag characters replaced by a
  visible marker.
- **Gate B**, at `agent/pre-step`. It redacts messages entering a step and can reject the
  step. It sees the entering batch only, never the conversation history.
- **The provider backstop**, at `llm/stream`. It short-circuits with a valid refusal stream
  rather than editing a request or throwing. Disabled unless a policy arms it.
- **The declarative policy.** Rules over `trust`, `sensitivity`, `capability`, and
  `boundary`, with effects `deny`, `ask`, `redact`, and `allow`. First match wins. A rule
  whose boundary and effect pair no seam can enforce is refused at load.
- **Capability classes**, with `run_code` and every `mcp__*` tool classified conservatively,
  and shells classified as `egress` as well as `mutate`.
- **Configuration**, merged from the built-in defaults, then a workspace policy file, then
  the mount config. Every key, value, and shape is validated, and anything unrecognised fails
  the plugin load rather than silently disabling a rule.
- **`policyFile`**, read from `.json` natively and from `.yml` or `.yaml` through the optional
  `js-yaml` peer. One hop only; a policy file may not name another.
- **Declassification**, as a bounded session-scoped store. A grant is scoped by capability
  class and optionally by tool, covers a later step only at or below the cleared label, and
  never outlives its session. It exists because `ctx.approval` grants are one-shot and the
  harness keeps no grant store.
- **Evidence sinks.** A hash-chained JSONL file, where each line commits to the previous
  line's hash, plus optional OpenTelemetry span events on the spans `dsh-otel` already
  produces. `verifyChain()` reports the first broken line.
- **`dryRun`**, which logs what the policy would have done without doing it.
- **Documentation** of every seam, the whole configuration shape, and the limits: coarse
  labels, path-based secret detection, content replacement not being a confidentiality
  boundary, undetectable tail truncation of the evidence chain, posture being configuration
  rather than detection, the bluntness of the backstop, and the impossibility of rewriting
  arguments.

### Known limits

- Gate B is installed and tested, and no configuration key arms its producer classification,
  so a stock mount rewrites nothing at that seam.
- Every gate consults the declassification store and no seam writes to it, so a stock mount
  never clears a call.
- The evidence chain has no external anchor, so truncation of the tail is undetectable.

See [README.md](./README.md) for the full list and
[docs/verification.md](./docs/verification.md) for what was checked against the harness
source.
