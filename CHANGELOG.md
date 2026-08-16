# Changelog

Notable changes to `dsh-airlock`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

The first release. The seam claims are verified against `deepseek-ai/deepseek-harness` at
`0.1.0-rc.5`, which warns of compatibility-breaking changes. The behaviour is verified end to
end against `@deepseek-ai/dsh` `0.1.0-rc.6`, driven by `deepseek-v4-flash:preview`: 29 pass,
0 fail, 2 weak, 1 gap.

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
  step. It sees the entering batch only, never the conversation history. The `preStep` section
  configures it: `secretProducers`, `untrustedProducers`, `redactAtOrAbove`, and `reject`. The
  defaults are inert. A `reject` naming neither axis is refused at load, because a rejection
  that fires for nothing is a control that reads as armed and is not.
- **The provider backstop**, at `llm/stream`. It short-circuits with a valid refusal stream
  rather than editing a request or throwing. It is armed by a `provider` boundary `redact`
  rule and by nothing else; there is no `enabled` key, so the rule an operator reads is the
  rule that fires. `backstop.auxiliary` decides whether `compaction` and `session-title`
  requests are claimed too, and it defaults to `false`.
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
- **Declassification**, as a bounded session-scoped store, read and written. A grant is scoped
  by capability class and optionally by tool, covers a later step only at or below the cleared
  label, and never outlives its session. It exists because `ctx.approval` grants are one-shot
  and the harness keeps no grant store. A grant is recorded by correlating the harness's own
  durable `approval/asked` and `approval/decided` events; an approval that cannot be
  attributed to an ask this plugin raised, by call id, tool name, and its own exact reason
  string, grants nothing.
- **Evidence sinks.** A hash-chained JSONL file, where each line commits to the previous
  line's hash, plus optional OpenTelemetry span events on the spans `dsh-otel` already
  produces. `verifyChain()` reports the first broken line.
- **`dryRun`**, which logs what the policy would have done without doing it.
- **Documentation** of every seam, the whole configuration shape, and the limits: the shell
  hole in `secret-no-egress`, coarse labels, path-based secret detection, content replacement
  not being a confidentiality boundary, undetectable tail truncation of the evidence chain,
  posture being configuration rather than detection, the bluntness of the backstop, and the
  impossibility of rewriting arguments.
- **The end-to-end verification harness** under `e2e/`. One command boots a real `dsh` CLI on
  a real profile, drives it with a real model, and reads every assertion out of the session
  log. Each scenario runs a control arm and a treatment arm, because a denial with no control
  arm could equally be the model declining or the tool being absent.

### Changed

- A `provider` boundary `redact` rule now blocks on the axes it actually names. Earlier builds
  of 0.1.0 discarded the rule's `when` and fell back to a fixed `sensitivity` at or above
  `secret`. A rule written `when: {trust: untrusted, boundary: provider}` previously did not
  block on trust and now does. Anyone already running such a rule gets different behaviour and
  should re-read the rule they wrote.

### Known limits

- **A secret read through a shell is not labelled, so `secret-no-egress` does not cover a
  session that has `bash`.** The ledger raises the sensitivity axis from a call's path
  argument, and `bash` names no path. Worse, one `bash` call can be both the reader and the
  network client, and the gate evaluates a call before it runs, so a read-and-send one-liner
  is judged against a context in which no read has happened. Both were reproduced end to end
  with the plugin mounted. This is a boundary of the design rather than a defect: labelling a
  shell read would require parsing the command string. The `untrusted` to egress half is not
  affected, because an untrusted label comes from the tool name. See the README for the
  mitigations that work.
- The mount requires `inject: [tools]`. Without it the whole plugin tree fails to load, so the
  plugin's documented "no tool runtime, warn and return" path is unreachable in a real
  composition. Cordis throws on an undeclared service access before the defensive read runs.
- `web_fetch` and `web_search` are unreachable in a stock `dsh-base` plus `dsh-headless`
  composition, so their classification is unit-tested only.
- Compaction label inheritance is unit-tested and has not been exercised in a live run.
- Gate B is inert until `preStep` is configured, and it sees only the messages entering a
  step.
- The evidence chain has no external anchor, so truncation of the tail is undetectable.

See [README.md](./README.md) for the full list and
[docs/verification.md](./docs/verification.md) for what was checked against the harness
source.
