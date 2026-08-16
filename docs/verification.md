# Verification against the harness

[proposal.md](./proposal.md) is the strategy document this implementation follows.
It was written from the harness documentation.
This file records what was checked against the harness source before any code was written,
and where the proposal turned out to be wrong.

Verified against `deepseek-ai/deepseek-harness` at `0.1.0-rc.5`.

## Confirmed

Every seam the design depends on exists and behaves as the proposal claims.

| Claim | Source | Result |
| --- | --- | --- |
| `ctx.tools.guard()` exists, is monotonic, and cannot force-allow | `packages/core/tools/README.md` | Confirmed. `ToolGuard = (execution) => string \| undefined`. |
| A guard denial survives later listeners | `packages/core/tools/README.md`, `.agents/notes/implemented/feature/2026-06-30-interception-extension-points.md` | Confirmed. |
| `sourceEventSeqs` records lineage in core | `packages/core/session/src/types.ts` | Confirmed. |
| A compaction `replace` must cite every shadowed surface node | `packages/core/session/src/surface.ts` | Confirmed, and enforced by a throw at append time. |
| `tools/pre-execute` cannot rewrite arguments | `docs/tool-execution-pipeline.md` | Confirmed. |
| `agent.inject()` content is a `user/message` distinguishable by source | `packages/llm/llm/src/message.ts` | Confirmed. `MessageSource.kind` is `user`, `plugin`, `model`, or `tool`. |
| `Agent.id` keys the same space as `Session.id` | `packages/core/agent/src/index.ts` | Confirmed. `readonly id: SessionId`. |

The rest of this section was verified for the seams added after the first milestone. Each
claim was read out of the harness source rather than out of its documentation.

### `tools/post-execute`

`PostToolDecision` is a three-member union, and nothing else is accepted:

```ts
| { kind: 'accept'; content?: ContentBlock[] }
| { kind: 'accept'; value: unknown }
| { kind: 'block'; feedback: ContentBlock[] }
```

Setting both `content` and `value` on one `accept` is a runtime error.

**Content replacement is not a confidentiality boundary.** The harness says so in as many
words in `packages/core/tools/README.md`: "content replacement is not a confidentiality
boundary". Replacing `content` changes what the model sees and what the durable event
records. The canonical `value` survives untouched, and a Code Mode `run_code` program reads
that value through its SDK bindings, so a content-redacted secret is one `run_code` call away
from the network.

The two mechanisms that do withhold are `block` and an `accept` that replaces `value`. A
replaced value is revalidated against the tool's declared `output.schema` and re-rendered, so
a redaction that typechecks for one tool becomes an `INVALID_TOOL_OUTPUT` failure for the
next, and this plugin cannot know that schema. `block` is correct for every tool, so
`block` is what the implementation uses for a secret result.

A `block` discards the tool's own deferred `additionalContexts`. That is intended here: they
are derived from content the policy just refused to release.

A tool definition's own `finalizeContent` runs after this seam and may replace content again.
The untrusted data envelope is therefore best effort against a hostile tool *definition*, and
exact against hostile tool *data*, which is the threat it is for.

### `tools/pre-execute` and `ctx.approval`

`PreToolDecision` is `{kind:'allow'}`, `{kind:'deny', reason}`, or `{kind:'ask', reason?}`.

An `ask` is not serviced by the listener. The registry resolves it through `ctx.approval`
**after** the whole reorderable waterfall has run
(`packages/core/tools/src/index.ts`). It degrades to a denial in two cases: no approval
service is mounted, and `exec.agent` is `undefined`. A plugin that returns `ask` therefore
never needs to call approval itself, and must not assume a human will see the question.

`ctx.approval` grants are **one-shot only**. The outcome union is `allowed-once`, `rejected`,
`cancelled`, and `unavailable` (`packages/interaction/user-approval/README.md`). There is no
allow-always, no remembered rule, no grant store, and no revocation API. That is the whole
reason `declassify.ts` exists: a clearance that outlives one call has to be kept by the
plugin, bounded and session-scoped, because the harness will not keep it.

`ctx.approval.request()` throws when it is called outside an open turn. It also carries no
tool arguments — an answerer sees the agent, the tool name, the optional call id, and the
`reason` string. The reason string must therefore be self-contained, which is why the ask
message names the rule, the label, and the origin event in full.

### `agent/pre-step`

The waterfall signature is in the API catalogue at
`packages/extensions/tool-cordis/src/api-catalog.ts:2225`.

The default `next()` enters the claimed batch followed by the projected runtime context
(`packages/core/agent-loop/src/agent.ts:234-240`). A listener that rewrites the payload batch
instead of the decision drops the context message the loop appended, so the implementation
redacts what `next()` returned.

### `llm/stream`

The waterfall signature and the sanction for short-circuiting are at
`packages/llm/llm/src/index.ts:64`. A listener may return its own `AsyncIterable` without
calling `next()`.

A loop-built request is **deep-frozen** before it reaches the seam
(`packages/core/agent-loop/src/agent.ts:486-494`), so any mutation throws. Listeners read the
request and never rewrite it.

Throwing from the listener is not a graceful block. Middleware failures are not normalised
into the stream protocol (`packages/llm/llm/README.md:27`), so a throw ends the whole turn
with `turn/end { kind: 'error', code: 'UNKNOWN' }` and an `agent/error` emit. Short-circuiting
with a valid chunk run is the graceful path, and it is what the backstop does. The chunk
grammar is enforced at `packages/llm/llm/src/invariant.ts:36-84` over the union at
`packages/llm/llm/src/types.ts:291-303`.

`llm/stream` is not scope-filtered, so a listener sees every session and must key off
`options.sessionId`.

### Headless is not detectable

The harness exposes no way to find out whether a human is present. There is no service, no
flag, and no API that reports it. `dsh-headless` is a bundle of plugins, not a capability
signal.

Two related facts are checkable, and both mean an ask will not reach anyone: `ctx.approval`
is absent, or the approval service is configured with an `ApprovalPolicy` of `'never'`. The
implementation uses those two to lower a configured posture, and claims nothing more.

## Corrections

Five details in the proposal do not survive contact with the source.
The implementation follows the source.

**The tool names are wrong.**
The proposal's policy example names `fs_write`, `fs_edit`, `shell`, and `terminal`.
The registered names are `write`, `edit`, `bash`, `pwsh`, and the six `terminal_*` tools.
Taken literally the example policy would have classified nothing.
See `docs/tool-catalog.md` in the harness.

**A guard is synchronous.**
`ToolGuard` returns `string | undefined`, not a promise.
Gate A therefore cannot await anything, which fixes the ledger as an in-memory
projection read synchronously. It also rules out the `ask` posture at this seam:
asking needs `ctx.approval` at `tools/pre-execute`.

**`sourceEventSeqs` is not the step's context.**
The proposal computes a step's label from `sourceEventSeqs`.
That field only exists on the three surface-eligible event types, and on an
`assistant/message` it cites `assistant/chunk` events, which never reach the
surface and carry no label. Following it alone would find nothing.

What the model actually sees is the **ordered surface**.
The ledger therefore joins over live surface nodes and uses `sourceEventSeqs`
for its real purpose: propagating labels across a `replace`.
The soundness argument is unchanged and the mechanism is the one the harness
actually provides.

**Step scope is surface scope.**
The proposal contrasts "step scope" with a sticky per-session flag.
The live surface gives exactly that property for free: a node dropped from the
surface stops contributing, and a node shadowed by a replacement has already
handed its label to the replacement.

**`agent/pre-step` carries the newly claimed batch, not the history.**
The proposal's turn-flow table describes Gate B as rewriting "what the model is about to
see", which reads as the assembled context. The payload is narrower than that: it is the
inbox content claimed for this step, which is fresh human input and injected context. A
secret that arrived earlier through a `tool/result` is already in the log and is not in this
batch, so nothing at this seam can reach it. Gate B is a gate on what enters a step, and the
implementation claims neither more nor less.

## Built since the first milestone

These parts of the proposal are present in 0.1.0, and the README documents what each one can
and cannot do:

- Gate B at `agent/pre-step`, redacting entering messages and able to reject a step.
- The policy file, in JSON natively and in YAML through the optional `js-yaml` peer.
- The `ask` posture, at the `tools/pre-execute` seam, routed by the harness through `ctx.approval`.
- Declassification, as a bounded session-scoped store consulted by every gate.
- The evidence sinks: hash-chained JSONL, and OpenTelemetry span events.
- The provider backstop at `llm/stream`, disabled unless a policy arms it.

## Not yet built

- **The producer classification that arms Gate B.** The redaction and rejection are
  implemented and tested. No configuration key sets `secretProducers`, `untrustedProducers`,
  `redactAtOrAbove`, or `reject`, and the plugin mounts the seam with an empty policy, so as
  shipped it rewrites nothing and rejects nothing.
- **The prompt that records a declassification grant.** Every read path consults the store.
  No seam writes to it, so a stock mount never clears a call.
- **An external anchor for the evidence chain.** Truncation of the tail is undetectable
  without one. See the README limitations.
- **`dsh-airlock-audit`** (proposal §3.6): OCSF and CEF mapping, syslog and HTTPS shipping,
  retention, and per-session crypto-erasure. Closes G3 and G4.
- **`dsh-airlock-supply`** (proposal §3.6): capability manifests for installed plugins, static
  profiling of what each one touches, and a CI gate. Closes G6.

## An open question the proposal does not address

`run_code` executes a Code Mode program in-process.
Its bridged sub-calls re-enter the guarded pipeline, so leaf tools stay gated.
The program itself can still open its own sockets, so `run_code` is classified
as `egress` here. Under `mode: code` that classification restricts the only
transport the model has once the context is untrusted.
Measure it with `dryRun` before enforcing on a code-mode profile.
