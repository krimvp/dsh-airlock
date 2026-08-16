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

## Corrections

Four details in the proposal do not survive contact with the source.
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

## Not yet built

The first milestone in the proposal (§3.7) is the scope of this implementation.
These parts of the proposal are not present, and the README says so:

- Gate B at `agent/pre-step`, and the redaction of `secret` content before a provider request.
- The policy file, the `ask` posture, and declassification.
- The evidence sinks, OpenTelemetry span events and hash-chained JSONL.
- `dsh-airlock-audit` and `dsh-airlock-supply`.

## An open question the proposal does not address

`run_code` executes a Code Mode program in-process.
Its bridged sub-calls re-enter the guarded pipeline, so leaf tools stay gated.
The program itself can still open its own sockets, so `run_code` is classified
as `egress` here. Under `mode: code` that classification restricts the only
transport the model has once the context is untrusted.
Measure it with `dryRun` before enforcing on a code-mode profile.
