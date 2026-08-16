# Verification against the harness

[proposal.md](./proposal.md) is the strategy document this implementation follows.
It was written from the harness documentation.
This file records what was checked against the harness source before any code was written,
what was later checked against a running harness, and where both the proposal and this
project's own documentation turned out to be wrong.

Source claims are verified against `deepseek-ai/deepseek-harness` at `0.1.0-rc.6`.
Runtime claims are verified against `@deepseek-ai/dsh` `0.1.0-rc.6`, driven by
`deepseek-v4-flash:preview` over Ollama Cloud. See [Verified against a running
harness](#verified-against-a-running-harness).

Every source claim was first checked at `0.1.0-rc.5` and then re-checked at `0.1.0-rc.6`.
No seam this plugin depends on changed between the two releases. The re-check found no
difference in any type, any event name, any event payload field, any enforcement throw, or
any registered tool name. No plugin code changed as a result.

### Evidence basis for the 0.1.0-rc.6 re-check

The two releases were read from different kinds of artifact, and the difference bounds what
the rc.6 attribution below means.

The rc.5 reading was a git clone of `deepseek-harness` with the full `packages/*/src` tree,
so it could cite a file and a line.

The rc.6 reading is the published npm packages: `@deepseek-ai/dsh-tools`, `dsh-session`,
`dsh-llm`, `dsh-agent`, `dsh-agent-loop`, `dsh-user-approval`, `dsh-tool-fs`,
`dsh-tool-fs-search`, `dsh-tool-bash`, `dsh-tool-pwsh`, `dsh-tool-terminal`, `dsh-tool-web`,
`dsh-mcp-client`, and `dsh-tool-cordis`, each at `0.1.0-rc.6`. Each package ships three
useful things: the emitted declarations under `lib/types/*.d.ts`, the compiled
implementation under `lib/*.js`, and the package `README.md`. Every rc.6 confirmation below
was read out of one of those three.

Two limits follow, and both are stated because a reader who discovers them later has learned
that the other claims are unverified too.

**The published packages do not ship TypeScript source.** Each `exports` map advertises a
`./src/*` subpath, but the `files` list omits `src`, so no tarball contains it. The advertised
subpath resolves to nothing. Declarations and compiled output carry every claim checked here,
so nothing below rests on source that was unavailable, but a reader cannot re-derive a
repository line number from an npm install.

**The repository line numbers below are rc.5 coordinates.** They were not re-checked at
rc.6, because the file they index is not published. What was re-checked at rc.6 is the
content at each citation, against the corresponding declaration, compiled function, or
README sentence. A citation of the form `packages/llm/llm/src/invariant.ts:36-84` therefore
names where the rule lives in the source tree and where it was first read, not a line this
project confirmed at rc.6.

The harness repository publishes no git tags. `git fetch --tags` and `git ls-remote --tags`
both return an empty set, so an `0.1.0-rc.6` tag could not be used as a cross-check. The
npm registry is the only version-pinned source of harness code this project can reach.

Two facts make the null result trustworthy rather than merely unrefuted. The package
`README.md` of every seam-bearing package — `dsh-tools`, `dsh-session`, `dsh-llm`,
`dsh-agent`, `dsh-agent-loop`, and `dsh-user-approval` — is byte for byte identical between
the rc.5 clone and the rc.6 tarball. The rc.5 clone's own `package.json` files declare
`0.1.0-rc.5`, so the two readings really are of different releases.

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

#### The two audit events declassification correlates

This pair is the most fragile dependency in the plugin. `declassify.ts` learns how a human
answered by matching one durable event to another, so a renamed event or a renamed field
would not fail loudly. It would stop granting clearance and leave no signal that it had.
The names and the payload shapes were therefore re-read in full at `0.1.0-rc.6`, in
`@deepseek-ai/dsh-user-approval` `lib/types/index.d.ts`:

```ts
'approval/asked': { id: ApprovalRequestId; toolName: string; callId?: CallId; reason?: string }
'approval/decided': { id: ApprovalRequestId; outcome: ApprovalOutcome }
```

Both event names are unchanged. All six fields are unchanged in name, type, and optionality.
The declaration is byte for byte identical to the rc.5 source, including its doc comment.
Both events remain log-only audit records that carry no `surfaceOp`, so folding them cannot
disturb the surface the ledger reads. Exactly one `approval/decided` still follows each
`approval/asked` with the same `id`. The correlation `declassify.ts` performs is therefore
sound at rc.6, and no change was needed.

`ApprovalOutcome` is likewise unchanged: `allowed-once`, `rejected`, `cancelled`, and
`unavailable`. The rc.6 service exposes `request`, `setPolicy`, `overrideOf`,
`effectiveApprovalPolicy`, and `setApprovalPolicy`, and nothing else. There is still no
allow-always, no grant store, and no revocation API, which is what keeps `declassify.ts`
necessary.

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

## Verified against a running harness

Everything above was read out of source. This section is what a real `dsh` process did.
`e2e/verify.sh` is the command, both arms of every scenario are run, and every assertion is
read out of the session log rather than out of the model's prose. The suite reported 29 pass,
0 fail, 2 weak, and 1 gap.

### Confirmed at runtime

| Claim | Result |
| --- | --- |
| `ctx.tools.guard()` denies over the label and no later listener undoes it | Confirmed. `bash` was denied under both built-in rules, and never succeeded in either treatment arm. |
| A denial names the rule, the label, and the origin event | Confirmed. The denial text the README quotes is copied from this run. |
| A denial is monotonic within a session | Confirmed. The same call retried 800 sequence numbers later met the identical denial. |
| `Agent.id` is the session id | Confirmed indirectly. A mismatch would have missed the ledger lookup and the gate would have abstained silently, which it did not. |
| `read`, `glob`, and `grep` are not gated at any label | Confirmed. No airlock denial appeared in that scenario at all. |
| A `secret` result is withheld at `tools/post-execute` | Confirmed. A `read` of `.env` returned an error result naming the glob. |
| An untrusted result is framed in a data envelope | Confirmed. The `airlock:untrusted-data` markers appeared around an MCP result. |

### Mount requirements the documentation did not state

An absolute filesystem path is accepted as a loader entry `name`. No `npm link` and no packed
tarball are needed. Two further facts were not documented and each one is fatal.

**`inject: [tools]` is mandatory.** Without it the plugin tree fails to load and the harness
does not boot:

```
Error: dsh: plugin tree failed to load: failed to apply loader entry dsh-airlock
(…/dist/index.js): cannot get property "tools" without inject
```

This contradicts a rule in this project's own AGENTS.md: a failure in this plugin must degrade
the plugin, never the agent loop. `toolRuntime()` in `src/dsh.ts` reads `ctx.tools`
defensively and is written to warn and return when no tool runtime is mounted. Cordis throws
on an undeclared service property access, so the defensive read never runs. In a real
composition that degradation path is dead code, and the observed behaviour is a crash at boot
rather than a degraded plugin. The README states this discrepancy where it documents the
mount.

**A loader entry `name` cannot be a `!!js` expression.** The name is resolved before `!!js`
expressions are evaluated, so `name: !!js process.env.X` fails with
`TypeError: name.startsWith is not a function`. A `config:` value may be a `!!js` expression;
the end-to-end fixture MCP overlay uses one.

### The gap the run reproduced

`SessionLedger` raises the sensitivity axis from a call's **path argument**. `bash` takes a
`command` string and names no path, so `bash cat .env` enters context labelled
`workspace, public` and egress stays open. Substituting the shell for the `read` tool defeats
`secret-no-egress` entirely.

Separately, one `bash` call can be both the reader and the network client. The gate evaluates
a call against the context that exists before it runs, so a command that reads a credential
and posts it is judged against a context in which no read has happened. There is no provenance
to judge. Reproduced with the plugin mounted: a `set -a; . ./.env; set +a; curl …` one-liner
was allowed.

Labelling a shell read would require parsing the command string, which AGENTS.md forbids. This
is therefore a boundary of the design and not a defect to be patched. The README documents it
first among the limitations, with the mitigations that do work.

The sequential half of it now has an opt-in mitigation, added after this run. An operator may
declare a tool an **opaque reader**, and every result that tool produces then carries a label
floor joined into the ordinary lattice, so the shell call after a shell read meets the ordinary
`secret-no-egress` denial. The declaration is evaluated against the registered tool name before
any model output exists and reads neither an argument value nor result text, which is what
keeps it inside the project's one invariant. It is off by default, and at the default `secret`
floor it ends network access for the session on the first shell call and withholds the shell's
own output. The atomic case — one call that reads and sends — is not closed by it, and no
provenance design can close it. The behaviour with no declaration, and the `confidential` floor
recipe that keeps the shell usable, are both covered in `tests/integration.spec.ts`. Neither
has been exercised against the live harness yet.

The asymmetry is worth stating precisely. `untrusted-no-egress` does not have this weakness,
because an untrusted label is assigned from the tool **name**, which is classification data
rather than an argument. The exfiltration chain has the hole. The injection chain does not.

### Not exercised at runtime

- **`web_fetch` and `web_search`.** Neither is reachable in a stock `dsh-base` plus
  `dsh-headless` composition. `tool-web` ships `fetch: false`, `web_fetch` reports no usable
  web provider, and `web_search` needs its own API key. The untrusted path was proven through
  a fixture stdio MCP server instead, so that part of the `egress` class and the `untrusted`
  labelling of the two web tools remain unit-tested only.
- **Compaction.** No run grew long enough to compact. The claim that a `replace` inherits the
  labels of every node it shadows is the load-bearing soundness claim of this design, it is
  confirmed against the harness source and covered by unit tests, and it has not been observed
  in a live session. It is the single most valuable thing left to verify.
- **The overt injection arm.** The model refused the injected instruction on its own in both
  arms, so no egress was attempted and no gate was consulted. That arm measures the model's
  alignment and says nothing about the plugin: with the plugin uninstalled the transcript
  looked the same, which is what the control arm showed. `verify.sh` reports it as `WEAK`.
  Only the covert variant produced a real attempt, a real denial, and a real contrast.
- **The `mutate` class, the ask seam, declassification, Gate B, and the provider backstop.**
  Outside the scope of this run.
- Only one model was used. A weaker tool caller would likely make the overt arm non-weak.

### Two conditions the run had to remove first

Both would have produced a false pass, and both are recorded because anyone re-running this
will meet them.

1. **No sandbox backend.** A plain container has neither bubblewrap nor Landlock, so under the
   default `workspace-write` the bash tool refuses to run at all rather than running
   unconfined. Both arms would have been equally unable to run bash and the denial would have
   proved nothing.
2. **No approver.** The headless surface has nobody to answer an approval prompt, so an `ask`
   policy fails closed and bash is denied in both arms.

Both arms therefore run with `DSH_PERMISSION_MODE=danger-full-access`, a shipped preset. That
is also the honest setting: it removes every other restraint, which leaves the plugin as the
only thing that can stop egress.

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

- Gate B at `agent/pre-step`, redacting entering messages and able to reject a step, and
  configured by the `preStep` section. `reject: {}` is refused at load: a rejection naming
  neither axis fires for nothing, which is a control that reads as armed and is inert. That is
  the opposite of `when: {}` on a rule, which matches everything and is accepted for that
  reason. The defaults remain inert.
- The policy file, in JSON natively and in YAML through the optional `js-yaml` peer.
- The `ask` posture, at the `tools/pre-execute` seam, routed by the harness through `ctx.approval`.
- Declassification, as a bounded session-scoped store consulted by every gate, and now
  recorded as well as read. The grant is derived by correlating the durable `approval/asked`
  and `approval/decided` events the approval service appends to the session log
  (`packages/interaction/user-approval/src/index.ts` at 0.1.0-rc.6), on the same
  `session/event` listener the ledger folds. Three facts must agree before an approval is
  claimed: the call id names a call this plugin asked about in this session, the tool name
  matches, and the reason string is byte for byte the one this plugin composed. An
  uncorrelated approval grants nothing, and the cost of failing to attribute is a second
  question rather than a wrongly cleared label.
- Opaque readers, as the opt-in partial mitigation for the shell hole the end-to-end run
  reproduced. The floor is joined rather than assigned, so it can only raise a label: a result
  that already matched a secret glob keeps its glob, and one that arrived `untrusted` stays
  `untrusted`. The floor is applied in the one function both the live result gate and the
  replay path share, so a result is labelled the same whether it is judged live or rebuilt from
  the log. The tool list is empty by default.
- The evidence sinks: hash-chained JSONL, and OpenTelemetry span events.
- The provider backstop at `llm/stream`, armed only by a `provider` boundary `redact` rule.
  There is no `backstop.enabled` key, and writing one fails the load with a message naming the
  rule form, so the rule an operator reads is the rule that fires. The backstop evaluates the
  axes the rule names and blocks when any provider rule matches. A rule naming neither axis
  falls back to sensitivity `secret`. `backstop.auxiliary` decides whether
  `purpose: 'compaction'` and `purpose: 'session-title'` requests are claimed too, and it
  defaults to `false`.

## Not yet built

- **An external anchor for the evidence chain.** Truncation of the tail is undetectable
  without one. See the README limitations.
- **A live proof of compaction label inheritance.** The harness invariant is confirmed against
  the source and the plugin's half is unit-tested. No end-to-end run has compacted yet.
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
