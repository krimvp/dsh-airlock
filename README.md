# dsh-airlock

Provenance-gated tool use for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh).

> **Status: 0.1.0.**
> The plugin labels context by origin and enforces rules over those labels at five seams.
> It is verified against dsh `0.1.0-rc.5`, which warns of compatibility-breaking changes.
> Expect breaking changes while the harness is a release candidate.

## The problem

Every tool guard in the dsh ecosystem matches patterns on arguments or output.
That approach is advisory, and the harness maintainers say so:

> Argument matching is advisory, not enforcement. When one command gets denied, the agent
> simply tries alternative approaches to achieve the same outcome. Only restricting the
> underlying capability provides true enforcement.
>
> — [deepseek-harness Discussion #174](https://github.com/deepseek-ai/deepseek-harness/discussions/174)

A model told "no" to `curl` tries `wget`, then `urllib`, then a base64 one-liner.
Blocking strings is a game the defender loses.

## What this plugin does instead

`dsh-airlock` stops asking what a tool call says and starts asking where its inputs came from.

Every piece of content entering the agent's context gets a label.
Labels propagate through the session's own lineage records.
The gates then enforce rules over labels rather than over strings.

Reformulation stops working, because the constraint is no longer about phrasing.
Once this session has read an untrusted web page, network-reaching tools are restricted —
as `bash`, as `pwsh`, as `run_code`, as an MCP server, identically.
The agent cannot talk its way out of a fact about its own history.

## The label lattice

Two independent axes.
Trust answers "could an attacker have written this".
Sensitivity answers "what happens if this escapes".

```
trust:        user   < workspace    < untrusted
sensitivity:  public < confidential < secret
```

A label is assigned from an event's own origin, then joined with the labels of the events it cites.

| Origin | Label |
| --- | --- |
| A message typed in the composer | `user`, `public` |
| `agent.inject()` context — a subdirectory `AGENTS.md`, a skill body, a cron notice | `workspace`, `public` |
| A `web_fetch` or `web_search` result | `untrusted`, `public` |
| Any MCP tool result | `untrusted`, `public` |
| A read whose path matches a secret glob | `workspace`, `secret` |
| Any other tool result | `workspace`, `public` |

Injected context is the case worth naming.
A cron notice, a subdirectory `AGENTS.md`, and the human's own typing are all `user/message`
events on the wire, and the model cannot tell them apart.
The event's `source.kind` does tell them apart, so the ledger can.
That is precisely the gap indirect injections live in.

The `confidential` level exists in the lattice and no built-in rule or label assignment
produces it. It is there for an operator who writes a rule over it.

## Why compaction cannot launder a label

This is the part that makes the design sound rather than decorative.

Information-flow control for agents is a known idea.
It keeps failing to ship inside real agents because nobody knows what the model saw:
context gets assembled, summarised, and re-summarised until origin is lost.

dsh records lineage in core for its own reasons.
A surface event carries `sourceEventSeqs`, and a compaction `replace` operation
**must** list every surface node it shadows.
So a summary of a poisoned page inherits that page's label, by the harness's own invariant.
Summarising untrusted content does not clean it.

The ledger is a pure projection over `session/event`.
The session log is the source of truth, so replaying it rebuilds the index exactly.

## The five seams

The plugin installs five seams. Each one can do exactly one thing, and each one is limited
by what the harness lets a listener do there.

| Seam | What it does | What it cannot do |
| --- | --- | --- |
| `ctx.tools.guard()` | Gate A. Denies a tool call over the step's context label. | It cannot ask, allow, rewrite, or await anything. |
| `tools/pre-execute` | The ask. Returns `{kind:'ask'}` for a rule the operator wrote as `ask`. | It cannot rewrite arguments, and it does not call `ctx.approval` itself. |
| `tools/post-execute` | Withholds a `secret` result by blocking it. Frames an untrusted result in a data envelope. | It cannot redact part of a result, and a content replacement withholds nothing. |
| `agent/pre-step` | Gate B. Redacts messages entering a step, and can reject the step. | It sees the entering batch only, never the conversation history. |
| `llm/stream` | The provider backstop. Refuses a model request. | It never edits a request, and it is disabled unless the policy arms it. |

### Gate A — `ctx.tools.guard()`

The capability gate, and the only decision here that no other plugin can undo.

That seam runs after the whole reorderable `tools/pre-execute` waterfall, and it is monotonic:
a guard may deny or abstain, and can never force-allow.
No later listener and no plugin ordering can turn its denial back into permission.
`dsh-guardian`, `dsh-tool-policy`, and `dsh-acp-plugin` all register on the reorderable seam instead.

The guard is synchronous by contract, so it reads the in-memory ledger and awaits nothing.
A session the plugin has observed no events for makes the gate abstain, because the gate
denies on evidence and it has none.

A denial names the rule, the label, and the event that caused it:

```
airlock denied `bash` by rule untrusted-no-egress: untrusted content in context
cannot direct a tool that reaches the network. This step's context is
trust=untrusted sensitivity=secret, from seq 5 (`web_fetch` result). The
restriction follows the data in context, not the wording of the call, so
another tool or another encoding reaches the same denial.
```

### The ask — `tools/pre-execute`

A rule written as `then: ask` returns `{kind:'ask'}` here.
The plugin does not call `ctx.approval`. The harness services the ask itself, through
`ctx.approval`, after the whole waterfall has run.

The harness degrades that ask to a denial when no approval service is mounted, and when the
call carries no agent.
The plugin reads the same two facts before it decides: an absent `ctx.approval`, or an
approval service configured `policy: 'never'`, lowers the posture to `deny`, so the refusal
says the posture refused rather than leaving an ask to be degraded silently.

The approval request carries no tool arguments.
An answerer sees the tool name, the call id, and the plugin's reason string, so the reason is
self-contained: it names the rule, the label, and the origin event.

The built-in policy ships no `ask` rule, so this seam abstains for every call until an
operator writes one.

### The result boundary — `tools/post-execute`

Two cases, and they use different mechanisms on purpose.

A result labelled `secret` is withheld with `{kind:'block'}`.
It is not content-replaced. A content replacement changes what the model sees and what the
durable event records, and the canonical `value` survives it untouched — a Code Mode
`run_code` program reads that value through its SDK bindings. The harness documents this
plainly in `packages/core/tools/README.md`: content replacement is not a confidentiality
boundary. A replaced `value` would withhold the content, but a replaced value is revalidated
against the tool's declared `output.schema`, and this plugin cannot know that schema. `block`
is the mechanism that is correct for every tool, so `block` is the one used.

The block carries feedback that says the content was withheld by policy, which glob decided
it, and what would release it. A block that reads like an empty file sends the agent into a
retry loop against a decision that will never change.

A result from an untrusted source is content-replaced into a data envelope.
That is presentation policy rather than confidentiality policy: the model is supposed to see
the page it fetched, and the only change is that it now reads as quoted data. Inside the
envelope, control characters, bidi overrides, zero-width characters, and Unicode tag
characters are replaced with a visible marker naming the class and the count. The marker is
the point — the smuggled instruction stops working and starts being visible.

### Gate B — `agent/pre-step`

`agent/pre-step` is a waterfall over the messages a proposed step enters with.
That batch is the inbox content claimed for this step: fresh human input and injected
context. It is not the conversation history, so nothing at this seam reaches a secret that
arrived earlier through a `tool/result`.

The seam is upstream of the log, so a message rewritten here reaches the log in its rewritten
form. The provider and the log continue to agree, which is the invariant a rewrite at
`llm/stream` would break.

Two moves are sound here and the module makes exactly those two: redaction of an entering
message whose producer is classified at or above a sensitivity threshold, and rejection of
the whole step.

Both are driven by producer classification, and 0.1.0 exposes no configuration key for it.
The plugin mounts this seam with an empty policy, so as shipped it classifies no producer as
`secret` or `untrusted`, rewrites nothing, and never rejects a step. The mechanism is built
and tested; the configuration surface that arms it is not.

### The provider backstop — `llm/stream`

`llm/stream` is the last seam before the adapter carries a request off the machine.

This seam blocks and never edits. A loop-built request arrives deep-frozen, so mutation
throws, and a request that reached the provider in a form the session log does not record
would break the harness's own "model-visible means logged" invariant.

Blocking is done by short-circuiting: the plugin returns its own valid chunk stream without
calling `next()`, and the turn ends with an ordinary assistant message saying what happened.
Throwing from the listener would end the whole turn with an error instead, because middleware
failures are not normalised into the stream protocol.

The backstop is disabled by default. It is armed by writing a rule at the `provider`
boundary, and an armed backstop blocks any request whose session context sensitivity is at or
above `secret`. The rule's own `when` axes are not read at this seam in 0.1.0.
Auxiliary requests — `purpose: 'compaction'` and `purpose: 'session-title'` — are not
blocked. Blocking compaction would wedge the session at exactly the label an operator wanted
cleared.

Read the limitations before arming this.

## Capability classes

Rules are written over classes, never over tool names in a policy string.

| Class | Tools |
| --- | --- |
| `egress` | `web_fetch`, `web_search`, `bash`, `pwsh`, `terminal_open`, `terminal_send`, `run_code`, `mcp__*` |
| `mutate` | `write`, `edit`, `str_replace_editor`, `bash`, `pwsh`, `terminal_open`, `terminal_send`, `terminal_close`, `terminal_signal`, `run_code`, `mcp__*` |
| `read` | everything else — `read`, `glob`, `grep`, `lsp`, and the rest |

A shell appears under `egress` because a shell is a general-purpose network client.
That is the whole point: `curl`, `wget`, and a Python one-liner are one capability, so one rule stops all three.

`run_code` is `egress` because a Code Mode program runs in-process and can open its own sockets.
Its bridged sub-calls re-enter the full guarded pipeline, so the leaf tools it invokes are gated separately as well.

An MCP tool is both classes, because the bridge speaks to a process this plugin cannot inspect.

`read` is the class of every tool that matches no other class. A tool joins it by being
absent from `egress` and `mutate`, and a policy cannot list it.

## Rules

A rule constrains four things and nothing else: the trust of the step's context, its
sensitivity, the capability class of the tool, and the boundary it is enforced at.
Every one of those is known before the model produces any output, which is what makes a rule
enforcing rather than advisory.

There is no key for an argument value and no key for tool output. Adding one is out of scope
for this project; see [AGENTS.md](./AGENTS.md).

`trust` and `sensitivity` match at or above the named level.
An axis that is absent constrains nothing.
A rule that names no capability governs all three classes.
Rules are evaluated in the order they are written, and the first match wins.

Each effect is carried by one seam, and a pair with no seam behind it is refused at load
rather than accepted as a rule that would never fire.

| Boundary | Effect | Enforced by |
| --- | --- | --- |
| `tool` | `deny` | the monotonic guard, `ctx.tools.guard()` |
| `tool` | `ask` | the `tools/pre-execute` approval seam |
| `tool` | `allow` | rule evaluation itself, which stops at the first match |
| `provider` | `redact` | the result boundary, before content reaches the provider |
| `provider` | `allow` | rule evaluation itself, which stops at the first match |

`redact` at the `tool` boundary is the pair worth naming. The harness documents that
`tools/pre-execute` cannot rewrite arguments, "because history, audit, UI, and execution must
agree", so no seam can scrub a tool call and the load fails with that explanation.

The default boundary is `tool`.

### The built-in rules

The defaults ship two rules. Both deny.

| Rule | Condition | Effect |
| --- | --- | --- |
| `untrusted-no-egress` | context trust is `untrusted` and the tool is `egress` | deny |
| `secret-no-egress` | context sensitivity is `secret` and the tool is `egress` | deny |

Reading and searching stay open at every label, which is most of what an agent does.
Writing stays open too — see the limitations below.

A configured `rules` list replaces the built-in rules outright, including these two, because
a reader of the policy must see the whole evaluation order in one place.

## Install

```sh
dsh plugin --profile <name> add dsh-airlock
```

Then mount the plugin in `$DSH_HOME/profiles/<name>/cordis.patch.yml`:

```yaml
- insert:
    - id: dsh-airlock
      name: dsh-airlock
      config:
        dryRun: true
```

Every key is optional, and the defaults need no configuration at all.
Confirm the mount and the resolved configuration with `dsh --profile <name> --dump-config`.

The plugin needs `@deepseek-ai/cordis` as a peer and has no runtime dependencies of its own.
Two optional peers extend it: `js-yaml` for a YAML policy file, and `@opentelemetry/api` for
the span event sink. Both are absent-safe.

## Configuration

Three layers, merged lowest to highest:

1. the built-in defaults,
2. the workspace policy file named by `policyFile`,
3. the mount config.

A key set at a higher layer replaces the same key at a lower one.
A list replaces the list below it and is never concatenated with it, so the policy in force is
the policy an operator can read in the diff.
The three sections that hold independent switches — `classes`, `declassify`, and `evidence` —
merge one key at a time, so setting `classes.egress` leaves the built-in `mutate` list in place.

A key, a value, or a shape the plugin does not understand fails the plugin load.
That is deliberate. A typo in a security policy is a rule that would not be enforced, and a
rule that silently does not apply is worse than no rule at all.

### Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `posture` | `"ask"` \| `"deny"` | `"ask"` | What an `ask` rule does. See below. |
| `dryRun` | boolean | `false` | Logs what the policy would have done without doing it. |
| `policyFile` | string | none | A workspace policy file to read. Only the mount config may set it. |
| `classes.egress` | string[] | see above | Tool name patterns in the `egress` class. |
| `classes.mutate` | string[] | see above | Tool name patterns in the `mutate` class. |
| `secretPaths` | string[] | see below | Globs whose contents are labelled `secret` when a tool reads them. |
| `untrustedSources` | string[] | `web_fetch`, `web_search`, `mcp__*` | Tools whose results are labelled `untrusted` on arrival. |
| `rules` | rule[] | the two built-in rules | The rules, in evaluation order. |
| `declassify.allow` | boolean | `true` | Whether a human may clear a label. |
| `evidence.otlp` | boolean | `true` | The OpenTelemetry span event sink. |
| `evidence.jsonl` | boolean \| string | `true` | The hash-chained JSONL sink. A string is the file path. |

A rule is a mapping of `id`, `when`, `then`, and `rationale`.
`when` and `then` are required. `id` defaults to the rule's position, and `rationale` is
generated from the condition.
`when` accepts `trust`, `sensitivity`, `capability`, and `boundary`, and nothing else.
Two rules may not share an id, because that would make evidence ambiguous about which one fired.

A tool name pattern is a plain name or a name with a trailing `*`, which is how `mcp__*`
covers every bridged server tool. A path glob supports `**` across separators, `*` within one
segment, and `?`. A leading `~/` is expanded.

Default `secretPaths`:

```
**/.env          **/.env.*        **/credentials   **/.aws/**
**/.ssh/**       **/*.pem         **/*.key         **/.netrc
**/.npmrc        **/id_rsa*       **/id_ed25519*
```

Run with `dryRun: true` against a real workload first.
Read the logs before you enforce.
Over-blocking is how a taint system dies, and a measurement beats an intuition.

### The policy file

A team that would rather review its policy in its own repository points `policyFile` at one.
`.json` is read with no dependency at all. `.yml` and `.yaml` are read through `js-yaml`, an
optional peer. Any other extension is refused rather than guessed at.

A relative path resolves against the working directory, and a leading `~/` is expanded.
A policy file may not name another policy file: one hop only, because a chain of files is a
policy nobody can read in one sitting.
A file that is missing, unparsable, or invalid fails the load rather than being ignored.

The whole accepted shape, with every section present:

```yaml
airlock:
  posture: ask
  dryRun: false
  classes:
    egress: [web_fetch, web_search, bash, pwsh, run_code, "mcp__*"]
    mutate: [write, edit, bash, pwsh, run_code, "mcp__*"]
  secretPaths: ["**/.env", "**/credentials", "~/.ssh/**", "**/*.pem"]
  untrustedSources: [web_fetch, web_search, "mcp__*"]
  rules:
    - id: untrusted-no-egress
      when: { trust: untrusted, capability: egress }
      then: deny
      rationale: untrusted content in context cannot direct a tool that reaches the network
    - id: untrusted-ask-before-mutate
      when: { trust: untrusted, capability: mutate }
      then: ask
    - id: secret-stays-off-the-provider
      when: { sensitivity: secret, boundary: provider }
      then: redact
  declassify:
    allow: true
  evidence:
    otlp: true
    jsonl: ~/.dsh/airlock/decisions.jsonl
```

The top-level `airlock` key is optional. A document with that single key is unwrapped, and
any other document is read as the configuration itself.

### Posture

`posture` decides what an `ask` rule does. `ask` puts the question to the operator, and
`deny` refuses without asking.

It is configuration, not detection. The harness exposes no way to find out whether a human is
present, so this plugin does not claim to know. Two facts are checkable, and both lower the
posture to `deny`: no `ctx.approval` is mounted, so no ask can be routed anywhere; or the
approval service is configured `policy: 'never'`, which is the harness's own statement that
every ask resolves without reaching an answerer.

The lowering is one-way. A hint can only take the posture down to `deny`, never up to `ask`.

## Declassification

A denial that cannot be overridden is a dead end, and a dead end is what makes an operator
turn a gate off. Declassification is the other half of the ask posture: a human clears a
label for a named action, and the clearance becomes an audit record rather than a disabled
plugin.

The harness grants nothing durable. `ctx.approval` resolves `allowed-once`, and there is no
allow-always, no remembered rule, no grant store, and no revocation. A plugin that wants a
clearance to outlive one call therefore keeps its own store, which is what airlock does.

The store is bounded on both axes that can leak: a session holds at most 16 grants, and the
store remembers at most 1,024 sessions. The oldest is evicted first, and eviction can only
remove permission. A grant is scoped by capability class and optionally by a single tool
name, and it covers a later step only when that step's label sits at or below the label the
human cleared. A clearance never outlives its session: the disposal listeners drop it with
the ledger.

`declassify.allow: false` disables the store, so every lookup answers no.

0.1.0 wires the read side only. Gate A, the ask seam, and the result boundary all consult the
store before they act. No seam in this release records a grant, so no call is cleared unless
a host drives the exported `Declassifier` itself. The prompt-to-grant path is not built.

## Evidence

Every decision the plugin makes emits one record: the session, the tool, the call id, the
capability classes, the outcome, the rule that fired, the label, and one line naming the
event the label came from. The outcomes are `allow`, `deny`, `ask`, `redact`, and
`declassify`.

Two sinks carry it, and a failure in either degrades the evidence and never the agent loop.

**Hash-chained JSONL.** One line per decision, appended synchronously to
`~/.dsh/airlock/decisions.jsonl` by default. Each line carries the sha256 of the previous
line's hash together with this line's own canonical content, so an edited, deleted, or
reordered line breaks the chain at that line and at every line after it. `verifyChain()`
reports the index of the first break. Set `evidence.jsonl` to a string to move the file, or
to `false` to disable the sink.

**OpenTelemetry span events.** Each decision is added to the current active span as an
`airlock.decision` event, so it rides along the span `dsh-otel` already produces for the
step. A single trace then shows what the agent did and what it was stopped from doing. The
JSONL sink runs first, so the line's hash rides out on the span event too and a trace ties
back to the exact line on disk. `@opentelemetry/api` is loaded through a guarded dynamic
import; when the package is absent the sink is a silent no-op. Set `evidence.otlp` to `false`
to disable it.

## Limitations, stated plainly

**Labels are coarse.**
This tracks provenance at message granularity, not through the model's reasoning.
Once untrusted text is in context, a paraphrase of it inherits the step's label rather than a precise one.
That is a deliberate trade: coarse and sound beats precise and unsound.

**Secrets are labelled by path, not by content.**
A credential pasted into an ordinary file is not labelled, and neither is one a tool prints
without being asked for a path.
Content-based detection is regex matching, which is the game this project exists to stop playing.

**Content replacement is not a confidentiality boundary.**
The harness documents this in `packages/core/tools/README.md`, and it is why a secret result
is withheld with `block` rather than with replaced content.
A `{kind:'accept', content}` changes only what the model sees and what the durable event
records. The canonical `value` survives untouched, and a Code Mode `run_code` program reads
that value through its SDK bindings, so a content-redacted secret would still be one
`run_code` call away from the network.
The untrusted data envelope is a content replacement, and it withholds nothing by design: it
frames data the model was always going to see.

**Hash-chain truncation is undetectable.**
The chain detects an edited record, a deleted record, a reordered pair, and a record
re-forged against the genesis hash. All four were tested adversarially.
It does not detect truncation of the tail. An attacker who deletes the last N lines leaves a
file that verifies intact, because a hash chain has no external anchor: nothing outside the
file records how long the file should be.
Shipping the head hash somewhere the attacker does not control is what closes that gap, and
this release does not do it.

**Posture is configuration, not detection.**
The harness exposes no way to detect whether a human is present. There is no service, no
flag, and no API for it. `dsh-headless` is a bundle of plugins, not a capability signal.
Claiming auto-detection would be a lie, so the plugin does not claim it.
`posture: ask` or `posture: deny` is the operator's explicit choice, lowered to `deny` only by
the two checkable facts named above: an absent `ctx.approval`, or the harness's own
`ApprovalPolicy` of `'never'`.

**The backstop is disabled by default, and it is blunt.**
Once a secret is on the surface it stays there until compaction drops it. An always-on rule
that blocks every model call carrying a secret therefore does not block one exfiltration. It
blocks every remaining step of the session, including the ones that would have done the
user's work, and it does so with no tool call in sight.
Gate A already denies the capability that could carry the secret out. The backstop is for the
deployment that does not trust the model provider itself with the content, and that is an
explicit operator decision rather than a default.

**Arguments are never rewritten.**
The harness documents that `tools/pre-execute` cannot rewrite arguments,
"because history, audit, UI, and execution must agree."
Allow, deny, and ask are the only moves, so no design here scrubs an argument.

**Gate B is built but not configurable.**
The `agent/pre-step` seam is installed and its redaction and rejection are tested, and 0.1.0
exposes no configuration key that arms them. As mounted it rewrites nothing and rejects
nothing. The seam also sees only the messages entering a step, never the conversation
history.

**Declassification has no prompt.**
The store, its bounds, and every read path are built. No seam records a grant, so in a stock
mount no call is ever cleared.

**The gate is one layer.**
It restricts the tools the harness owns.
A tool that reaches the network through a channel this plugin does not classify is not covered.
Classification is data, and correcting it is a pull request.

## Prior art

The idea is not new, and the credit is not this project's to take.

- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/pdf/2503.18813) — Google DeepMind.
- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) — the survey.
- The [openclaw CaMeL RFC](https://github.com/openclaw/openclaw/issues/39160), closed as stale without implementation.

None of them is a harness plugin.
Network-level firewalls cannot see inside the context.
The contribution here is an implementation on a runtime whose log invariant makes lineage tractable.

## Development

```sh
npm install
npm run build
npm test
```

The test suite runs on `node:test` and needs no test framework dependency.
It is 309 tests across 52 suites at this release.

[docs/verification.md](./docs/verification.md) records what was checked against the harness
source, and where the design documents turned out to be wrong.

## License

MIT
