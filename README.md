# dsh-airlock

Provenance-gated tool use for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh).

> **Status: first milestone.**
> The plugin labels context by origin and denies network-reaching tools over those labels.
> It is verified against dsh `0.1.0-rc.5`, which warns of compatibility-breaking changes.
> Expect breaking changes before version 0.1.0.

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
A gate then enforces rules over labels rather than over strings.

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

## The gate

The capability gate registers through `ctx.tools.guard()`.

That seam runs after the whole reorderable `tools/pre-execute` waterfall, and it is monotonic:
a guard may deny or abstain, and can never force-allow.
No later listener and no plugin ordering can turn its denial back into permission.
`dsh-guardian`, `dsh-tool-policy`, and `dsh-acp-plugin` all register on the reorderable seam instead.

### Capability classes

Rules are written over classes, never over tool names in a policy string.

| Class | Tools |
| --- | --- |
| `egress` | `web_fetch`, `web_search`, `bash`, `pwsh`, `terminal_open`, `terminal_send`, `run_code`, `mcp__*` |
| `mutate` | `write`, `edit`, `str_replace_editor`, `bash`, `pwsh`, `terminal_*`, `run_code`, `mcp__*` |
| `read` | everything else — `read`, `glob`, `grep`, `lsp`, and the rest |

A shell appears under `egress` because a shell is a general-purpose network client.
That is the whole point: `curl`, `wget`, and a Python one-liner are one capability, so one rule stops all three.

`run_code` is `egress` because a Code Mode program runs in-process and can open its own sockets.
Its bridged sub-calls re-enter the full guarded pipeline, so the leaf tools it invokes are gated separately as well.

An MCP tool is both classes, because the bridge speaks to a process this plugin cannot inspect.

### Rules

The first milestone ships two rules. Both deny.

| Rule | Condition | Effect |
| --- | --- | --- |
| `untrusted-no-egress` | context trust is `untrusted` and the tool is `egress` | deny |
| `secret-no-egress` | context sensitivity is `secret` and the tool is `egress` | deny |

Reading and searching stay open at every label, which is most of what an agent does.
Writing stays open too, for now — see the limitations below.

A denial names the rule, the label, and the event that caused it:

```
airlock denied `bash` by rule untrusted-no-egress: untrusted content in context
cannot direct a tool that reaches the network. This step's context is
trust=untrusted sensitivity=secret, from seq 5 (`web_fetch` result). The
restriction follows the data in context, not the wording of the call, so
another tool or another encoding reaches the same denial.
```

## Install

```sh
dsh plugin --profile <name> add dsh-airlock
```

Then mount the plugin in `$DSH_HOME/profiles/<name>/cordis.patch.yml`:

```yaml
- insert:
    - id: dsh-airlock
      name: dsh-airlock
```

Confirm the mount with `dsh --profile <name> --dump-config`.

The plugin needs `@deepseek-ai/cordis` as a peer and has no runtime dependencies of its own.

## Configuration

The first milestone has two options, and the defaults need no configuration file.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `secretPaths` | string[] | see below | Globs whose contents are labelled `secret` when a tool reads them. |
| `dryRun` | boolean | `false` | Logs what the gate would have denied without denying it. |

Default `secretPaths`:

```
**/.env          **/.env.*        **/credentials   **/.aws/**
**/.ssh/**       **/*.pem         **/*.key         **/.netrc
**/.npmrc        **/id_rsa*       **/id_ed25519*
```

Run with `dryRun: true` against a real workload first.
Read the logs before you enforce.
Over-blocking is how a taint system dies, and a measurement beats an intuition.

## Limitations, stated plainly

**Labels are coarse.**
This tracks provenance at message granularity, not through the model's reasoning.
Once untrusted text is in context, a paraphrase of it inherits the step's label rather than a precise one.
That is a deliberate trade: coarse and sound beats precise and unsound.

**Mutation is not gated yet.**
The proposal calls for `untrusted` context to make a mutating call *ask*.
A monotonic guard can only deny, and asking belongs to `ctx.approval` at the `tools/pre-execute` seam.
That rule arrives with the policy file rather than being faked here.

**Secrets are labelled by path, not by content.**
A credential pasted into an ordinary file is not labelled.
Content-based detection is regex matching, which is the game this project exists to stop playing.

**Arguments are never rewritten.**
The harness documents that `tools/pre-execute` cannot rewrite arguments,
"because history, audit, UI, and execution must agree."
Allow, deny, and ask are the only moves, so no design here scrubs an argument.

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

## License

MIT
