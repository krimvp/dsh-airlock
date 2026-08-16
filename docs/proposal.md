# dsh-airlock — gap analysis and design proposal

**Status:** proposal, not committed work.
**Date of measurement:** 16 August 2026.
**Subject:** the DeepSeek Harness (dsh) plugin ecosystem.
**Related artifact:** https://claude.ai/code/artifact/dbe93f84-5a2d-436f-b498-d54a27dba7f8

This document is a strategy proposal for a *separate* project. It lives in this repository
for convenience only. It does not describe `dsh-otel` behaviour, and it does not follow the
`AGENTS.md` documentation rules that govern the `dsh-otel` design documents.

---

## 1. Where the ecosystem is empty

### 1.1 Method

The [dshworks registry](https://github.com/dshworks/awesome-dsh-plugins) publishes the plugin
catalogue as open data at `data/plugins.json`. The analysis below:

1. pulled all 2,757 entries (registry `updated: 2026-08-16`),
2. keyword-mapped every name, description, and tag,
3. read the source and README of the closest existing plugins,
4. read the harness architecture and subsystem documentation.

The numbers are from that dataset. They are not impressions.

### 1.2 The ecosystem is wide and shallow

The harness shipped on 13 August 2026. The ecosystem is four days old.

| Measure | Value |
| --- | --- |
| Plugins in the registry | 2,757 |
| Median stars | 2 |
| Plugins with 2 stars or fewer | 1,776 (64%) |
| Plugins with 50 stars or more | 64 |
| Official plugins | 5 |

Effort has gone where effort is cheap. Tag counts: `capabilities` 719, `ui` 490,
`memory` 400, `agents` 351, `models` 261, `usage` 225, `safety` 130,
`observability` 117.

Everything a solo developer can build in an evening already exists several times over.
The work that requires talking to an auditor does not exist at all.

### 1.3 Terms with zero matches across all 2,757 descriptions

```
syslog            splunk           datadog          OCSF
OIDC              SAML             SCIM             LDAP
rego / OPA        Cedar            GDPR             erasure
retention policy  legal hold       data residency   SBOM
sigstore          cosign           attestation      chargeback
showback          seccomp          SOC 2            HIPAA
taint
```

A zero means no plugin *describes itself* that way. It is evidence of absent intent, not
proof of absent code. Across 2,757 descriptions, twenty-four consecutive zeros is a market
signal.

### 1.4 Two numbers that decided the direction

- **225 plugins are tagged `usage`.** Balance readouts, cost meters, token HUDs, spend
  dashboards. **Exactly one** mentions enforcing a limit (`dsh-agent-budget`, 2 stars).
  The ecosystem built the speedometer 225 times and the brake once.
- **130 plugins are tagged `safety`.** Three have ten stars or more, and the largest of
  those (`dsh-auto-mode`, 54 stars) is an *auto-approval* plugin — a tool for granting
  permission faster, not for withholding it.

### 1.5 The six real gaps, ranked

| Gap | What exists today | State |
| --- | --- | --- |
| **G1 — Provenance-gated tool use.** Decide by where data came from, not what it says. | Nothing. Every guard in the registry matches patterns on arguments or output. | Empty |
| **G2 — Egress control on the model call.** Stop secrets crossing to the provider. | `dsh-egress-guard` (0★), `dsh-promptwall` (3★). Both regex. Both document that encoded or fragmented secrets evade them. | Thin |
| **G3 — Audit export to a SIEM.** Splunk, Sentinel, Elastic, OCSF, CEF. | Local JSONL receipts exist (`qiushi-dsh-evidence-audit`, 4★). Nothing ships anywhere. | Empty |
| **G4 — Retention and erasure.** Session logs hold everything the model saw, forever. | Nothing. No TTL, no redaction-in-place, no per-subject deletion. | Empty |
| **G5 — Identity and tenancy.** Who ran this, under whose authority. | `dsh-multi-tenant` (3★). Password gates exist. No SSO, no roles. | Thin |
| **G6 — Plugin supply chain.** 2,757 npm packages running in-process. | Three vetting plugins at 1–6★ (`dsh-plugin-healthcheck`, `dsh-plugin-audit`, `dsh-plugin-vetting`). No signing, no manifest, no attestation. | Thin |

### 1.6 Why the existing guards do not close G1

This is the finding that decided the design. A community policy plugin was posted to the
harness discussions. A commenter demonstrated the flaw and the author accepted it:

> Argument matching is advisory, not enforcement. When one command gets denied, the agent
> simply tries alternative approaches to achieve the same outcome. Only restricting the
> underlying capability provides true enforcement.
>
> — [deepseek-ai/deepseek-harness Discussion #174](https://github.com/deepseek-ai/deepseek-harness/discussions/174)

The resolution was to document the limit rather than fix it. The maintainers warned that
richer matching "invites false confidence in enforcement strength that the mechanism cannot
deliver."

That is the whole problem in one paragraph. A model told "no" to `curl` tries `wget`, then
Python's `urllib`, then a base64-encoded one-liner. Blocking strings is a game the defender
loses, and every guard in this ecosystem is playing it.

Upstream's position on the other half is equally clear:
*"Third-party plugins are not security-audited — review the source before installing."*
The 2,757-package supply chain is explicitly the user's problem.

---

## 2. The idea: label the data, gate the capability

`dsh-airlock` stops asking what a tool call *says* and starts asking where its inputs
*came from*. Every piece of content entering the agent's context gets a label. Labels
propagate. Two gates enforce rules over labels rather than strings.

Reformulation stops working, because the constraint is no longer about phrasing. If this
session has read an untrusted web page, then network-egress tools are restricted for the
rest of it — as `curl`, as `wget`, as a Python one-liner, identically. The agent cannot
talk its way out of a fact about its own history.

### 2.1 One mechanism, three payoffs

1. **Secrets stop leaving.** Content read from `.env`, a keychain, or a credentials file
   carries a `secret` label. Policy forbids that label crossing to a third-party provider,
   whatever encoding it is wearing.
2. **Injected instructions stop acting.** A poisoned README or issue body is labelled
   `untrusted` on arrival. Untrusted context cannot authorise a privileged tool, so the
   standard indirect-injection kill chain breaks at the capability gate.
3. **Compliance falls out for free.** Every decision is already a structured record of what
   data class went where and why. That is the audit trail G3 needs, produced as a
   by-product rather than bolted on.

### 2.2 Why this is buildable on dsh and nowhere else

Information-flow control for agents is a known idea — Google DeepMind's CaMeL paper, the
2025–26 IFC literature, network-level products like Pipelock. It keeps failing to ship
inside real agents for one reason: **nobody knows what the model saw.** Context gets
assembled, summarised, and re-summarised until origin is lost, and a taint tracker with no
lineage is a random-number generator.

The harness solves that problem for its own reasons, and the solution is exactly the
substrate this needs. Three primitives, all documented, all core:

| Primitive | What core guarantees | Why airlock needs it |
| --- | --- | --- |
| `sourceEventSeqs` | Every message-producing event records which earlier events produced it. Compaction's `replace` op **must** list every node it shadows. | A real lineage graph, in core, that survives summarisation. Taint cannot be laundered by compaction. |
| Model-visible means logged | A runtime invariant asserts anything reaching a model request is reconstructable from the append-only log. | The label index is a pure projection of the log — rebuildable, crash-safe, unable to drift from reality. |
| `ctx.tools.guard()` | Monotonic guards run after the reorderable waterfall. They can only reduce permission. No later listener can force-allow. | A deny that a careless plugin ordering cannot undo. Every existing guard uses the overridable seam instead. |

That third row is the sharpest technical distinction available. `dsh-guardian`,
`dsh-tool-policy`, and `dsh-acp-plugin` all register on `tools/pre-execute`, which is
explicitly documented as reorderable. Airlock's denial is structural.

### 2.3 The adoption ladder

The project only matters if individuals install it for selfish reasons long before any
compliance officer hears the name.

- **Day one, solo developer.** Zero config. The agent reads a GitHub issue, then tries to
  POST your AWS credentials to a pastebin, and the terminal says why it stopped. That
  story travels.
- **Team.** A policy file in the repository, reviewable in a pull request like any other
  code. Shared rules without a server.
- **Enterprise.** Signed central policy, OCSF export to the SIEM, retention and erasure.
  This is the paid-support surface, and it is where G3, G4, and G5 get absorbed.

### 2.4 The honest failure mode: over-blocking

Taint systems die of over-blocking. Fetch one web page, mark the whole session untrusted,
block every subsequent command, and the user uninstalls within an hour. Four mitigations,
all in the design from the start:

- **Step scope, not session scope.** Labels are computed over the context actually derived
  for *this* step, via `sourceEventSeqs`. Not a sticky per-session flag.
- **Capability classes, not blanket denial.** Untrusted context restricts egress and
  mutation. Reading and searching stay open, which is most of what the agent does.
- **Declassification is a first-class action.** The user can approve, which clears the
  label and writes who did it and when. Friction becomes evidence instead of a dead end.
- **Posture follows the operator.** Interactive sessions *ask*. Headless and scheduled runs
  *deny* — nobody is there to consent.

---

## 3. Technical design

Four components: a ledger that assigns and propagates labels, two gates that enforce, and a
sink that emits evidence.

### 3.1 The label lattice

Two independent axes. Trust answers "could an attacker have written this". Sensitivity
answers "what happens if this escapes". Joins take the upper bound on both.

```
trust:        user  <  workspace  <  untrusted
sensitivity:  public  <  confidential  <  secret
```

```js
// label(e) = intrinsic(e) ⊔ ⨆ label(s) for s in e.sourceEventSeqs
function label(event, index) {
  const inherited = (event.sourceEventSeqs ?? [])
    .map((seq) => index.get(seq))
    .reduce(join, BOTTOM)
  return join(inherited, intrinsic(event))
}

// intrinsic labels come from the event's own origin
//   user/message typed in the composer       -> user,      public
//   tool/result from web_fetch or an MCP     -> untrusted, public
//   tool/result reading .env or credentials  -> workspace, secret
//   agent.inject() context (AGENTS.md, cron) -> workspace, public
```

The index is a projection over `session/event`, keyed by `(sessionId, seq)`, held in memory
and mirrored to append-only JSONL. Because the log is the single source of truth, the ledger
is rebuilt by replay on restart. No divergent state, no migration.

One subtlety worth naming: `agent.inject()` content arrives as a `user/message` event. A
cron notice, a subdirectory `AGENTS.md`, and the human's own typing are the same role on the
wire. The event type distinguishes them, so the ledger can — and the model, unaided, cannot.
That is precisely the gap injections live in.

### 3.2 Where each gate attaches

Mapped onto the documented turn flow:

| Hook | Role |
| --- | --- |
| `turn/start` | Turn opens. |
| **`agent/pre-step`** | **Gate B — egress.** Rewrite or reject what the model is about to see. Messages carrying `secret` are redacted or held before the provider request is built. This waterfall may rewrite claimed messages, so the log and the provider stay in agreement. |
| `step/start` → `agent/request` → `llm/stream` | Prompt assembled from the log, request dispatched. |
| `tools/pre-execute` | Reorderable allow / deny / ask. Airlock *observes* here and asks when policy says ask — but does not rely on it. |
| **`ctx.tools.guard()`** | **Gate A — capability.** The binding denial. Monotonic and final: if the step's context carries `untrusted` and the tool's capability class is egress or mutate, the call dies here. No later listener can revive it. |
| `tools/execute` | Tool body runs, wrapped by around-dispatch listeners. |
| `tools/post-execute` | Result labelled and, for untrusted sources, wrapped in a data envelope with control characters, bidi overrides, and zero-width runs normalised. |
| `tool/result` → `step/end` → `turn/end` | Durable events. The ledger folds them into the index. |

### 3.3 Why not rewrite at `llm/stream`

`dsh-egress-guard` intercepts at `llm/stream`, the last point before the adapter. It is the
obvious place and it is the wrong one. Rewriting there makes the provider receive something
the session log does not record, which breaks the harness's own "model-visible means logged"
invariant and silently corrupts replay, fork, and every downstream telemetry consumer.

`agent/pre-step` is upstream of the log projection, so a redaction there is a fact the log
knows about. Airlock keeps `llm/stream` as a fail-closed backstop that **blocks** — never
edits.

One further constraint from the tool pipeline documentation: `tools/pre-execute` **cannot
rewrite arguments**, "because history, audit, UI, and execution must agree." Any design that
assumed argument scrubbing at that seam is wrong. Allow, deny, and ask are the only moves.

### 3.4 Policy

Flat, declarative, reviewable in a pull request. Capability classes are assigned to tools.
Rules are written over labels and classes, never over argument strings.

```yaml
airlock:
  posture: ask          # interactive; headless forces deny
  classes:
    egress: [web_fetch, web_search, mcp_*]
    mutate: [fs_write, fs_edit, shell, terminal]
  secretPaths: ["**/.env", "**/credentials", "~/.ssh/**", "**/*.pem"]
  rules:
    - # the injection kill chain
      when: { trust: untrusted, capability: egress }
      then: deny
    - when: { trust: untrusted, capability: mutate }
      then: ask
    - # the exfiltration kill chain
      when: { sensitivity: secret, boundary: provider }
      then: redact
  declassify:
    allow: true         # user approval clears a label, and is recorded
  evidence:
    otlp: true          # decisions as span events, alongside dsh-otel
    jsonl: ~/.dsh/airlock/decisions.jsonl
```

### 3.5 Evidence output

Every decision — allow, deny, ask, redact, declassify — emits one record: the labels
involved, the rule that fired, the tool, the session, the turn, and the step.

Two sinks, and this is where the existing `dsh-otel` work compounds:

1. **OpenTelemetry.** Decisions ride out as span events on the spans `dsh-otel` already
   produces, so a single trace shows what the agent did *and* what it was stopped from
   doing.
2. **Hash-chained JSONL.** A local file that a later module maps to OCSF for a SIEM.

### 3.6 How it ships

| Module | Scope |
| --- | --- |
| `dsh-airlock` (now, MIT) | Ledger, both gates, policy, local evidence. The whole individual-developer story. Zero runtime dependencies beyond the harness peers. |
| `dsh-airlock-audit` (next) | OCSF and CEF mapping, syslog and HTTPS shipping, hash-chained receipts, retention and per-session crypto-erasure. Closes G3 and G4. |
| `dsh-airlock-supply` (later) | Capability manifests for installed plugins, static profiling of what each one touches, a CI gate. Closes G6 against upstream's explicit non-goal. |

All three npm names were unregistered as of 16 August 2026, along with `dsh-boundary`,
`dsh-taint`, `dsh-provenance`, `dsh-warden`, `dsh-perimeter`, `dsh-audit`, `dsh-trustline`,
`dsh-capsule`, and `dsh-ledger`.

### 3.7 First milestone

The smallest version that produces the demo which sells the project:

- ledger over `session/event`,
- intrinsic labels for web fetches and secret paths,
- Gate A as a monotonic guard with the two default rules,
- a terminal message that names the rule and the origin event when it denies.

No policy file. No evidence sink. No configuration.

If that build cannot stop a poisoned repository file from exfiltrating a key, nothing after
it matters.

---

## 4. Risks, stated plainly

**Core absorbs it.** The harness already owns approvals, sandbox tiers, and monotonic
guards. Labelling is a natural next step for them, and they have `sourceEventSeqs` in hand.
Mitigation: build only on documented seams, keep the policy vocabulary portable, and treat
being upstreamed as a good outcome rather than a loss. The audit and supply-chain modules
are far less likely to be absorbed — they are integration work, which core projects rarely
want.

**Over-blocking drives uninstalls.** The four mitigations in §2.4 are the answer. The
default posture must be *ask*, not *deny*, for anything short of a secret crossing a
provider boundary. Ship with a dry-run mode that logs what it would have blocked, and read
those logs before tightening defaults.

**The platform is a release candidate.** The harness is at `0.1.0-rc.6` and warns of
compatibility-breaking changes. Every hook in this design is documented in
`docs/architecture.md` and the subsystem references, which is the best available hedge.
Expect churn. Pin the verified version in the README the way `dsh-otel` already does, and
keep the surface area small.

**Labels are coarse.** This tracks provenance at message granularity, not through the
model's reasoning. Once untrusted text is in context, the model may paraphrase it, and the
paraphrase inherits the step's label rather than a precise one. That is a deliberate trade:
coarse and sound beats precise and unsound. Say so in the README — the two nearest
competitors both quietly overstate what pattern matching buys, and being straight about
limits is a differentiator.

**Prior art exists elsewhere.** CaMeL, LlamaFirewall, Pipelock, and the openclaw `trust`
proposals cover this ground conceptually. None is a harness plugin. Network-level firewalls
cannot see inside the context, and the openclaw CaMeL RFC was closed as stale without
implementation. The contribution here is not the idea. It is the first sound implementation
on a runtime whose log invariant makes it tractable. Cite the prior art prominently; it is
credibility, not competition.

---

## 5. One unrelated finding worth acting on

`dsh-otel` is not in the dshworks registry, and it does not carry the `dsh-plugin` GitHub
topic that every discovery tool in this ecosystem scrapes.

Three OpenTelemetry competitors are listed, all at two to four stars, all Langfuse-shaped:
`dsh-plugin-langfuse` (4★), `dsh-langfuse` (2★), `dsh-observability-codeprom` (2★).

Adding the topic and submitting the registry entry is an afternoon's work against an open
niche.

---

## 6. Sources

1. [dshworks/awesome-dsh-plugins](https://github.com/dshworks/awesome-dsh-plugins) —
   registry data, 2,757 entries, updated 16 August 2026.
2. [deepseek-harness/docs/architecture.md](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md)
   — seams, turn flow, waterfall inventory.
3. deepseek-harness `docs/subsystems/session.md` and `docs/tool-execution-pipeline.md` —
   `sourceEventSeqs`, `SurfaceOp`, guard monotonicity, decision types, the
   "arguments cannot be rewritten" constraint.
4. [Discussion #174](https://github.com/deepseek-ai/deepseek-harness/discussions/174) — the
   advisory-versus-enforcement exchange.
5. Nearest existing work: [dsh-egress-guard](https://github.com/LKRCharon/dsh-egress-guard),
   [promptwall](https://github.com/Chhlafiu4312/promptwall),
   [dsh-guardian](https://github.com/cdxiaodong/dsh-guardian),
   [dsh-tool-policy](https://github.com/Drifter-yh/dsh-tool-policy),
   [dsh-acp-plugin](https://github.com/agentic-control-plane/dsh-acp-plugin).
6. [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/pdf/2503.18813);
   [openclaw CaMeL RFC](https://github.com/openclaw/openclaw/issues/39160) (closed,
   unimplemented); [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses).

Registry figures computed 16 August 2026. Star counts move fast in a four-day-old
ecosystem — re-measure before quoting them anywhere binding.
