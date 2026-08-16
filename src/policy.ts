/**
 * Capability classes, the policy shape, and the built-in rules.
 *
 * A rule is written over a label and a capability class. No rule reads an
 * argument string, because an argument string is exactly what a model can
 * reformulate. The tool names below come from the harness tool catalogue
 * (`docs/tool-catalog.md` at 0.1.0-rc.5), not from a guess.
 *
 * The policy is flat and declarative so that an operator can review it in a
 * pull request. A rule constrains four things and nothing else: the trust of
 * the step's context, its sensitivity, the capability class of the tool, and
 * the boundary the rule is enforced at. Every one of those is known before the
 * model produces any output, which is what makes the rule enforcing rather
 * than advisory.
 *
 * Everything here is load-time and evaluation-time data. Loading a policy may
 * throw; see `config.ts`. Evaluating one may not, because evaluation runs on
 * the agent loop.
 */

import { DEFAULT_EVIDENCE_PATH, expandHome } from './evidence.js'
import type { Label, Sensitivity, Trust } from './labels.js'
import { sensitivityAtLeast, trustAtLeast } from './labels.js'
// Type-only, and therefore erased: `prestep.ts` imports this module at runtime,
// and `verbatimModuleSyntax` guarantees this line emits nothing.
import type { PreStepPolicy } from './prestep.js'

/**
 * What a tool can do with the context it is given.
 *
 * - `egress` — the call can carry context out of the machine.
 * - `mutate` — the call can change the workspace or the host.
 * - `read` — the call brings information in and sends nothing out.
 */
export type Capability = 'egress' | 'mutate' | 'read'

/** Every capability class, in the order a rule expands over them. */
export const CAPABILITIES: readonly Capability[] = Object.freeze(['egress', 'mutate', 'read'])

/**
 * Every trust level, low to high.
 *
 * This mirrors the ordering in `labels.ts`, which keeps its own copy private.
 * The policy layer needs the list to validate a configured value and to name
 * the accepted values in an error. A test asserts the two orderings agree, so a
 * change to the lattice cannot drift away from this copy unnoticed.
 */
export const TRUST_LEVELS: readonly Trust[] = Object.freeze(['user', 'workspace', 'untrusted'])

/** Every sensitivity level, low to high. See {@link TRUST_LEVELS}. */
export const SENSITIVITY_LEVELS: readonly Sensitivity[] = Object.freeze([
  'public',
  'confidential',
  'secret',
])

/**
 * What a rule does to a call it matches.
 *
 * - `deny` — the call does not run, and no later listener can undo that.
 * - `ask` — a human is asked before the call runs.
 * - `redact` — the content is withheld at the boundary it would cross.
 * - `allow` — evaluation stops here and the call proceeds. An explicit escape
 *   hatch, written above a broader rule.
 */
export type Effect = 'deny' | 'ask' | 'redact' | 'allow'

/** Every effect, for validation messages. */
export const EFFECTS: readonly Effect[] = Object.freeze(['deny', 'ask', 'redact', 'allow'])

/**
 * Where a rule is enforced.
 *
 * - `tool` — the tool call itself, before it runs.
 * - `provider` — the result boundary, where content would reach the model
 *   provider.
 */
export type Boundary = 'tool' | 'provider'

/** Every boundary, for validation messages. */
export const BOUNDARIES: readonly Boundary[] = Object.freeze(['tool', 'provider'])

/** The boundary a rule is enforced at when it names none. */
export const DEFAULT_BOUNDARY: Boundary = 'tool'

/**
 * What the plugin does when a rule asks for a human.
 *
 * - `ask` — put the decision to the operator.
 * - `deny` — refuse without asking.
 */
export type Posture = 'ask' | 'deny'

/** Every posture, for validation messages. */
export const POSTURES: readonly Posture[] = Object.freeze(['ask', 'deny'])

/** Which seam enforces one boundary and effect pair. */
export interface SeamBinding {
  readonly boundary: Boundary
  readonly effect: Effect
  /** The seam that carries the effect, named for an error message. */
  readonly enforcedBy: string
}

/**
 * The seam table.
 *
 * This is the whole of the enforcement story, written once. A pair that is
 * absent from this table cannot be enforced by any seam this plugin holds, so
 * the config validator rejects it at load rather than accepting a rule that
 * would never fire. `redact` at the tool boundary is the case worth naming:
 * the harness documents that `tools/pre-execute` cannot rewrite arguments,
 * "because history, audit, UI, and execution must agree", so there is no seam
 * that can scrub a tool call.
 */
export const SEAM_BINDINGS: readonly SeamBinding[] = Object.freeze([
  Object.freeze({
    boundary: 'tool' as const,
    effect: 'deny' as const,
    enforcedBy: 'the monotonic guard, `ctx.tools.guard()`',
  }),
  Object.freeze({
    boundary: 'tool' as const,
    effect: 'ask' as const,
    enforcedBy: 'the `tools/pre-execute` approval seam',
  }),
  Object.freeze({
    boundary: 'tool' as const,
    effect: 'allow' as const,
    enforcedBy: 'rule evaluation itself, which stops at the first match',
  }),
  Object.freeze({
    boundary: 'provider' as const,
    effect: 'redact' as const,
    enforcedBy: 'the result boundary, before content reaches the provider',
  }),
  Object.freeze({
    boundary: 'provider' as const,
    effect: 'allow' as const,
    enforcedBy: 'rule evaluation itself, which stops at the first match',
  }),
])

/**
 * Look up the seam that enforces one boundary and effect pair.
 * @param boundary - the boundary the rule names.
 * @param effect - the effect the rule asks for.
 * @returns the binding, or `undefined` when no seam can enforce the pair.
 */
export function seamFor(boundary: Boundary, effect: Effect): SeamBinding | undefined {
  return SEAM_BINDINGS.find((seam) => seam.boundary === boundary && seam.effect === effect)
}

/** The tool name lists that assign tools to capability classes. */
export interface CapabilityClasses {
  /** Tools that can carry bytes off the machine. */
  readonly egress: readonly string[]
  /** Tools that can change the workspace or the host. */
  readonly mutate: readonly string[]
}

/** The MCP bridge registers every server tool under this prefix. */
const MCP_GLOB = 'mcp__*'

/**
 * The built-in capability classes.
 *
 * `bash`, `pwsh`, and `terminal_send` appear in the egress set as well as in
 * the mutating set, because a shell is a general-purpose network client. That
 * double classification is the point of the design: `curl`, `wget`, and a
 * base64 Python one-liner are all the same capability, so all three are stopped
 * by the same rule.
 *
 * `run_code` is egress because a Code Mode program executes in-process and can
 * open its own sockets. Its bridged sub-calls re-enter the full guarded
 * pipeline, so the leaf tools it invokes are gated on their own account too.
 *
 * An MCP tool is both classes, because the bridge speaks to a process this
 * plugin cannot inspect. The conservative classification is the only sound one.
 */
export const DEFAULT_CLASSES: CapabilityClasses = Object.freeze({
  egress: Object.freeze([
    'web_fetch',
    'web_search',
    'bash',
    'pwsh',
    'terminal_send',
    'terminal_open',
    'run_code',
    MCP_GLOB,
  ]),
  mutate: Object.freeze([
    'write',
    'edit',
    'str_replace_editor',
    'bash',
    'pwsh',
    'terminal_send',
    'terminal_open',
    'terminal_close',
    'terminal_signal',
    'run_code',
    MCP_GLOB,
  ]),
})

/**
 * Tools whose results arrive from outside the workspace and are therefore
 * labelled `untrusted` on arrival.
 */
export const DEFAULT_UNTRUSTED_SOURCES: readonly string[] = Object.freeze([
  'web_fetch',
  'web_search',
  MCP_GLOB,
])

/**
 * Tools whose reads cannot be inspected, and the floor their results carry.
 *
 * The ledger derives a `secret` label from the path a call names. A shell takes
 * a command, not a path, so a shell read of a secret file raises nothing and the
 * next shell call is judged on a `public` context. An opaque reader is the
 * operator's declaration that a named tool reads through a surface this plugin
 * cannot see, so every result it produces is treated as though it had read
 * something at this floor.
 *
 * Declaring a tool opaque is classification data about a tool, in the same sense
 * as the capability classes and the untrusted source list. It is evaluated
 * against the registered tool name, before the model produces anything, and it
 * reads neither an argument value nor result text. That is why this is in scope
 * where a predicate over a `command` string is not; see AGENTS.md.
 */
export interface OpaqueReaders {
  /** Tool name patterns, in the {@link matchesToolName} vocabulary. */
  readonly tools: readonly string[]
  /** The sensitivity floor a matching tool's results carry. */
  readonly sensitivity: Sensitivity
  /** The trust floor, when the operator set one. Absent leaves trust alone. */
  readonly trust?: Trust
}

/**
 * The opaque reader settings in force when nothing is configured.
 *
 * The tool list is empty, so the feature does nothing until an operator names a
 * tool. That default is deliberate and the cost is why: a shell declared opaque
 * at `secret` raises the whole context to `secret` on its first call, which ends
 * network access for the rest of the session and, under the built-in result
 * rule, withholds the shell's own output as well. An operator must choose that.
 */
export const DEFAULT_OPAQUE_READERS: OpaqueReaders = Object.freeze({
  tools: Object.freeze([]) as readonly string[],
  sensitivity: 'secret' as const,
})

/** Paths whose contents are labelled `secret` when a tool reads them. */
export const DEFAULT_SECRET_PATHS: readonly string[] = Object.freeze([
  '**/.env',
  '**/.env.*',
  '**/credentials',
  '**/.aws/**',
  '**/.ssh/**',
  '**/*.pem',
  '**/*.key',
  '**/.netrc',
  '**/.npmrc',
  '**/id_rsa*',
  '**/id_ed25519*',
])

/**
 * What a rule constrains.
 *
 * These four keys are the entire vocabulary. `trust` and `sensitivity` match at
 * or above the named level, so a rule written for `untrusted` also covers
 * anything above it. An axis that is absent constrains nothing. There is no key
 * for an argument value or for output text, and adding one is out of scope for
 * this project; see AGENTS.md.
 */
export interface RuleCondition {
  /** Matches when the context trust is at or above this level. */
  readonly trust?: Trust
  /** Matches when the context sensitivity is at or above this level. */
  readonly sensitivity?: Sensitivity
  /** Matches when the tool belongs to this capability class. */
  readonly capability?: Capability
  /** Where the rule is enforced. Defaults to {@link DEFAULT_BOUNDARY}. */
  readonly boundary?: Boundary
}

/** Every key a {@link RuleCondition} admits, for validation messages. */
export const CONDITION_KEYS: readonly string[] = Object.freeze([
  'trust',
  'sensitivity',
  'capability',
  'boundary',
])

/** One rule as the operator wrote it. */
export interface RuleSpec {
  /** A stable identifier. Generated from the rule's position when absent. */
  readonly id?: string
  /** What the rule constrains. */
  readonly when: RuleCondition
  /** What the rule does when it matches. */
  readonly then: Effect
  /** Why the rule exists, in one line. Generated from `when` when absent. */
  readonly rationale?: string
}

/** Every key a {@link RuleSpec} admits, for validation messages. */
export const RULE_KEYS: readonly string[] = Object.freeze(['id', 'when', 'then', 'rationale'])

/**
 * One compiled rule, governing exactly one capability class.
 *
 * The first four fields are the shape Gate A has always consumed, and they keep
 * their meaning: a guard reads `capability`, `matches`, `id`, and `rationale`.
 * The rest describes where the rule is enforced and what it does there, so one
 * ordered list can serve every seam.
 */
export interface Rule {
  /** Stable identifier, quoted in the denial message and in evidence. */
  readonly id: string
  /** The capability class the rule governs. */
  readonly capability: Capability
  /** Whether the step's context label triggers the rule. */
  readonly matches: (label: Label) => boolean
  /** Why this rule exists, in one line, for the denial message. */
  readonly rationale: string
  /** What the rule does when it matches. */
  readonly effect: Effect
  /** Where the rule is enforced. */
  readonly boundary: Boundary
  /**
   * The rule's position in the authored list, from zero.
   *
   * One authored rule compiles to one {@link Rule} per capability class it
   * governs, and every one of them keeps the authored order. Ordering survives
   * selection, so first match still wins after a seam has taken its subset.
   */
  readonly order: number
  /** The condition the rule was compiled from, for evidence and diagnostics. */
  readonly when: RuleCondition
}

/** The resolved policy, with every default filled in. */
export interface Policy {
  /** What to do when a rule asks for a human. See {@link effectivePosture}. */
  readonly posture: Posture
  /** `true` logs what the policy would have done without doing it. */
  readonly dryRun: boolean
  /** Which tools belong to which capability class. */
  readonly classes: CapabilityClasses
  /** Globs whose contents are labelled `secret` when a tool reads them. */
  readonly secretPaths: readonly string[]
  /** Tools whose results are labelled `untrusted` on arrival. */
  readonly untrustedSources: readonly string[]
  /**
   * Tools whose reads cannot be inspected, and the floor their results carry.
   * Inert until an operator names a tool; see {@link DEFAULT_OPAQUE_READERS}.
   */
  readonly opaqueReaders: OpaqueReaders
  /** The rules, in evaluation order. */
  readonly rules: readonly Rule[]
  /** Whether a human may clear a label. */
  readonly declassify: { readonly allow: boolean }
  /** Where decisions are recorded. */
  readonly evidence: EvidencePolicy
  /**
   * How Gate B, the entering-message gate at `agent/pre-step`, is configured.
   * Every field is inert by default, so an operator who configures nothing gets
   * a pass-through.
   */
  readonly preStep: PreStepPolicy
  /**
   * The provider backstop settings an operator sets directly. What arms the
   * backstop is the presence of a `provider` boundary `redact` rule, not a
   * switch here; this section only carries what a rule cannot say.
   */
  readonly backstop: BackstopSettings
}

/** The provider backstop settings that are not derived from a rule. */
export interface BackstopSettings {
  /**
   * `true` subjects auxiliary model calls — `compaction` and `session-title` —
   * to the backstop as well. Defaults to `false`, because blocking compaction
   * wedges the session at the label the operator wanted cleared.
   */
  readonly auxiliary: boolean
}

/** Where decisions are recorded. The field names match `EvidenceOptions`. */
export interface EvidencePolicy {
  /** `false` disables the OpenTelemetry span event sink. */
  readonly otlp: boolean
  /** `false` disables the hash-chained JSONL sink. */
  readonly jsonl: boolean
  /** Where the JSONL sink writes, with a leading `~/` already expanded. */
  readonly path: string
}

/**
 * Match a path against one glob.
 *
 * Supports `**` across separators, `*` within one segment, and `?`. This is
 * deliberately small: the pattern set is operator-authored configuration, not
 * model-controlled input, so it needs no defence against a crafted pattern.
 *
 * @param pattern - the glob.
 * @param path - the path to test, with `\` normalised to `/`.
 * @returns `true` when the glob matches the whole path.
 */
export function matchesGlob(pattern: string, path: string): boolean {
  const expanded = pattern.startsWith('~/') ? `**/${pattern.slice(2)}` : pattern
  let regex = '^'
  for (let index = 0; index < expanded.length; index += 1) {
    const char = expanded[index]
    if (char === '*') {
      if (expanded[index + 1] === '*') {
        // `**/` also matches zero segments, so `**/.env` matches a bare `.env`.
        if (expanded[index + 2] === '/') {
          regex += '(?:.*/)?'
          index += 2
        } else {
          regex += '.*'
          index += 1
        }
      } else {
        regex += '[^/]*'
      }
      continue
    }
    if (char === '?') {
      regex += '[^/]'
      continue
    }
    regex += char!.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  regex += '$'
  return new RegExp(regex).test(path)
}

/**
 * Test a tool name against a list of name patterns.
 *
 * A pattern is a plain tool name or a name with a trailing `*`, which is how
 * `mcp__*` covers every bridged server tool. The same matcher serves paths and
 * tool names, because a tool name has no separator and a trailing `*` therefore
 * behaves the same in both.
 *
 * @param patterns - the operator-authored name patterns.
 * @param name - the registered tool name, as the model calls it.
 * @returns `true` when any pattern matches the whole name.
 */
export function matchesToolName(patterns: readonly string[], name: string): boolean {
  return patterns.some((pattern) => matchesGlob(pattern, name))
}

/**
 * Classify a tool name.
 *
 * A tool carries every class that applies to it. A tool that matches no class
 * is `read`, which is the class no rule in the built-in policy restricts.
 *
 * @param name - the registered tool name, as the model calls it.
 * @param classes - the class lists to use. Defaults to {@link DEFAULT_CLASSES}.
 * @returns every capability class the tool belongs to.
 */
export function classify(
  name: string,
  classes: CapabilityClasses = DEFAULT_CLASSES,
): ReadonlySet<Capability> {
  const found = new Set<Capability>()
  if (matchesToolName(classes.egress, name)) found.add('egress')
  if (matchesToolName(classes.mutate, name)) found.add('mutate')
  if (found.size === 0) found.add('read')
  return found
}

/**
 * Test whether a tool's results are untrusted by origin.
 * @param name - the registered tool name.
 * @param sources - the name patterns to use. Defaults to
 *   {@link DEFAULT_UNTRUSTED_SOURCES}.
 * @returns `true` when the tool reads from outside the workspace.
 */
export function isUntrustedSource(
  name: string,
  sources: readonly string[] = DEFAULT_UNTRUSTED_SOURCES,
): boolean {
  return matchesToolName(sources, name)
}

/**
 * Test a path against every configured secret glob.
 * @param path - the path a tool call named.
 * @param patterns - the globs to test.
 * @returns the glob that matched, or `undefined`.
 */
export function matchSecretPath(
  path: string,
  patterns: readonly string[],
): string | undefined {
  const normalised = path.replace(/\\/g, '/')
  return patterns.find((pattern) => matchesGlob(pattern, normalised))
}

/** How each effect reads in a generated rationale. */
const EFFECT_VERB: Readonly<Record<Effect, string>> = Object.freeze({
  deny: 'denies',
  ask: 'asks before',
  redact: 'redacts',
  allow: 'allows',
})

/**
 * Build the predicate a condition's label axes describe.
 *
 * The capability axis is not part of the predicate. Gate A tests the capability
 * separately, against the classes it derived from the tool name, so the
 * predicate stays a pure function of the label.
 *
 * @param when - the condition.
 * @returns a predicate over the context label.
 */
function labelMatcher(when: RuleCondition): (label: Label) => boolean {
  const { trust, sensitivity } = when
  return (label: Label): boolean =>
    (trust === undefined || trustAtLeast(label, trust))
    && (sensitivity === undefined || sensitivityAtLeast(label, sensitivity))
}

/**
 * Write one line explaining what a compiled rule does and why.
 * @param when - the authored condition.
 * @param effect - what the rule does.
 * @param capability - the class this compiled rule governs.
 * @returns the rationale, phrased for the denial message.
 */
function describeRule(when: RuleCondition, effect: Effect, capability: Capability): string {
  const clauses: string[] = []
  if (when.trust !== undefined) {
    clauses.push(`the context trust is at or above ${when.trust}`)
  }
  if (when.sensitivity !== undefined) {
    clauses.push(`the context sensitivity is at or above ${when.sensitivity}`)
  }
  clauses.push(`the tool is ${capability}`)
  return `configured policy ${EFFECT_VERB[effect]} this call because ${clauses.join(' and ')}`
}

/**
 * Compile one authored rule.
 *
 * A rule that names no capability governs every class, so it compiles to one
 * {@link Rule} per class. Every compiled rule keeps the authored id, because
 * the id names the rule the operator reviewed rather than an artefact of this
 * expansion.
 *
 * @param spec - the authored rule.
 * @param order - its position in the authored list, from zero.
 * @returns one compiled rule per capability class the spec governs.
 */
export function compileRule(spec: RuleSpec, order: number): readonly Rule[] {
  const when = spec.when
  const boundary = when.boundary ?? DEFAULT_BOUNDARY
  const id = spec.id ?? `rule-${order + 1}`
  const matches = labelMatcher(when)
  const capabilities = when.capability === undefined ? CAPABILITIES : [when.capability]

  return capabilities.map((capability) => Object.freeze({
    id,
    capability,
    matches,
    rationale: spec.rationale ?? describeRule(when, spec.then, capability),
    effect: spec.then,
    boundary,
    order,
    when,
  }))
}

/**
 * Compile an authored rule list.
 * @param specs - the rules, in the order the operator wrote them.
 * @returns the compiled rules, in evaluation order.
 */
export function compileRules(specs: readonly RuleSpec[]): readonly Rule[] {
  return Object.freeze(specs.flatMap((spec, order) => compileRule(spec, order)))
}

/**
 * The two rules the first milestone ships.
 *
 * They are the two halves of the demo: untrusted content cannot reach a tool
 * that talks to the network, and secret content cannot leave through one.
 * Nothing here restricts reading or searching, which is most of what an agent
 * does — see the over-blocking discussion in the README.
 */
export const DEFAULT_RULE_SPECS: readonly RuleSpec[] = Object.freeze([
  Object.freeze({
    id: 'untrusted-no-egress',
    when: Object.freeze({ trust: 'untrusted' as const, capability: 'egress' as const }),
    then: 'deny' as const,
    rationale: 'untrusted content in context cannot direct a tool that reaches the network',
  }),
  Object.freeze({
    id: 'secret-no-egress',
    when: Object.freeze({ sensitivity: 'secret' as const, capability: 'egress' as const }),
    then: 'deny' as const,
    rationale: 'secret content in context cannot leave through a tool that reaches the network',
  }),
])

/** The compiled built-in rules. Gate A consumes this list directly. */
export const DEFAULT_RULES: readonly Rule[] = compileRules(DEFAULT_RULE_SPECS)

/** The policy in force when nothing is configured. */
export const DEFAULT_POLICY: Policy = Object.freeze({
  posture: 'ask' as const,
  dryRun: false,
  classes: DEFAULT_CLASSES,
  secretPaths: DEFAULT_SECRET_PATHS,
  untrustedSources: DEFAULT_UNTRUSTED_SOURCES,
  opaqueReaders: DEFAULT_OPAQUE_READERS,
  rules: DEFAULT_RULES,
  declassify: Object.freeze({ allow: true }),
  evidence: Object.freeze({ otlp: true, jsonl: true, path: expandHome(DEFAULT_EVIDENCE_PATH) }),
  preStep: Object.freeze({}),
  backstop: Object.freeze({ auxiliary: false }),
})

/**
 * Resolve the posture that is actually in force.
 *
 * A non-interactive run always resolves to `deny`. Nobody is present to
 * consent, so an `ask` there is an allow with a longer name.
 *
 * @param posture - the configured posture.
 * @param interactive - whether a human can answer a prompt in this run.
 * @returns the posture to enforce.
 */
export function effectivePosture(posture: Posture, interactive: boolean): Posture {
  if (!interactive) return 'deny'
  return posture
}

/** Which rules a caller wants. An absent field constrains nothing. */
export interface RuleSelector {
  /** Keep only rules enforced at this boundary. */
  readonly boundary?: Boundary
  /** Keep only rules with this effect, or with any of these effects. */
  readonly effect?: Effect | readonly Effect[]
}

/** The selector for Gate A, the monotonic guard. A guard may only deny. */
export const GUARD_SEAM: RuleSelector = Object.freeze({
  boundary: 'tool' as const,
  effect: 'deny' as const,
})

/** The selector for the `tools/pre-execute` approval seam. */
export const APPROVAL_SEAM: RuleSelector = Object.freeze({
  boundary: 'tool' as const,
  effect: 'ask' as const,
})

/** The selector for the result boundary, where content reaches the provider. */
export const PROVIDER_SEAM: RuleSelector = Object.freeze({
  boundary: 'provider' as const,
  effect: 'redact' as const,
})

/** A policy, or a bare rule list. Both are accepted wherever rules are read. */
export type RuleSource = Policy | readonly Rule[]

/**
 * Read the rule list out of either accepted source.
 * @param source - a resolved policy or a bare rule list.
 * @returns the rules, in evaluation order.
 */
function rulesOf(source: RuleSource): readonly Rule[] {
  return Array.isArray(source) ? (source as readonly Rule[]) : (source as Policy).rules
}

/**
 * Select the rules one seam enforces.
 *
 * Each seam takes its own subset of one ordered list, so the operator reads a
 * single list top to bottom and the seams agree about what it means.
 *
 * An `allow` above a selected rule is honoured rather than dropped. Selecting
 * only `deny` would otherwise hand a guard a rule the operator had already
 * excepted, and the guard would deny a call the policy permits. So a selected
 * rule that sits below an `allow` on the same boundary and capability gets a
 * predicate that yields to that escape hatch first. The selected rules can then
 * be evaluated first-match-wins on their own, which is what Gate A does.
 *
 * @param source - a resolved policy or a bare rule list.
 * @param selector - the boundary and effect the caller enforces.
 * @returns the matching rules, in authored order.
 */
export function selectRules(source: RuleSource, selector: RuleSelector = {}): readonly Rule[] {
  const wanted = selector.effect === undefined
    ? undefined
    : typeof selector.effect === 'string' ? [selector.effect] : [...selector.effect]

  const escapes = new Map<string, Array<(label: Label) => boolean>>()
  const selected: Rule[] = []

  for (const rule of rulesOf(source)) {
    if (selector.boundary !== undefined && rule.boundary !== selector.boundary) continue
    const key = `${rule.boundary} ${rule.capability}`

    if (rule.effect === 'allow' && (wanted === undefined || !wanted.includes('allow'))) {
      const above = escapes.get(key) ?? []
      above.push(rule.matches)
      escapes.set(key, above)
      continue
    }

    if (wanted !== undefined && !wanted.includes(rule.effect)) continue

    const above = escapes.get(key)
    if (above === undefined || above.length === 0) {
      selected.push(rule)
      continue
    }

    const shadowed = [...above]
    const matches = rule.matches
    selected.push(Object.freeze({
      ...rule,
      matches: (label: Label) => !shadowed.some((escape) => escape(label)) && matches(label),
    }))
  }

  return Object.freeze(selected)
}
