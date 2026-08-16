/**
 * Policy configuration: reading it, validating it, and merging it.
 *
 * The plugin is mounted with a configuration object, which the harness has
 * already parsed out of the profile's cordis patch. That is the primary path
 * and it parses nothing. A team that would rather review its policy in its own
 * repository points `policyFile` at a file; `.json` is read natively, and
 * `.yml` or `.yaml` is read through a dynamic import of `js-yaml`, an optional
 * peer dependency.
 *
 * Merge order, lowest to highest:
 *
 *   1. the built-in defaults, supplied by {@link resolvePolicy}
 *   2. the workspace policy file named by `policyFile`
 *   3. the mount config
 *
 * A key set at a higher layer replaces the same key at a lower one. A list
 * replaces the list below it and is never concatenated with it, so the policy
 * in force is the policy an operator can read in the diff.
 *
 * Every function here runs at load time, and every function here throws on a
 * configuration it does not understand. That is deliberate and it is the
 * opposite of the runtime rule: an unknown effect, an unknown `when` key, or a
 * policy file that will not parse is a rule that would not be enforced, and a
 * security rule that silently does not apply is worse than no rule at all.
 * Nothing in this module runs on the agent loop.
 */

import { readFileSync } from 'node:fs'
import { extname, resolve } from 'node:path'

import { expandHome } from './evidence.js'
import type { Sensitivity, Trust } from './labels.js'
import type {
  BackstopSettings,
  Boundary,
  Capability,
  CapabilityClasses,
  Effect,
  OpaqueReaders,
  Policy,
  Posture,
  RuleCondition,
  RuleSpec,
} from './policy.js'
import type { PreStepPolicy, PreStepRejection } from './prestep.js'
import {
  BOUNDARIES,
  CAPABILITIES,
  compileRules,
  CONDITION_KEYS,
  DEFAULT_BOUNDARY,
  DEFAULT_CLASSES,
  DEFAULT_OPAQUE_READERS,
  DEFAULT_POLICY,
  DEFAULT_RULES,
  DEFAULT_SECRET_PATHS,
  DEFAULT_UNTRUSTED_SOURCES,
  EFFECTS,
  POSTURES,
  RULE_KEYS,
  SEAM_BINDINGS,
  seamFor,
  SENSITIVITY_LEVELS,
  TRUST_LEVELS,
} from './policy.js'

/** How the mount config is named in an error message. */
export const MOUNT_SOURCE = 'the mount config'

/** The path an error message starts from, matching the documented YAML. */
export const ROOT_PATH = 'airlock'

/** Every key the configuration admits at the top level. */
export const CONFIG_KEYS: readonly string[] = Object.freeze([
  'posture',
  'dryRun',
  'policyFile',
  'classes',
  'secretPaths',
  'untrustedSources',
  'opaqueReaders',
  'rules',
  'declassify',
  'evidence',
  'preStep',
  'backstop',
])

/** Every key the `preStep` section admits. */
export const PRE_STEP_KEYS: readonly string[] = Object.freeze([
  'secretProducers',
  'untrustedProducers',
  'redactAtOrAbove',
  'reject',
])

/** Every key `preStep.reject` admits. */
export const PRE_STEP_REJECT_KEYS: readonly string[] = Object.freeze(['trust', 'sensitivity'])

/** Every key the `backstop` section admits. */
export const BACKSTOP_KEYS: readonly string[] = Object.freeze(['auxiliary'])

/** Every key the `opaqueReaders` section admits. */
export const OPAQUE_READER_KEYS: readonly string[] = Object.freeze([
  'tools',
  'sensitivity',
  'trust',
])

/** The capability classes a tool can be assigned to by name. */
export const ASSIGNABLE_CLASSES: readonly string[] = Object.freeze(['egress', 'mutate'])

/** Policy file extensions read without any dependency. */
export const JSON_EXTENSIONS: readonly string[] = Object.freeze(['.json'])

/** Policy file extensions read through the optional `js-yaml` peer. */
export const YAML_EXTENSIONS: readonly string[] = Object.freeze(['.yml', '.yaml'])

/**
 * Tool name lists, as configured.
 *
 * A class that is absent keeps its built-in list. A class that is present
 * replaces its built-in list outright, including the `mcp__*` entry that covers
 * every bridged server tool, so a configured list must name everything it means
 * to cover. That is the cost of a policy an operator can read off the page.
 */
export interface ClassConfig {
  readonly egress?: readonly string[]
  readonly mutate?: readonly string[]
}

/** Declassification, as configured. */
export interface DeclassifyConfig {
  readonly allow?: boolean
}

/** Evidence sinks, as configured. `jsonl` is a path, or `false` to disable. */
export interface EvidenceConfig {
  readonly otlp?: boolean
  readonly jsonl?: boolean | string
}

/**
 * Gate B, the entering-message gate, as configured.
 *
 * This is the section that makes `agent/pre-step` reachable from a policy file.
 * Every field is optional and every default is inert: nothing classifies as
 * secret, and the gate never rejects a step, until an operator says otherwise.
 *
 * `secretProducers` and `untrustedProducers` are producer name patterns, in the
 * same vocabulary the capability class lists use — a plain name, or a name with
 * a trailing `*`. A producer is a plugin name for plugin-sourced content, and
 * the message kind otherwise. That is classification data about producers,
 * evaluated before any content exists, in the same sense as a secret path glob.
 */
export interface PreStepConfig {
  readonly secretProducers?: readonly string[]
  readonly untrustedProducers?: readonly string[]
  readonly redactAtOrAbove?: Sensitivity
  readonly reject?: PreStepRejection
}

/**
 * Opaque readers, as configured.
 *
 * `tools` is a list of tool name patterns in the same vocabulary the capability
 * class lists use — a plain name, or a name with a trailing `*`. It is empty
 * until an operator writes one, because the feature is off by default.
 *
 * ```yaml
 * airlock:
 *   opaqueReaders:
 *     tools: [bash, pwsh, run_code, "terminal_*"]
 *     sensitivity: secret
 *     trust: workspace
 * ```
 *
 * Read the cost in the `ledger.ts` module documentation before setting `tools`.
 * A shell declared opaque at `secret` ends the session's network access on its
 * first call and has its own output withheld under the built-in result rule.
 */
export interface OpaqueReadersConfig {
  readonly tools?: readonly string[]
  readonly sensitivity?: Sensitivity
  readonly trust?: Trust
}

/** The provider backstop, as configured. */
export interface BackstopConfig {
  /**
   * `true` subjects auxiliary model calls to the backstop too. There is no
   * `enabled` key: what arms the backstop is a `provider` boundary `redact`
   * rule, so that the rule an operator reads is the rule that fires.
   */
  readonly auxiliary?: boolean
}

/**
 * One validated configuration layer.
 *
 * Every field is optional, because a layer states only what it changes. A field
 * that is absent here is absent, not `undefined`: `exactOptionalPropertyTypes`
 * makes that distinction, and merging relies on it.
 */
export interface PolicyConfig {
  readonly posture?: Posture
  readonly dryRun?: boolean
  /** A workspace policy file to read. Only the mount config may set it. */
  readonly policyFile?: string
  readonly classes?: ClassConfig
  readonly secretPaths?: readonly string[]
  readonly untrustedSources?: readonly string[]
  readonly opaqueReaders?: OpaqueReadersConfig
  readonly rules?: readonly RuleSpec[]
  readonly declassify?: DeclassifyConfig
  readonly evidence?: EvidenceConfig
  readonly preStep?: PreStepConfig
  readonly backstop?: BackstopConfig
}

/** How a policy is loaded. Every field is a seam a test can substitute. */
export interface LoadPolicyOptions {
  /** A policy file to read, overriding the one the mount config names. */
  readonly policyFile?: string
  /** The directory a relative `policyFile` resolves against. Defaults to `process.cwd()`. */
  readonly cwd?: string
  /** How a file is read. Defaults to `readFileSync` in UTF-8. */
  readonly readFile?: (path: string) => string
  /** How `js-yaml` is loaded. Defaults to a dynamic import of the package. */
  readonly loadYaml?: () => Promise<unknown>
}

/**
 * A configuration this module refused to load.
 *
 * The message names the file, the path within it, and what was wrong, because
 * the operator reading it is holding a typo in a security policy.
 */
export class PolicyConfigError extends Error {
  /** Which layer the error came from: the mount config or a file. */
  readonly source: string

  /** Where in that layer, in `airlock.rules[0].then` form. */
  readonly at: string

  constructor(source: string, at: string, detail: string) {
    super(`airlock policy: \`${at}\` in ${source} ${detail}`)
    this.name = 'PolicyConfigError'
    this.source = source
    this.at = at
  }
}

/**
 * Refuse a configuration.
 * @param source - which layer the value came from.
 * @param at - where in that layer.
 * @param detail - what was wrong, continuing the sentence the message opens.
 * @throws {PolicyConfigError} always.
 */
function fail(source: string, at: string, detail: string): never {
  throw new PolicyConfigError(source, at, detail)
}

/**
 * Name a value's type for an error message.
 * @param value - the offending value.
 * @returns a short noun phrase.
 */
function describeType(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return 'not set'
  if (Array.isArray(value)) return 'a list'
  return `a ${typeof value}`
}

/**
 * Render a list of accepted values for an error message.
 * @param values - the accepted values.
 * @returns them, comma separated and back-quoted.
 */
function quoteList(values: readonly string[]): string {
  return values.map((value) => `\`${value}\``).join(', ')
}

/**
 * Read an error's message.
 * @param error - whatever was thrown.
 * @returns its message, or its string form.
 */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Require a mapping.
 * @param value - the configured value.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the value as a plain object.
 */
function requireObject(value: unknown, source: string, at: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail(source, at, `must be a mapping, but it is ${describeType(value)}.`)
  }
  return value as Record<string, unknown>
}

/**
 * Reject any key that is not in the accepted set.
 *
 * A typo in a security policy must not be ignored. `sensitivty: secret` would
 * otherwise leave a rule that constrains nothing and denies nothing.
 *
 * @param object - the mapping to check.
 * @param allowed - the accepted keys.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @param hint - an extra sentence appended to the message.
 */
function requireKeys(
  object: Record<string, unknown>,
  allowed: readonly string[],
  source: string,
  at: string,
  hint = '',
): void {
  for (const key of Object.keys(object)) {
    if (allowed.includes(key)) continue
    fail(
      source,
      `${at}.${key}`,
      `is not a key airlock knows. The accepted keys are ${quoteList(allowed)}.${hint}`,
    )
  }
}

/**
 * Require one of a fixed set of strings.
 * @param value - the configured value.
 * @param allowed - the accepted values.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @param what - what the set is called, for the message.
 * @returns the value, narrowed.
 */
function requireEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  source: string,
  at: string,
  what: string,
): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    fail(
      source,
      at,
      `is not ${what} airlock knows. The accepted values are ${quoteList(allowed)}, but it is `
      + `${typeof value === 'string' ? `\`${value}\`` : describeType(value)}.`,
    )
  }
  return value as T
}

/**
 * Require a boolean.
 * @param value - the configured value.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the value.
 */
function requireBoolean(value: unknown, source: string, at: string): boolean {
  if (typeof value !== 'boolean') {
    fail(source, at, `must be true or false, but it is ${describeType(value)}.`)
  }
  return value
}

/**
 * Require a non-empty string.
 * @param value - the configured value.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the value.
 */
function requireString(value: unknown, source: string, at: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    fail(source, at, `must be a non-empty string, but it is ${describeType(value)}.`)
  }
  return value
}

/**
 * Require a list of non-empty strings.
 * @param value - the configured value.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the list, copied and frozen.
 */
function requireStringArray(value: unknown, source: string, at: string): readonly string[] {
  if (!Array.isArray(value)) {
    fail(source, at, `must be a list of strings, but it is ${describeType(value)}.`)
  }
  const entries = value as readonly unknown[]
  return Object.freeze(entries.map((entry, index) => requireString(entry, source, `${at}[${index}]`)))
}

/**
 * Validate one rule's `when`.
 *
 * The accepted keys are the whole vocabulary of the policy. There is no key for
 * an argument value and no key for output text, and the error message says so,
 * because an operator who reaches for one has misunderstood what this plugin
 * enforces rather than mistyped.
 *
 * @param value - the configured condition.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated condition.
 */
function validateCondition(value: unknown, source: string, at: string): RuleCondition {
  const raw = requireObject(value, source, at)
  requireKeys(
    raw,
    CONDITION_KEYS,
    source,
    at,
    ' A rule constrains labels and capability classes only. There is no key for'
    + ' an argument value or for tool output, because a model can rewrite both.',
  )

  const condition: {
    trust?: Trust
    sensitivity?: Sensitivity
    capability?: Capability
    boundary?: Boundary
  } = {}

  if (raw.trust !== undefined) {
    condition.trust = requireEnum(raw.trust, TRUST_LEVELS, source, `${at}.trust`, 'a trust level')
  }
  if (raw.sensitivity !== undefined) {
    condition.sensitivity = requireEnum(
      raw.sensitivity,
      SENSITIVITY_LEVELS,
      source,
      `${at}.sensitivity`,
      'a sensitivity level',
    )
  }
  if (raw.capability !== undefined) {
    condition.capability = requireEnum(
      raw.capability,
      CAPABILITIES,
      source,
      `${at}.capability`,
      'a capability class',
    )
  }
  if (raw.boundary !== undefined) {
    condition.boundary = requireEnum(raw.boundary, BOUNDARIES, source, `${at}.boundary`, 'a boundary')
  }
  return condition
}

/**
 * Name the effects one boundary can carry.
 * @param boundary - the boundary.
 * @returns the effects, comma separated and back-quoted.
 */
function effectsAt(boundary: Boundary): string {
  return quoteList(
    SEAM_BINDINGS.filter((seam) => seam.boundary === boundary).map((seam) => seam.effect),
  )
}

/**
 * Validate one authored rule.
 * @param value - the configured rule.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated rule spec.
 */
function validateRule(value: unknown, source: string, at: string): RuleSpec {
  const raw = requireObject(value, source, at)
  requireKeys(raw, RULE_KEYS, source, at)

  if (raw.when === undefined) {
    fail(source, at, 'needs a `when`. Write `when: {}` if the rule really applies to every call.')
  }
  if (raw.then === undefined) {
    fail(source, at, `needs a \`then\`. The accepted effects are ${quoteList(EFFECTS)}.`)
  }

  const when = validateCondition(raw.when, source, `${at}.when`)
  const then = requireEnum(raw.then, EFFECTS, source, `${at}.then`, 'an effect')
  const boundary = when.boundary ?? DEFAULT_BOUNDARY

  // A pair with no seam behind it is a rule that would never fire. Saying so at
  // load time is the only honest option; accepting it would ship a policy whose
  // written intent and enforced behaviour disagree.
  if (seamFor(boundary, then) === undefined) {
    const elsewhere = SEAM_BINDINGS.find((seam) => seam.effect === then)
    const advice = elsewhere === undefined
      ? ''
      : ` \`${then}\` is enforced at the ${elsewhere.boundary} boundary, by ${elsewhere.enforcedBy}.`
    fail(
      source,
      at,
      `asks for \`${then}\` at the ${boundary} boundary, and no seam enforces that. The `
      + `${boundary} boundary carries ${effectsAt(boundary)}.${advice}`,
    )
  }

  const id = raw.id === undefined ? undefined : requireString(raw.id, source, `${at}.id`)
  const rationale = raw.rationale === undefined
    ? undefined
    : requireString(raw.rationale, source, `${at}.rationale`)

  return {
    when,
    then,
    ...id === undefined ? {} : { id },
    ...rationale === undefined ? {} : { rationale },
  }
}

/**
 * Validate the tool name lists.
 * @param value - the configured classes.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated class lists.
 */
function validateClasses(value: unknown, source: string, at: string): ClassConfig {
  const raw = requireObject(value, source, at)
  for (const key of Object.keys(raw)) {
    if (ASSIGNABLE_CLASSES.includes(key)) continue
    if (key === 'read') {
      fail(
        source,
        `${at}.read`,
        'cannot be listed. `read` is the class of every tool that matches no other class, so a'
        + ' tool joins it by being absent from `egress` and `mutate`.',
      )
    }
    fail(
      source,
      `${at}.${key}`,
      `is not a capability class airlock knows. Tools can be assigned to ${quoteList(ASSIGNABLE_CLASSES)}.`,
    )
  }

  const classes: { egress?: readonly string[]; mutate?: readonly string[] } = {}
  if (raw.egress !== undefined) {
    classes.egress = requireStringArray(raw.egress, source, `${at}.egress`)
  }
  if (raw.mutate !== undefined) {
    classes.mutate = requireStringArray(raw.mutate, source, `${at}.mutate`)
  }
  return classes
}

/**
 * Validate `preStep.reject`.
 *
 * A rejection that names neither axis is refused rather than accepted. A
 * `when: {}` on a rule is accepted because it applies to everything, which is
 * the broad reading; a `reject: {}` is the opposite — it fires for nothing —
 * and an operator who wrote one has configured a control that cannot act.
 *
 * @param value - the configured rejection.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated rejection.
 */
function validatePreStepRejection(value: unknown, source: string, at: string): PreStepRejection {
  const raw = requireObject(value, source, at)
  requireKeys(
    raw,
    PRE_STEP_REJECT_KEYS,
    source,
    at,
    ' Rejection reads the session context label and nothing else. There is no key'
    + ' for a message body, because a model can rewrite one.',
  )

  const rejection: { trust?: Trust; sensitivity?: Sensitivity } = {}
  if (raw.trust !== undefined) {
    rejection.trust = requireEnum(raw.trust, TRUST_LEVELS, source, `${at}.trust`, 'a trust level')
  }
  if (raw.sensitivity !== undefined) {
    rejection.sensitivity = requireEnum(
      raw.sensitivity,
      SENSITIVITY_LEVELS,
      source,
      `${at}.sensitivity`,
      'a sensitivity level',
    )
  }
  if (rejection.trust === undefined && rejection.sensitivity === undefined) {
    fail(
      source,
      at,
      'names neither `trust` nor `sensitivity`, so it would never reject a step. Name the axis '
      + 'the step must not run at, or remove the key.',
    )
  }
  return rejection
}

/**
 * Validate the `preStep` section.
 * @param value - the configured section.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated section, holding only the keys it actually set.
 */
function validatePreStep(value: unknown, source: string, at: string): PreStepConfig {
  const raw = requireObject(value, source, at)
  requireKeys(raw, PRE_STEP_KEYS, source, at)

  const preStep: {
    secretProducers?: readonly string[]
    untrustedProducers?: readonly string[]
    redactAtOrAbove?: Sensitivity
    reject?: PreStepRejection
  } = {}

  if (raw.secretProducers !== undefined) {
    preStep.secretProducers = requireStringArray(
      raw.secretProducers,
      source,
      `${at}.secretProducers`,
    )
  }
  if (raw.untrustedProducers !== undefined) {
    preStep.untrustedProducers = requireStringArray(
      raw.untrustedProducers,
      source,
      `${at}.untrustedProducers`,
    )
  }
  if (raw.redactAtOrAbove !== undefined) {
    preStep.redactAtOrAbove = requireEnum(
      raw.redactAtOrAbove,
      SENSITIVITY_LEVELS,
      source,
      `${at}.redactAtOrAbove`,
      'a sensitivity level',
    )
  }
  if (raw.reject !== undefined) {
    preStep.reject = validatePreStepRejection(raw.reject, source, `${at}.reject`)
  }
  return preStep
}

/**
 * Validate the `opaqueReaders` section.
 *
 * The error message names the cost, because an operator who mistyped this
 * section is configuring the one setting in this plugin that trades a large
 * amount of ordinary agent capability for one guarantee.
 *
 * @param value - the configured section.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated section, holding only the keys it actually set.
 */
function validateOpaqueReaders(value: unknown, source: string, at: string): OpaqueReadersConfig {
  const raw = requireObject(value, source, at)
  requireKeys(
    raw,
    OPAQUE_READER_KEYS,
    source,
    at,
    ' A tool is declared opaque by name. There is no key for a command string or'
    + ' for result text, because a model can rewrite both.',
  )

  const readers: { tools?: readonly string[]; sensitivity?: Sensitivity; trust?: Trust } = {}
  if (raw.tools !== undefined) {
    readers.tools = requireStringArray(raw.tools, source, `${at}.tools`)
  }
  if (raw.sensitivity !== undefined) {
    readers.sensitivity = requireEnum(
      raw.sensitivity,
      SENSITIVITY_LEVELS,
      source,
      `${at}.sensitivity`,
      'a sensitivity level',
    )
  }
  if (raw.trust !== undefined) {
    readers.trust = requireEnum(raw.trust, TRUST_LEVELS, source, `${at}.trust`, 'a trust level')
  }
  return readers
}

/**
 * Validate the `backstop` section.
 * @param value - the configured section.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated section.
 */
function validateBackstop(value: unknown, source: string, at: string): BackstopConfig {
  const raw = requireObject(value, source, at)
  requireKeys(
    raw,
    BACKSTOP_KEYS,
    source,
    at,
    ' The backstop is armed by a rule with `boundary: provider` and `then: redact`,'
    + ' not by a switch here.',
  )
  return raw.auxiliary === undefined
    ? {}
    : { auxiliary: requireBoolean(raw.auxiliary, source, `${at}.auxiliary`) }
}

/**
 * Validate one configuration layer.
 *
 * @param value - the layer, exactly as it was parsed.
 * @param source - which layer it is, for the error message.
 * @param at - the path prefix, for the error message.
 * @returns the validated layer, holding only keys the layer actually set.
 * @throws {PolicyConfigError} on any key, value, or shape it does not know.
 */
export function validateConfig(
  value: unknown,
  source: string = MOUNT_SOURCE,
  at: string = ROOT_PATH,
): PolicyConfig {
  const raw = requireObject(value, source, at)
  requireKeys(raw, CONFIG_KEYS, source, at)

  const config: {
    posture?: Posture
    dryRun?: boolean
    policyFile?: string
    classes?: ClassConfig
    secretPaths?: readonly string[]
    untrustedSources?: readonly string[]
    opaqueReaders?: OpaqueReadersConfig
    rules?: readonly RuleSpec[]
    declassify?: DeclassifyConfig
    evidence?: EvidenceConfig
    preStep?: PreStepConfig
    backstop?: BackstopConfig
  } = {}

  if (raw.posture !== undefined) {
    config.posture = requireEnum(raw.posture, POSTURES, source, `${at}.posture`, 'a posture')
  }
  if (raw.dryRun !== undefined) {
    config.dryRun = requireBoolean(raw.dryRun, source, `${at}.dryRun`)
  }
  if (raw.policyFile !== undefined) {
    config.policyFile = requireString(raw.policyFile, source, `${at}.policyFile`)
  }
  if (raw.classes !== undefined) {
    config.classes = validateClasses(raw.classes, source, `${at}.classes`)
  }
  if (raw.secretPaths !== undefined) {
    config.secretPaths = requireStringArray(raw.secretPaths, source, `${at}.secretPaths`)
  }
  if (raw.untrustedSources !== undefined) {
    config.untrustedSources = requireStringArray(
      raw.untrustedSources,
      source,
      `${at}.untrustedSources`,
    )
  }
  if (raw.opaqueReaders !== undefined) {
    config.opaqueReaders = validateOpaqueReaders(raw.opaqueReaders, source, `${at}.opaqueReaders`)
  }
  if (raw.rules !== undefined) {
    config.rules = validateRules(raw.rules, source, `${at}.rules`)
  }
  if (raw.declassify !== undefined) {
    const declassifyAt = `${at}.declassify`
    const declassify = requireObject(raw.declassify, source, declassifyAt)
    requireKeys(declassify, ['allow'], source, declassifyAt)
    config.declassify = declassify.allow === undefined
      ? {}
      : { allow: requireBoolean(declassify.allow, source, `${declassifyAt}.allow`) }
  }
  if (raw.evidence !== undefined) {
    config.evidence = validateEvidence(raw.evidence, source, `${at}.evidence`)
  }
  if (raw.preStep !== undefined) {
    config.preStep = validatePreStep(raw.preStep, source, `${at}.preStep`)
  }
  if (raw.backstop !== undefined) {
    config.backstop = validateBackstop(raw.backstop, source, `${at}.backstop`)
  }

  return config
}

/**
 * Validate the rule list and reject a duplicated id.
 * @param value - the configured rules.
 * @param source - which layer they came from.
 * @param at - where in that layer.
 * @returns the validated rule specs, in the authored order.
 */
function validateRules(value: unknown, source: string, at: string): readonly RuleSpec[] {
  if (!Array.isArray(value)) {
    fail(source, at, `must be a list of rules, but it is ${describeType(value)}.`)
  }
  const entries = value as readonly unknown[]
  const seen = new Set<string>()
  const specs = entries.map((entry, index) => {
    const spec = validateRule(entry, source, `${at}[${index}]`)
    if (spec.id !== undefined) {
      // Two rules under one id make evidence ambiguous about which one fired.
      if (seen.has(spec.id)) {
        fail(source, `${at}[${index}].id`, `repeats the id \`${spec.id}\`. Rule ids must be unique.`)
      }
      seen.add(spec.id)
    }
    return spec
  })
  return Object.freeze(specs)
}

/**
 * Validate the evidence sinks.
 * @param value - the configured evidence section.
 * @param source - which layer it came from.
 * @param at - where in that layer.
 * @returns the validated section.
 */
function validateEvidence(value: unknown, source: string, at: string): EvidenceConfig {
  const raw = requireObject(value, source, at)
  requireKeys(raw, ['otlp', 'jsonl'], source, at)

  const evidence: { otlp?: boolean; jsonl?: boolean | string } = {}
  if (raw.otlp !== undefined) {
    evidence.otlp = requireBoolean(raw.otlp, source, `${at}.otlp`)
  }
  if (raw.jsonl !== undefined) {
    const jsonl = raw.jsonl
    if (typeof jsonl === 'boolean') evidence.jsonl = jsonl
    else if (typeof jsonl === 'string' && jsonl.length > 0) evidence.jsonl = jsonl
    else {
      fail(
        source,
        `${at}.jsonl`,
        `must be a file path or false, but it is ${describeType(jsonl)}.`,
      )
    }
  }
  return evidence
}

/**
 * Merge one section of two layers.
 * @param base - the lower layer's section.
 * @param override - the higher layer's section.
 * @returns the merged section, or `undefined` when neither layer set one.
 */
function mergeSection<T extends object>(base: T | undefined, override: T | undefined): T | undefined {
  if (base === undefined) return override
  if (override === undefined) return base
  return { ...base, ...override }
}

/**
 * Merge two validated layers.
 *
 * A key the higher layer sets replaces the same key in the lower one. A list
 * replaces a list rather than extending it: an operator reviewing a diff should
 * be able to read the effective list off the page, and a silent union would
 * also make a class impossible to narrow. The sections that hold independent
 * switches — `classes`, `declassify`, `evidence`, `preStep`, `backstop`, and
 * `opaqueReaders` — merge one key at a time, so setting `classes.egress` leaves the
 * built-in `mutate` list in place. That merge is one level deep: a `preStep`
 * layer that sets `reject` replaces the whole `reject` mapping below it, for the
 * same reason a list replaces a list.
 *
 * @param base - the lower layer.
 * @param override - the higher layer.
 * @returns the merged layer.
 */
export function mergeConfigs(base: PolicyConfig, override: PolicyConfig): PolicyConfig {
  const classes = mergeSection(base.classes, override.classes)
  const declassify = mergeSection(base.declassify, override.declassify)
  const evidence = mergeSection(base.evidence, override.evidence)
  const preStep = mergeSection(base.preStep, override.preStep)
  const backstop = mergeSection(base.backstop, override.backstop)
  const opaqueReaders = mergeSection(base.opaqueReaders, override.opaqueReaders)
  return {
    ...base,
    ...override,
    ...classes === undefined ? {} : { classes },
    ...declassify === undefined ? {} : { declassify },
    ...evidence === undefined ? {} : { evidence },
    ...preStep === undefined ? {} : { preStep },
    ...backstop === undefined ? {} : { backstop },
    ...opaqueReaders === undefined ? {} : { opaqueReaders },
  }
}

/**
 * Fill every default and compile the rules.
 *
 * This is the lowest merge layer: whatever the configuration leaves unset comes
 * from {@link DEFAULT_POLICY} here. A configured rule list replaces the
 * built-in rules outright, including the two the milestone ships, because a
 * reader of the policy file must see the whole evaluation order in one place.
 *
 * @param config - the merged configuration layers.
 * @returns the policy in force.
 */
export function resolvePolicy(config: PolicyConfig = {}): Policy {
  const evidence = config.evidence ?? {}
  const jsonl = evidence.jsonl
  const classes: CapabilityClasses = {
    egress: config.classes?.egress ?? DEFAULT_CLASSES.egress,
    mutate: config.classes?.mutate ?? DEFAULT_CLASSES.mutate,
  }
  const preStepConfig = config.preStep
  // Every field is conditionally spread, because `exactOptionalPropertyTypes`
  // distinguishes an absent field from one set to `undefined`, and Gate B reads
  // an absent field as its inert default.
  const preStep: PreStepPolicy = preStepConfig === undefined ? {} : {
    ...preStepConfig.secretProducers === undefined
      ? {}
      : { secretProducers: preStepConfig.secretProducers },
    ...preStepConfig.untrustedProducers === undefined
      ? {}
      : { untrustedProducers: preStepConfig.untrustedProducers },
    ...preStepConfig.redactAtOrAbove === undefined
      ? {}
      : { redactAtOrAbove: preStepConfig.redactAtOrAbove },
    ...preStepConfig.reject === undefined ? {} : { reject: preStepConfig.reject },
  }
  const backstop: BackstopSettings = {
    auxiliary: config.backstop?.auxiliary ?? DEFAULT_POLICY.backstop.auxiliary,
  }
  const readers = config.opaqueReaders
  // `trust` is spread conditionally rather than defaulted: an absent trust floor
  // means the axis is left where the inspected label put it, which is not the
  // same statement as a floor of `user`.
  const opaqueReaders: OpaqueReaders = {
    tools: readers?.tools ?? DEFAULT_OPAQUE_READERS.tools,
    sensitivity: readers?.sensitivity ?? DEFAULT_OPAQUE_READERS.sensitivity,
    ...readers?.trust === undefined ? {} : { trust: readers.trust },
  }

  return {
    posture: config.posture ?? DEFAULT_POLICY.posture,
    dryRun: config.dryRun ?? DEFAULT_POLICY.dryRun,
    classes,
    secretPaths: config.secretPaths ?? DEFAULT_SECRET_PATHS,
    untrustedSources: config.untrustedSources ?? DEFAULT_UNTRUSTED_SOURCES,
    opaqueReaders,
    rules: config.rules === undefined ? DEFAULT_RULES : compileRules(config.rules),
    declassify: { allow: config.declassify?.allow ?? DEFAULT_POLICY.declassify.allow },
    evidence: {
      otlp: evidence.otlp ?? DEFAULT_POLICY.evidence.otlp,
      jsonl: jsonl === undefined ? DEFAULT_POLICY.evidence.jsonl : jsonl !== false,
      path: typeof jsonl === 'string' ? expandHome(jsonl) : DEFAULT_POLICY.evidence.path,
    },
    preStep,
    backstop,
  }
}

/**
 * Resolve a policy from the mount config alone.
 *
 * The synchronous path, and the one a plugin's `apply` uses when no policy file
 * is configured. A mount config that names a `policyFile` is refused rather
 * than served without it, because ignoring the file would enforce a policy the
 * operator did not write.
 *
 * @param mount - the configuration object the cordis mount supplied.
 * @returns the policy in force.
 * @throws {PolicyConfigError} on an invalid config, or when a file is named.
 */
export function policyFromConfig(mount: unknown = {}): Policy {
  const config = validateConfig(mount, MOUNT_SOURCE)
  if (config.policyFile !== undefined) {
    fail(
      MOUNT_SOURCE,
      `${ROOT_PATH}.policyFile`,
      'names a file, and reading a file needs `loadPolicy()` rather than `policyFromConfig()`.',
    )
  }
  return resolvePolicy(config)
}

/**
 * Resolve a policy file path.
 * @param path - the configured path, possibly relative and possibly `~`-prefixed.
 * @param cwd - the directory a relative path resolves against.
 * @returns the absolute path.
 */
function resolvePolicyPath(path: string, cwd: string | undefined): string {
  return resolve(cwd ?? process.cwd(), expandHome(path))
}

/**
 * Load the `js-yaml` namespace.
 * @param source - the file being read, for the error message.
 * @param options - the load seams.
 * @returns the module namespace.
 * @throws {PolicyConfigError} when the optional peer cannot be loaded.
 */
async function importYaml(source: string, options: LoadPolicyOptions): Promise<unknown> {
  try {
    if (options.loadYaml !== undefined) return await options.loadYaml()
    // The specifier is held in a variable so the compiler does not resolve it.
    // `js-yaml` is an optional peer and may be absent from an installation.
    const specifier = 'js-yaml'
    return await import(specifier)
  } catch (error) {
    fail(
      source,
      ROOT_PATH,
      'is YAML, and reading it needs the optional peer dependency `js-yaml`, which failed to load: '
      + `${messageOf(error)}. Install it with \`npm install js-yaml\`, or write the policy as JSON. `
      + 'The file is not ignored, because a policy that does not load is a policy that is not enforced.',
    )
  }
}

/**
 * Pull the `load` function out of the `js-yaml` namespace.
 * @param namespace - whatever the import resolved.
 * @returns the parser, or `undefined` when the shape is not the one expected.
 */
function yamlLoadOf(namespace: unknown): ((text: string) => unknown) | undefined {
  if (typeof namespace !== 'object' || namespace === null) return undefined
  const direct = (namespace as { load?: unknown }).load
  if (typeof direct === 'function') return direct as (text: string) => unknown
  const fallback = (namespace as { default?: { load?: unknown } }).default?.load
  if (typeof fallback === 'function') return fallback as (text: string) => unknown
  return undefined
}

/**
 * Parse a policy file's text according to its extension.
 *
 * `.json` is parsed with no dependency at all. `.yml` and `.yaml` go through
 * `js-yaml`. Any other extension is refused rather than guessed at.
 *
 * @param text - the file's contents.
 * @param path - the file's path, which selects the parser.
 * @param options - the load seams.
 * @returns the parsed document, before validation.
 * @throws {PolicyConfigError} when the file cannot be parsed.
 */
export async function parsePolicyDocument(
  text: string,
  path: string,
  options: LoadPolicyOptions = {},
): Promise<unknown> {
  const source = `the policy file ${path}`
  const extension = extname(path).toLowerCase()

  if (JSON_EXTENSIONS.includes(extension)) {
    try {
      return JSON.parse(text)
    } catch (error) {
      fail(source, ROOT_PATH, `is not valid JSON: ${messageOf(error)}.`)
    }
  }

  if (YAML_EXTENSIONS.includes(extension)) {
    const namespace = await importYaml(source, options)
    const load = yamlLoadOf(namespace)
    if (load === undefined) {
      fail(
        source,
        ROOT_PATH,
        'is YAML, and the loaded `js-yaml` module exposes no `load` function. Check that the'
        + ' installed `js-yaml` is version 4 or later.',
      )
    }
    try {
      return load(text)
    } catch (error) {
      fail(source, ROOT_PATH, `is not valid YAML: ${messageOf(error)}.`)
    }
  }

  fail(
    source,
    ROOT_PATH,
    `has the extension \`${extension}\`, which airlock does not read. It reads `
    + `${quoteList(JSON_EXTENSIONS)} natively and ${quoteList(YAML_EXTENSIONS)} through \`js-yaml\`.`,
  )
}

/**
 * Unwrap a policy document written under a top-level `airlock` key.
 *
 * A file that a team keeps in its repository reads better with the plugin named
 * in it, and the proposal's example is written that way. A document with that
 * single key is unwrapped; anything else is passed through untouched.
 *
 * @param document - the parsed document.
 * @returns the configuration mapping.
 */
export function unwrapPolicyDocument(document: unknown): unknown {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) return document
  const keys = Object.keys(document)
  if (keys.length !== 1 || keys[0] !== ROOT_PATH) return document
  return (document as Record<string, unknown>)[ROOT_PATH]
}

/**
 * Read one file's text.
 * @param path - the absolute path.
 * @param source - the file, for the error message.
 * @param options - the load seams.
 * @returns the file's contents.
 * @throws {PolicyConfigError} when the file cannot be read.
 */
function readPolicyText(path: string, source: string, options: LoadPolicyOptions): string {
  const read = options.readFile ?? ((target: string) => readFileSync(target, 'utf8'))
  try {
    return read(path)
  } catch (error) {
    fail(
      source,
      ROOT_PATH,
      `cannot be read: ${messageOf(error)}. A configured policy file must load, because a policy `
      + 'that does not load is a policy that is not enforced.',
    )
  }
}

/**
 * Read and validate a workspace policy file.
 * @param path - the configured path, relative to `options.cwd` when relative.
 * @param options - the load seams.
 * @returns the validated layer.
 * @throws {PolicyConfigError} when the file is missing, unparsable, or invalid.
 */
export async function loadPolicyFile(
  path: string,
  options: LoadPolicyOptions = {},
): Promise<PolicyConfig> {
  const resolved = resolvePolicyPath(path, options.cwd)
  const source = `the policy file ${resolved}`
  const text = readPolicyText(resolved, source, options)
  const document = await parsePolicyDocument(text, resolved, options)
  const config = validateConfig(unwrapPolicyDocument(document), source)
  if (config.policyFile !== undefined) {
    // One hop only. A chain of files is a policy nobody can read in one sitting.
    fail(source, `${ROOT_PATH}.policyFile`, 'cannot appear in a policy file. Only the mount config may name one.')
  }
  return config
}

/**
 * Load the policy from the mount config and, when one is named, a policy file.
 *
 * The merge order is the documented one: built-in defaults, then the workspace
 * policy file, then the mount config.
 *
 * @param mount - the configuration object the cordis mount supplied.
 * @param options - the load seams, including a `policyFile` override.
 * @returns the policy in force.
 * @throws {PolicyConfigError} on any configuration this module cannot load.
 */
export async function loadPolicy(
  mount: unknown = {},
  options: LoadPolicyOptions = {},
): Promise<Policy> {
  const mountConfig = validateConfig(mount, MOUNT_SOURCE)
  const path = options.policyFile ?? mountConfig.policyFile
  if (path === undefined) return resolvePolicy(mountConfig)
  const fileConfig = await loadPolicyFile(path, options)
  return resolvePolicy(mergeConfigs(fileConfig, mountConfig))
}
