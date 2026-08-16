/**
 * The provider backstop at `llm/stream`.
 *
 * `llm/stream` is the last seam before the adapter carries a request off the
 * machine. This module blocks there. It never edits, for two reasons. A
 * loop-built request arrives deep-frozen and mutation throws, and a request
 * that reached the provider in a form the session log does not record would
 * break the harness's own "model-visible means logged" invariant. The
 * catalogue states the rule plainly: listeners read the request, never rewrite
 * it.
 *
 * Blocking has two shapes here, and only one of them is graceful. Throwing
 * ends the whole turn with `turn/end { kind: 'error', code: 'UNKNOWN' }` and an
 * `agent/error` emit, because middleware failures are not normalised into the
 * stream protocol. Short-circuiting returns this module's own chunks without
 * calling `next()`, which the catalogue sanctions, and the turn ends with an
 * assistant message that says what happened. This module short-circuits.
 *
 * ## The backstop is disabled by default, and that is the important decision
 *
 * Over-blocking is the failure mode this project most needs to avoid. Once a
 * secret is on the surface it stays there until compaction drops it, so an
 * always-on rule that blocks every model call carrying a secret does not block
 * one exfiltration. It blocks every remaining step of the session, including
 * the ones that would have done the user's work, and it does so with no tool
 * call in sight. Gate A already denies the capability that could carry the
 * secret out. The backstop exists for the deployment that does not trust the
 * model provider itself with the content, and that is an explicit operator
 * decision rather than a default.
 *
 * Enabling it therefore requires `enabled: true` from the caller. A policy that
 * does not say so leaves every request untouched.
 *
 * Verified against dsh 0.1.0-rc.5. The waterfall signature and the
 * short-circuit sanction are at `packages/llm/llm/src/index.ts:64`, the
 * deep-freeze of a loop-built request at
 * `packages/core/agent-loop/src/agent.ts:486-494`, the fact that middleware
 * errors stay thrown at `packages/llm/llm/README.md:27`, and the absence of
 * scope filtering in the catalogue entry, which is why this module keys off
 * `options.sessionId`.
 */

import type { GenerateOptions, StreamChunk } from './dsh.js'
import type { Label, Sensitivity, Trust } from './labels.js'
import { formatLabel, sensitivityAtLeast, trustAtLeast } from './labels.js'
import type { ContextLabel, Ledger } from './ledger.js'

/**
 * One rule this seam evaluates.
 *
 * A structural subset of the compiled `Rule` in `policy.ts`, declared locally so
 * this module keeps deciding over a label predicate rather than over a policy
 * object it would then have to interpret. A compiled rule is assignable to it.
 */
export interface BackstopRule {
  /** The rule's stable id, quoted in the log line and in evidence. */
  readonly id: string
  /** Whether the session context label triggers the rule. */
  readonly matches: (label: Label) => boolean
  /**
   * The axes the operator actually wrote, which decide which origin the refusal
   * cites. A rule that names neither axis is answered by whichever origin the
   * context has.
   */
  readonly when: {
    readonly trust?: Trust
    readonly sensitivity?: Sensitivity
  }
}

/**
 * The policy bits the backstop reads.
 *
 * The whole shape defaults to inert. An absent policy, an empty policy, and a
 * policy with `enabled: false` all mean the same thing: this seam observes
 * nothing and blocks nothing.
 */
export interface BackstopPolicy {
  /**
   * `true` arms the backstop. Anything else leaves it disabled, which is the
   * default. See the note at the top of this file.
   */
  readonly enabled?: boolean
  /**
   * The rules to evaluate, in authored order.
   *
   * When this list is present it decides, and {@link BackstopPolicy.sensitivity}
   * and {@link BackstopPolicy.trust} are not read at all. The request is blocked
   * when ANY rule matches, which is the same disjunction Gate A performs over an
   * ordered list, and the first matching rule owns the refusal.
   *
   * The alternative — folding several rules into the single threshold pair below
   * — cannot express what an operator wrote. Two rules constraining different
   * axes have no common threshold: the most permissive pair that still fires for
   * both is `trust=user, sensitivity=public`, which blocks every request in
   * every session. Evaluating the rules is the only reading that both fires when
   * a rule says so and stays silent when none does.
   *
   * A provider rule's `capability` axis is not read here, because this seam
   * carries no tool call. Compiling one authored rule per capability class
   * therefore yields duplicate label predicates at this seam, and a disjunction
   * over duplicates is the predicate itself.
   */
  readonly rules?: readonly BackstopRule[]
  /**
   * Block when the session context sensitivity is at or above this level.
   * Defaults to `secret` when the policy names neither axis. Ignored when
   * {@link BackstopPolicy.rules} is present.
   */
  readonly sensitivity?: Sensitivity
  /**
   * Block when the session context trust is at or above this level. Ignored
   * when {@link BackstopPolicy.rules} is present.
   */
  readonly trust?: Trust
  /**
   * `true` subjects auxiliary calls to the backstop too. Defaults to `false`.
   *
   * An auxiliary call is not the agent conversing. `purpose: 'compaction'` is
   * the mechanism that removes a secret from the live surface, so blocking it
   * wedges the session at exactly the label the operator wanted cleared, and
   * `purpose: 'session-title'` names a session. Both reach the same provider,
   * so a deployment that distrusts the provider with any byte of the content
   * sets this to `true` and accepts that compaction stops.
   */
  readonly auxiliary?: boolean
}

/** Whether the backstop blocks one request, and why. */
export type BackstopDecision =
  | { readonly blocked: true; readonly reason: string }
  | { readonly blocked: false }

/** The decision returned when nothing blocks. Shared because it carries no detail. */
const PASS: BackstopDecision = Object.freeze({ blocked: false as const })

/**
 * Compose the refusal text.
 *
 * The text names the label and the origin event, never the content it withheld.
 *
 * @param label - the session context label.
 * @param from - the origin description, or a fallback.
 * @returns the refusal, as the model and the transcript will see it.
 */
function refusalText(label: Label, from: string): string {
  return [
    `airlock blocked this model request at the provider boundary.`,
    `This session's context is ${formatLabel(label)}, from ${from}.`,
    `The request was not sent, and no content left the machine.`,
  ].join(' ')
}

/**
 * Name the event the refusal cites.
 *
 * The axis a rule constrained owns the explanation, exactly as it does in a
 * denial message: a rule written over sensitivity is answered by the node that
 * raised sensitivity, and one written over trust by the node that raised trust.
 *
 * @param context - the session context label and its origins.
 * @param bySensitivity - whether the sensitivity axis is the one that fired.
 * @returns the origin description, or a fallback naming the context itself.
 */
function originFrom(context: ContextLabel, bySensitivity: boolean): string {
  const origin = bySensitivity
    ? context.sensitivityOrigin ?? context.trustOrigin
    : context.trustOrigin ?? context.sensitivityOrigin
  return origin === undefined ? 'this session\'s context' : origin.description
}

/**
 * Evaluate a rule list against one session context label.
 *
 * Any rule that matches blocks, and the first one to match owns the refusal.
 * That is the same first-match-wins reading of one ordered list that Gate A and
 * the ask seam perform, so the operator reads the list once.
 *
 * @param rules - the provider rules, in authored order.
 * @param context - the session context label and its origins.
 * @returns the decision, whose `reason` is present only when it blocks.
 */
function decideByRules(
  rules: readonly BackstopRule[],
  context: ContextLabel,
): BackstopDecision {
  for (const rule of rules) {
    if (!rule.matches(context.label)) continue
    return {
      blocked: true,
      reason: refusalText(context.label, originFrom(context, rule.when.sensitivity !== undefined)),
    }
  }
  return PASS
}

/**
 * Decide whether one assembled request may reach the provider.
 *
 * Pure, and readable without an async iterable. Every path abstains unless the
 * policy is armed and the session's own observed history reaches the
 * configured label.
 *
 * `llm/stream` is not scope-filtered, so this function sees every session and
 * keys off `options.sessionId`. A request with no session identity is a
 * hand-built call the loop did not stamp; it has no ledger to read, so the
 * backstop abstains for the reason Gate A abstains without an agent.
 *
 * @param options - the assembled request, read and never written.
 * @param ledger - the label ledger.
 * @param policy - the policy bits.
 * @returns the decision, whose `reason` is present only when it blocks.
 */
export function shouldBlockRequest(
  options: GenerateOptions,
  ledger: Ledger,
  policy: BackstopPolicy = {},
): BackstopDecision {
  if (policy.enabled !== true) return PASS

  // An auxiliary call is not the agent conversing. See `BackstopPolicy`.
  if (options.purpose !== undefined && policy.auxiliary !== true) return PASS

  const sessionId = options.sessionId
  if (typeof sessionId !== 'string' || sessionId.length === 0) return PASS

  const session = ledger.peek(sessionId)
  if (session === undefined) return PASS

  const context = session.contextLabel()

  // A rule list is what the operator wrote, so it decides on its own terms.
  const rules = policy.rules
  if (rules !== undefined) return decideByRules(rules, context)

  const trust = policy.trust
  const sensitivity = policy.sensitivity ?? (trust === undefined ? 'secret' : undefined)
  if (trust === undefined && sensitivity === undefined) return PASS

  const bySensitivity = sensitivity !== undefined && sensitivityAtLeast(context.label, sensitivity)
  const byTrust = trust !== undefined && trustAtLeast(context.label, trust)
  if (!bySensitivity && !byTrust) return PASS

  return { blocked: true, reason: refusalText(context.label, originFrom(context, bySensitivity)) }
}

/**
 * The stream this module returns in place of a blocked model response.
 *
 * The chunks are a complete, valid run of the harness's stream protocol: one
 * text block opened, filled, and closed, then the terminal `finish`. The
 * grammar the harness enforces is in `packages/llm/llm/src/invariant.ts:36-84`
 * and the union itself is `packages/llm/llm/src/types.ts:291-303`, both at
 * 0.1.0-rc.5. A `finish` reason of `stop` is used rather than `error`, because
 * the request was refused rather than failed: the loop ends the turn with an
 * ordinary assistant message, and that message is appended to the log like any
 * other, so the model-visible text and the log still agree.
 *
 * @param reason - the refusal text to deliver.
 * @returns a single-use stream of valid chunks.
 */
export async function* refusalStream(reason: string): AsyncIterable<StreamChunk> {
  yield { type: 'block-start', index: 0, blockType: 'text' }
  yield { type: 'text-delta', index: 0, text: reason }
  yield { type: 'block-end', index: 0, block: { type: 'text', text: reason } }
  yield { type: 'finish', reason: { kind: 'stop' } }
}

/**
 * Describe an internal failure without leaking a stack into the transcript.
 * @param error - whatever was thrown.
 * @returns the refusal text for a backstop that could not decide.
 */
function internalFailureText(error: unknown): string {
  const message = typeof (error as { message?: unknown } | undefined)?.message === 'string'
    ? (error as { message: string }).message
    : 'unknown failure'
  return [
    `airlock blocked this model request because its own provider backstop failed: ${message}.`,
    `The backstop is enabled, so an undecided request is refused rather than sent.`,
    `Disable the backstop to restore model calls while the failure is investigated.`,
  ].join(' ')
}

/**
 * Wrap the `llm/stream` waterfall.
 *
 * The pass-through returns `next()` itself rather than re-yielding it, so a
 * request this module does not block reaches the adapter through exactly the
 * chunks the adapter produced.
 *
 * The failure direction is the opposite of Gate B's, and deliberately so. A
 * disabled backstop that fails passes through, because nothing was armed and a
 * bug here must not become the first denial of the session. An enabled
 * backstop that fails refuses, because an operator who armed a last-resort deny
 * asked for an undecided request to resolve closed, and AGENTS.md is explicit
 * that a failure must not become an allow. The refusal is graceful and says so
 * in its own text, so a systematic failure is visible in the first transcript
 * rather than silent.
 *
 * @param options - the assembled request, read and never written.
 * @param next - the downstream stream, called only when nothing blocks.
 * @param ledger - the label ledger.
 * @param policy - the policy bits.
 * @returns the adapter's stream, or this module's refusal stream.
 */
export function backstopStream(
  options: GenerateOptions,
  next: () => AsyncIterable<StreamChunk>,
  ledger: Ledger,
  policy: BackstopPolicy = {},
): AsyncIterable<StreamChunk> {
  let decision: BackstopDecision
  try {
    decision = shouldBlockRequest(options, ledger, policy)
  } catch (error) {
    if (policy.enabled !== true) return next()
    return refusalStream(internalFailureText(error))
  }

  if (!decision.blocked) return next()
  return refusalStream(decision.reason)
}
