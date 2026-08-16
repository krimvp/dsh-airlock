/**
 * Gate B — the entering-message gate at `agent/pre-step`.
 *
 * `agent/pre-step` is a waterfall over the messages a proposed step enters
 * with. That batch is the inbox content claimed for this step: fresh human
 * input and injected context, and nothing else. It is not the conversation
 * history. Nothing here can therefore reach a secret that arrived earlier
 * through a `tool/result`, because that content is already in the log and
 * belongs to a different boundary. This module claims neither more nor less.
 *
 * Two moves are sound at this seam, and this module makes exactly those two.
 *
 * The first is redaction of content entering the step. The seam runs upstream
 * of the log, so a message rewritten here reaches the log in its rewritten
 * form. The provider and the log continue to agree, which is the invariant a
 * rewrite at `llm/stream` would break.
 *
 * The second is rejection of the step. A rejected step does not run, the
 * claimed messages end there, and the turn closes without a step. That is a
 * heavy action, so rejection is off unless policy names a condition for it.
 *
 * Every decision here reads a label, and a label is derived from the producer
 * of a message rather than from its text. No branch in this file inspects
 * content; see AGENTS.md.
 *
 * Verified against dsh 0.1.0-rc.5. The waterfall signature is in the API
 * catalogue at `packages/extensions/tool-cordis/src/api-catalog.ts:2225`. The
 * default `next()` enters the claimed batch followed by the projected runtime
 * context, at `packages/core/agent-loop/src/agent.ts:234-240`, which is why
 * {@link applyPreStep} redacts the decision `next()` returned rather than the
 * payload batch. Rewriting the payload would drop the context message the loop
 * appended.
 */

import type { Message, MessageSource, PreStepDecision, PreStepPayload } from './dsh.js'
import type { Label, Sensitivity, Trust } from './labels.js'
import { formatLabel, sensitivityAtLeast, trustAtLeast } from './labels.js'
import type { Ledger } from './ledger.js'
import { matchesToolName } from './policy.js'

/**
 * When the gate rejects a proposed step.
 *
 * Both axes match at or above the named level, exactly as a policy rule does.
 * An absent axis constrains nothing, and a condition that names no axis never
 * fires. There is no key for message text.
 */
export interface PreStepRejection {
  /** Fires when the session context trust is at or above this level. */
  readonly trust?: Trust
  /** Fires when the session context sensitivity is at or above this level. */
  readonly sensitivity?: Sensitivity
}

/**
 * The policy bits Gate B reads.
 *
 * Every field is optional and every default is inert. An empty policy makes
 * this gate a pass-through, which is the posture a step gate should hold until
 * an operator has measured what it would do.
 */
export interface PreStepPolicy {
  /**
   * Producer names whose injected content is `secret`. This is classification
   * data about producers, in the same sense as the secret path globs: it is
   * configuration evaluated before any content exists. Defaults to none, so no
   * message classifies as secret and nothing is redacted.
   */
  readonly secretProducers?: readonly string[]
  /**
   * Producer names whose injected content is `untrusted`. Defaults to none.
   */
  readonly untrustedProducers?: readonly string[]
  /**
   * The sensitivity at or above which an entering message is redacted.
   * Defaults to `secret`.
   */
  readonly redactAtOrAbove?: Sensitivity
  /**
   * When the gate rejects the step outright. Absent means it never rejects,
   * which is the default.
   */
  readonly reject?: PreStepRejection
}

/** What Gate B did to one entering message. */
export interface Redaction {
  /** The message id, when the message carried one. */
  readonly id?: string
  /** The producer the label came from. */
  readonly producer: string
  /** The label that crossed the threshold. */
  readonly label: Label
}

/** The trust of a message whose producer is unknown. Not typed by a human. */
const UNKNOWN_PRODUCER_LABEL: Label = Object.freeze({
  trust: 'workspace' as const,
  sensitivity: 'public' as const,
})

/** The name used when a source names neither a plugin nor a kind. */
const UNKNOWN_PRODUCER = 'an unknown producer'

/**
 * Name the producer of a message.
 *
 * A plugin-sourced message names its plugin. Any other source names its kind,
 * so a policy can classify `tool` or `goal` content as a class. The name is an
 * identity, never a piece of content.
 *
 * @param source - the message source, as the producer declared it.
 * @returns the producer name, or a placeholder when the source declares none.
 */
export function producerName(source: MessageSource | undefined): string {
  if (source === undefined || source === null) return UNKNOWN_PRODUCER
  if (typeof source.plugin === 'string' && source.plugin.length > 0) return source.plugin
  if (typeof source.kind === 'string' && source.kind.length > 0) return source.kind
  return UNKNOWN_PRODUCER
}

/**
 * Label one message entering a step.
 *
 * A message the human typed is the lattice bottom. Everything else is at least
 * workspace trust, because it was produced rather than typed. Policy raises an
 * axis when the producer is named in the corresponding list.
 *
 * @param message - the entering message.
 * @param policy - the policy bits.
 * @returns the label the message carries on arrival.
 */
export function enteringLabel(message: Message, policy: PreStepPolicy = {}): Label {
  const source = message.source
  const producer = producerName(source)
  const typedByAHuman = source?.kind === 'user'

  const secret = matchesToolName(policy.secretProducers ?? [], producer)
  const untrusted = matchesToolName(policy.untrustedProducers ?? [], producer)

  return {
    trust: untrusted
      ? 'untrusted'
      : typedByAHuman ? 'user' : UNKNOWN_PRODUCER_LABEL.trust,
    sensitivity: secret ? 'secret' : 'public',
  }
}

/**
 * Compose the notice that replaces redacted content.
 *
 * The notice names the producer and the label, and nothing about the content
 * it stands in for. It is model-visible and it reaches the log, so the two
 * agree on what the step saw.
 *
 * @param producer - the producer of the redacted message.
 * @param label - the label that crossed the threshold.
 * @returns the notice text.
 */
export function redactionNotice(producer: string, label: Label): string {
  return `[airlock withheld content from ${producer}: ${formatLabel(label)}. `
    + `The step continues without it.]`
}

/**
 * Rewrite one message, keeping its identity.
 *
 * The entered batch is authoritative, so a rewritten message must remain the
 * same message. Every field but `content` is carried over unchanged, which
 * preserves `id` and `source` whatever else the harness attached to it.
 *
 * @param message - the message to rewrite.
 * @param producer - its producer name.
 * @param label - the label that crossed the threshold.
 * @returns a new message carrying only the notice.
 */
function withNotice(message: Message, producer: string, label: Label): Message {
  return { ...message, content: [{ type: 'text', text: redactionNotice(producer, label) }] }
}

/**
 * Redact the entering messages a policy classifies at or above its threshold.
 * @param messages - the messages entering the step.
 * @param policy - the policy bits.
 * @returns the rewritten batch, or `undefined` when nothing changed.
 */
export function redactEntering(
  messages: readonly Message[],
  policy: PreStepPolicy = {},
): readonly Message[] | undefined {
  const threshold = policy.redactAtOrAbove ?? 'secret'
  const redacted: Message[] = []
  let changed = false

  for (const message of messages) {
    const label = enteringLabel(message, policy)
    if (!sensitivityAtLeast(label, threshold)) {
      redacted.push(message)
      continue
    }
    redacted.push(withNotice(message, producerName(message.source), label))
    changed = true
  }

  return changed ? redacted : undefined
}

/**
 * Report which entering messages a policy would redact.
 *
 * Exposed for logging and for evidence. It reads the same classification the
 * gate acts on, so a dry run and an enforcing run agree.
 *
 * @param payload - the pre-step payload.
 * @param policy - the policy bits.
 * @returns one entry per message the gate would rewrite.
 */
export function plannedRedactions(
  payload: PreStepPayload,
  policy: PreStepPolicy = {},
): readonly Redaction[] {
  const threshold = policy.redactAtOrAbove ?? 'secret'
  const planned: Redaction[] = []

  for (const message of payload.messages ?? []) {
    const label = enteringLabel(message, policy)
    if (!sensitivityAtLeast(label, threshold)) continue
    planned.push({
      ...message.id === undefined ? {} : { id: message.id },
      producer: producerName(message.source),
      label,
    })
  }

  return planned
}

/**
 * Decide whether the step must not run at all.
 *
 * The condition is read against the session's context label, which is the same
 * label Gate A denies over. A session with no observed history abstains, for
 * the reason Gate A abstains: the gate acts on evidence, and it has none.
 *
 * @param payload - the pre-step payload.
 * @param ledger - the label ledger.
 * @param policy - the policy bits.
 * @returns the reason to reject, or `undefined` when the step may run.
 */
export function rejectionReason(
  payload: PreStepPayload,
  ledger: Ledger,
  policy: PreStepPolicy = {},
): string | undefined {
  const condition = policy.reject
  if (condition === undefined) return undefined
  if (condition.trust === undefined && condition.sensitivity === undefined) return undefined

  const sessionId = payload.agent?.id
  if (sessionId === undefined) return undefined
  const session = ledger.peek(sessionId)
  if (session === undefined) return undefined

  const context = session.contextLabel()
  if (condition.trust !== undefined && !trustAtLeast(context.label, condition.trust)) {
    return undefined
  }
  if (condition.sensitivity !== undefined
    && !sensitivityAtLeast(context.label, condition.sensitivity)) {
    return undefined
  }

  // The axis the condition named owns the explanation. A condition that names
  // both is explained by its sensitivity, which is the narrower statement.
  const origin = condition.sensitivity === undefined
    ? context.trustOrigin
    : context.sensitivityOrigin ?? context.trustOrigin
  const from = origin === undefined ? 'this step\'s context' : origin.description

  return [
    `airlock rejected this step by configured policy.`,
    `This session's context is ${formatLabel(context.label)}, from ${from}.`,
    `The restriction follows the data in context, not the wording of the request.`,
  ].join(' ')
}

/**
 * Evaluate Gate B over the payload alone.
 *
 * Pure, and testable without the waterfall. A caller that drives the seam
 * itself should prefer {@link applyPreStep}, because the loop's own `next()`
 * appends the projected runtime context to the batch and this function cannot
 * see it.
 *
 * @param payload - the pre-step payload.
 * @param ledger - the label ledger.
 * @param policy - the policy bits.
 * @returns `reject`, or `enter` with the batch the step should run on.
 */
export function evaluatePreStep(
  payload: PreStepPayload,
  ledger: Ledger,
  policy: PreStepPolicy = {},
): PreStepDecision {
  if (rejectionReason(payload, ledger, policy) !== undefined) return { kind: 'reject' }
  const messages = payload.messages ?? []
  return { kind: 'enter', messages: redactEntering(messages, policy) ?? messages }
}

/**
 * Drive the `agent/pre-step` waterfall.
 *
 * Rejection is decided before `next()` runs, because a rejected step should not
 * pay for the work downstream listeners do. Redaction is applied after `next()`
 * returns, so the batch this gate rewrites is the batch the step will actually
 * enter, including the runtime context the loop appended.
 *
 * An internal failure passes the step through unchanged. That direction is
 * deliberate: Gate A still stands at the tool boundary and denies there on the
 * same labels, so a bug in this file degrades one layer rather than ending a
 * turn the policy never asked to end.
 *
 * @param payload - the pre-step payload.
 * @param next - the downstream waterfall.
 * @param ledger - the label ledger.
 * @param policy - the policy bits.
 * @returns the decision to hand back to the harness.
 */
export async function applyPreStep(
  payload: PreStepPayload,
  next: () => Promise<PreStepDecision>,
  ledger: Ledger,
  policy: PreStepPolicy = {},
): Promise<PreStepDecision> {
  let rejected: string | undefined
  try {
    rejected = rejectionReason(payload, ledger, policy)
  } catch {
    // Contain the failure and let the step run. See the note above.
    rejected = undefined
  }
  if (rejected !== undefined) return { kind: 'reject' }

  const decision = await next()
  try {
    if (decision.kind !== 'enter') return decision
    const redacted = redactEntering(decision.messages, policy)
    return redacted === undefined ? decision : { kind: 'enter', messages: redacted }
  } catch {
    // The downstream decision is still valid. Return it untouched.
    return decision
  }
}
