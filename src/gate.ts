/**
 * Gate A — the capability gate.
 *
 * Registered through `ctx.tools.guard()`, which runs after the whole
 * reorderable `tools/pre-execute` waterfall and can only reduce permission. No
 * later listener can turn a denial here back into an allow, and no ordering of
 * other plugins can either. Every other guard in the ecosystem registers on the
 * reorderable seam instead.
 *
 * The guard is synchronous by contract, so it reads the in-memory ledger and
 * never awaits anything.
 */

import type { ToolExecution } from './dsh.js'
import type { ContextLabel, Ledger } from './ledger.js'
import { formatLabel } from './labels.js'
import type { Capability, CapabilityClasses, Rule } from './policy.js'
import { classify } from './policy.js'

/** What the gate classifies with. */
export interface GateOptions {
  /**
   * The class lists a tool is classified against. Defaults to the built-in
   * classes. A deployment that reclassifies a tool in its policy must pass its
   * own lists here, or the gate would judge the call against the wrong
   * capability and silently permit what the policy meant to stop.
   */
  readonly classes?: CapabilityClasses
}

/** What the gate decided about one call. */
export interface Decision {
  readonly tool: string
  readonly callId: string
  readonly capabilities: readonly Capability[]
  readonly context: ContextLabel
  /** The rule that denied the call, or `undefined` when the gate abstained. */
  readonly rule?: Rule
  /** The message handed back to the harness, present only on a denial. */
  readonly reason?: string
}

/**
 * Compose the denial message.
 *
 * The message names the rule, the origin event, and the fact that rephrasing
 * will not help. That last sentence is the whole point of the project: the
 * restriction is a fact about the session's history, not about the wording of
 * the command, so a model that retries with `wget` meets the identical denial.
 *
 * @param tool - the tool that was denied.
 * @param rule - the rule that fired.
 * @param context - the step's context label and its origins.
 * @returns the reason string the harness reports.
 */
export function denialMessage(tool: string, rule: Rule, context: ContextLabel): string {
  const origin = rule.id === 'secret-no-egress'
    ? context.sensitivityOrigin
    : context.trustOrigin
  const from = origin === undefined ? 'this step\'s context' : origin.description
  return [
    `airlock denied \`${tool}\` by rule ${rule.id}: ${rule.rationale}.`,
    `This step's context is ${formatLabel(context.label)}, from ${from}.`,
    `The restriction follows the data in context, not the wording of the call,`,
    `so another tool or another encoding reaches the same denial.`,
  ].join(' ')
}

/**
 * Evaluate the gate for one call.
 * @param exec - the pipeline's view of the call.
 * @param ledger - the label ledger.
 * @param rules - the rules to apply.
 * @returns the decision, whose `reason` is set only when a rule denied.
 */
export function evaluate(
  exec: ToolExecution,
  ledger: Ledger,
  rules: readonly Rule[],
  options: GateOptions = {},
): Decision {
  const capabilities = [...classify(exec.name, options.classes)]
  const sessionId = exec.agent?.id
  const session = sessionId === undefined ? undefined : ledger.peek(sessionId)

  // No ledger means no observed history for this session. Abstaining is
  // correct: the gate denies on evidence, and it has none.
  if (session === undefined) {
    return {
      tool: exec.name,
      callId: exec.callId,
      capabilities,
      context: { label: { trust: 'user', sensitivity: 'public' } },
    }
  }

  const context = session.contextLabel()

  for (const rule of rules) {
    if (!capabilities.includes(rule.capability)) continue
    if (!rule.matches(context.label)) continue
    return {
      tool: exec.name,
      callId: exec.callId,
      capabilities,
      context,
      rule,
      reason: denialMessage(exec.name, rule, context),
    }
  }

  return { tool: exec.name, callId: exec.callId, capabilities, context }
}
