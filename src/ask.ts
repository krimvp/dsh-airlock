/**
 * Gate B — the ask posture.
 *
 * Registered on the reorderable `tools/pre-execute` waterfall, which is the
 * only seam that can raise a question. It turns a policy `ask` effect into
 * `{kind:'ask'}` and lets the harness service it: the registry resolves an ask
 * through `ctx.approval` after the whole waterfall has run, and degrades it to
 * a denial when no approval service is mounted or when the call carries no
 * agent (verified against `packages/core/tools/src/index.ts` at 0.1.0-rc.6).
 * This module never calls approval itself.
 *
 * The approval request carries no tool arguments. An answerer sees the tool
 * name, the optional call id, and this module's `reason` string, so the reason
 * has to be self-contained: it names the rule, the label, and the origin event,
 * exactly as the denial message does.
 *
 * A harness grant is one-shot. Anything longer lives in `declassify.ts`, and
 * this module consults it through the synchronous {@link DeclassificationLookup}.
 *
 * Nothing here decides over an argument string or over tool output. The inputs
 * are the tool's capability classes, the context label, and the rule list.
 */

import type { DeclassificationLookup, GrantQuery } from './declassify.js'
import type { ApprovalService, PreToolDecision, ToolExecution } from './dsh.js'
import { formatLabel } from './labels.js'
import type { ContextLabel, Ledger, Provenance } from './ledger.js'
import type { Capability, CapabilityClasses, Posture, Rule } from './policy.js'
import { classify } from './policy.js'

/**
 * The harness's own approval policy.
 *
 * Derived from {@link ApprovalService} rather than restated, so a change to the
 * local structural copy of the harness type reaches this module too. `'never'`
 * is the harness's explicit declaration that no human will be asked.
 */
export type ApprovalPolicy = NonNullable<NonNullable<ApprovalService['config']>['policy']>

/** The context label used when the plugin has observed no history for a session. */
const CLEAN_CONTEXT: ContextLabel = { label: { trust: 'user', sensitivity: 'public' } }

/** How the ask seam is evaluated. */
export interface AskOptions {
  /**
   * What an `ask` becomes.
   *
   * There is no API that reports whether a human is present, so this is
   * configuration rather than detection. The caller passes the operator's
   * choice, optionally lowered by {@link postureHint}.
   */
  readonly posture: Posture
  /**
   * A posture the deployment implies, from {@link postureHint}. It can only
   * lower the configured posture, never raise it.
   */
  readonly hint?: Posture
  /** The class lists to classify the tool with. Defaults to the built-in classes. */
  readonly classes?: CapabilityClasses
  /**
   * Session-scoped clearances. A live grant answers the question the rule would
   * have raised, so the call proceeds without asking again.
   */
  readonly declassification?: DeclassificationLookup
}

/** What the ask seam decided about one call, with the material an audit record needs. */
export interface AskEvaluation {
  readonly tool: string
  readonly callId: string
  readonly capabilities: readonly Capability[]
  readonly context: ContextLabel
  /** The rule that matched, or `undefined` when none did. */
  readonly rule?: Rule
  /** The posture that was actually in force. */
  readonly posture: Posture
  /**
   * `true` when no rule matched, so the plugin has no opinion at this seam. The
   * decision is `allow`, which is what `next()` would have produced; a caller
   * on the waterfall should call `next()` instead, to leave the rest of the
   * chain its turn.
   */
  readonly abstained: boolean
  /** The id of the grant that cleared the call, when one did and it can name itself. */
  readonly declassifiedBy?: string
  /** What the seam returns to the harness. */
  readonly decision: PreToolDecision
}

/**
 * Derive a posture from the harness's own approval configuration.
 *
 * This is not a detection of whether a human is present; the harness exposes
 * nothing that reports that, and this plugin claims nothing it cannot check.
 * Two facts are checkable and both mean the same thing for an ask:
 * `ctx.approval` is absent, so no ask can be routed anywhere; or the service is
 * configured `'never'`, which is the harness's own statement that every ask
 * resolves `rejected` without reaching an answerer.
 *
 * The result only ever lowers the configured posture. See
 * {@link resolvePosture}.
 *
 * @param approval - the approval service, or `undefined` when none is mounted.
 * @returns `'deny'` when no human will be asked, or `undefined` when the
 *   deployment implies nothing.
 */
export function postureHint(approval: ApprovalService | undefined): Posture | undefined {
  if (approval === undefined) return 'deny'
  try {
    const policy: ApprovalPolicy | undefined = approval.config?.policy
    return policy === 'never' ? 'deny' : undefined
  } catch {
    // A harness compatibility break must degrade this plugin rather than crash
    // it. An unreadable configuration implies nothing.
    return undefined
  }
}

/**
 * Resolve the posture in force for one evaluation.
 * @param configured - the operator's posture.
 * @param hint - what the deployment implies, from {@link postureHint}.
 * @returns the posture to enforce; `'deny'` when either says so.
 */
export function resolvePosture(configured: Posture, hint?: Posture): Posture {
  if (configured === 'deny' || hint === 'deny') return 'deny'
  return 'ask'
}

/**
 * Pick the origin the rule is actually about.
 *
 * A rule that constrains sensitivity is answered by the node that raised
 * sensitivity; a rule that constrains trust is answered by the node that raised
 * trust. A rule that constrains neither takes whichever origin the context has.
 *
 * @param rule - the rule that matched.
 * @param context - the step's context label and its origins.
 * @returns the provenance to cite, or `undefined` when the context has none.
 */
function originFor(rule: Rule, context: ContextLabel): Provenance | undefined {
  if (rule.when.sensitivity !== undefined && context.sensitivityOrigin !== undefined) {
    return context.sensitivityOrigin
  }
  if (rule.when.trust !== undefined && context.trustOrigin !== undefined) {
    return context.trustOrigin
  }
  return context.trustOrigin ?? context.sensitivityOrigin
}

/**
 * Compose the message the answerer reads.
 *
 * The approval request carries no tool arguments, so everything the answerer
 * needs is in this string: which tool, which rule and why, what the context
 * label is, where that label came from, and that a grant covers this one call.
 * The last sentence is the same point the denial message makes — the
 * restriction is a fact about the session's history rather than about the
 * wording of the command.
 *
 * @param tool - the tool the question is about.
 * @param rule - the rule that fired.
 * @param context - the step's context label and its origins.
 * @returns the reason string the harness carries to the answerer.
 */
export function approvalMessage(tool: string, rule: Rule, context: ContextLabel): string {
  const origin = originFor(rule, context)
  const from = origin === undefined ? 'this step\'s context' : origin.description
  return [
    `airlock asks before \`${tool}\` by rule ${rule.id}: ${rule.rationale}.`,
    `This step's context is ${formatLabel(context.label)}, from ${from}.`,
    `Approving covers this one call.`,
    `The restriction follows the data in context, not the wording of the call,`,
    `so another tool or another encoding reaches the same question.`,
  ].join(' ')
}

/**
 * Compose the message a refused question reports.
 *
 * Under the `deny` posture nobody is present to consent, so the seam refuses
 * rather than asking. The message says which posture refused, because an
 * operator who sees this line in a headless run needs to know the posture is
 * the reason and not the rule.
 *
 * @param tool - the tool that was refused.
 * @param rule - the rule that fired.
 * @param context - the step's context label and its origins.
 * @returns the reason string the harness reports.
 */
export function refusalMessage(tool: string, rule: Rule, context: ContextLabel): string {
  const origin = originFor(rule, context)
  const from = origin === undefined ? 'this step\'s context' : origin.description
  return [
    `airlock denied \`${tool}\` by rule ${rule.id}: ${rule.rationale}.`,
    `This step's context is ${formatLabel(context.label)}, from ${from}.`,
    `The rule asks for a human and the configured posture is deny,`,
    `so the call is refused rather than approved unattended.`,
  ].join(' ')
}

/**
 * Evaluate the ask seam for one call, with the material an audit record needs.
 *
 * The ledger lookup, the abstain-when-no-history behaviour, and the
 * first-match-wins ordering are the ones Gate A uses, so the two seams agree
 * about what one ordered rule list means.
 *
 * The first matching rule decides. An `ask` becomes an ask or a denial
 * depending on the posture, an `allow` stops evaluation, and any other effect
 * belongs to another seam and is left to it — this seam returns `allow`, which
 * takes no permission away, because the monotonic guard still runs after the
 * whole waterfall.
 *
 * @param exec - the pipeline's view of the call.
 * @param ledger - the label ledger.
 * @param rules - the rules this seam enforces, in evaluation order.
 * @param options - the posture and the optional clearance store.
 * @returns the decision and what it was made from.
 */
export function evaluateAskDetail(
  exec: ToolExecution,
  ledger: Ledger,
  rules: readonly Rule[],
  options: AskOptions,
): AskEvaluation {
  const capabilities = [...classify(exec.name, options.classes)]
  const posture = resolvePosture(options.posture, options.hint)
  const sessionId = exec.agent?.id
  const session = sessionId === undefined ? undefined : ledger.peek(sessionId)

  // No ledger means no observed history for this session. Abstaining is
  // correct: the seam raises a question on evidence, and it has none. A call
  // with no agent lands here too, which is also where the harness would send
  // it — an ask with no agent to route it through degrades to a denial.
  if (session === undefined || sessionId === undefined) {
    return {
      tool: exec.name,
      callId: exec.callId,
      capabilities,
      context: CLEAN_CONTEXT,
      posture,
      abstained: true,
      decision: { kind: 'allow' },
    }
  }

  const context = session.contextLabel()

  for (const rule of rules) {
    if (!capabilities.includes(rule.capability)) continue
    if (!rule.matches(context.label)) continue

    if (rule.effect === 'allow') {
      return {
        tool: exec.name,
        callId: exec.callId,
        capabilities,
        context,
        rule,
        posture,
        abstained: false,
        decision: { kind: 'allow' },
      }
    }

    if (rule.effect !== 'ask') {
      // Another seam enforces this rule. Taking no permission away here leaves
      // the monotonic guard to do it.
      return {
        tool: exec.name,
        callId: exec.callId,
        capabilities,
        context,
        rule,
        posture,
        abstained: true,
        decision: { kind: 'allow' },
      }
    }

    const query: GrantQuery = {
      capability: rule.capability,
      label: context.label,
      tool: exec.name,
    }
    const lookup = options.declassification
    if (lookup?.isDeclassified(sessionId, query) === true) {
      const grant = lookup.find?.(sessionId, query)
      return {
        tool: exec.name,
        callId: exec.callId,
        capabilities,
        context,
        rule,
        posture,
        abstained: false,
        ...grant === undefined ? {} : { declassifiedBy: grant.id },
        decision: { kind: 'allow' },
      }
    }

    return {
      tool: exec.name,
      callId: exec.callId,
      capabilities,
      context,
      rule,
      posture,
      abstained: false,
      decision: posture === 'ask'
        ? { kind: 'ask', reason: approvalMessage(exec.name, rule, context) }
        : { kind: 'deny', reason: refusalMessage(exec.name, rule, context) },
    }
  }

  return {
    tool: exec.name,
    callId: exec.callId,
    capabilities,
    context,
    posture,
    abstained: true,
    decision: { kind: 'allow' },
  }
}

/**
 * Evaluate the ask seam for one call.
 * @param exec - the pipeline's view of the call.
 * @param ledger - the label ledger.
 * @param rules - the rules this seam enforces, in evaluation order.
 * @param options - the posture and the optional clearance store.
 * @returns what the seam returns to the harness.
 */
export function evaluateAsk(
  exec: ToolExecution,
  ledger: Ledger,
  rules: readonly Rule[],
  options: AskOptions,
): PreToolDecision {
  return evaluateAskDetail(exec, ledger, rules, options).decision
}
