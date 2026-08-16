/**
 * dsh-airlock — provenance-gated tool use.
 *
 * The plugin labels every piece of content entering the agent's context by
 * where it came from, propagates those labels through the session's own
 * lineage records, and decides over the labels. It matches no argument
 * strings, because argument strings are what a model reformulates.
 *
 * Five seams carry the decisions:
 *
 *   ctx.tools.guard()    the monotonic denial no later listener can undo
 *   tools/pre-execute    the ask, routed by the harness through ctx.approval
 *   tools/post-execute   withholding a secret, and framing untrusted data
 *   agent/pre-step       redaction of content entering a step
 *   llm/stream           an opt-in last-resort refusal at the provider
 *
 * A sixth seam carries no decision and only observes. The approval service
 * appends a durable, log-only `approval/asked` and `approval/decided` pair
 * around every question it services, and both reach `session/event`. That pair
 * is the only way this plugin learns how a human answered its own ask, because
 * the harness resolves an ask after the whole `tools/pre-execute` waterfall has
 * returned. An `allowed-once` on a question this plugin raised becomes a
 * recorded clearance; see `declassify.ts`. Verified against dsh 0.1.0-rc.5 at
 * `packages/interaction/user-approval/src/index.ts`.
 */

import type { Context } from '@deepseek-ai/cordis'
import type {
  Agent,
  GenerateOptions,
  PostToolDecision,
  PreStepDecision,
  PreStepPayload,
  PreToolDecision,
  Session,
  SessionEvent,
  StreamChunk,
  ToolExecution,
  ToolExecutionResult,
} from './dsh.js'
import { approvalService, listen, toolRuntime } from './dsh.js'
import { evaluateAskDetail, postureHint } from './ask.js'
import { backstopStream } from './backstop.js'
import type { BackstopPolicy } from './backstop.js'
import { loadPolicy } from './config.js'
import {
  APPROVAL_ASKED_EVENT,
  APPROVAL_DECIDED_EVENT,
  APPROVAL_GRANTED_OUTCOME,
  AskCorrelator,
  Declassifier,
  declassificationRecord,
  describeGrant,
} from './declassify.js'
import type { AirlockAsk } from './declassify.js'
import { EvidenceSink, decisionRecord } from './evidence.js'
import type { Outcome } from './evidence.js'
import { evaluate } from './gate.js'
import type { Label } from './labels.js'
import { Ledger, resultLabelFor } from './ledger.js'
import type { ContextLabel } from './ledger.js'
import { applyPreStep } from './prestep.js'
import { APPROVAL_SEAM, GUARD_SEAM, PROVIDER_SEAM, selectRules } from './policy.js'
import type { Capability, Policy } from './policy.js'
import { decideResult } from './results.js'

export type { Capability, Effect, Boundary, Posture, Policy, Rule } from './policy.js'
export type { PolicyConfig, LoadPolicyOptions } from './config.js'
export type { ContextLabel, LabelledNode, Provenance, ResultLabel } from './ledger.js'
export type { Decision } from './gate.js'
export type { Label, Sensitivity, Trust } from './labels.js'
export type { DecisionRecord, Outcome } from './evidence.js'
export type { AirlockAsk, Grant } from './declassify.js'
export type { PreStepPolicy, PreStepRejection } from './prestep.js'
export type { BackstopPolicy, BackstopRule } from './backstop.js'
export type { BackstopConfig, PreStepConfig } from './config.js'
export type { BackstopSettings } from './policy.js'

export { BOTTOM, formatLabel, join, joinAll } from './labels.js'
export { Ledger, SessionLedger, resultLabelFor } from './ledger.js'
export { classify, selectRules, DEFAULT_POLICY, DEFAULT_RULES, DEFAULT_SECRET_PATHS } from './policy.js'
export { loadPolicy, policyFromConfig, validateConfig, PolicyConfigError } from './config.js'
export { denialMessage, evaluate } from './gate.js'
export { evaluateAsk, evaluateAskDetail, postureHint, resolvePosture } from './ask.js'
export { AskCorrelator, Declassifier } from './declassify.js'
export { decideResult, normaliseUntrustedText } from './results.js'
export { evaluatePreStep, applyPreStep } from './prestep.js'
export { shouldBlockRequest, backstopStream } from './backstop.js'
export { EvidenceSink, JsonlSink, verifyChain } from './evidence.js'

export const name = 'dsh-airlock'

/**
 * Plugin configuration.
 *
 * Every key is optional and the defaults need no configuration file. The
 * validated shape lives in `config.ts`; a typo fails the plugin load rather
 * than silently disabling a rule.
 */
export type { PolicyConfig as Config } from './config.js'

/** A parsed-argument view of a call, for the intrinsic result label. */
function callArguments(exec: ToolExecution): Record<string, unknown> | undefined {
  const args = exec.arguments
  if (typeof args !== 'object' || args === null || Array.isArray(args)) return undefined
  return args as Record<string, unknown>
}

/**
 * Mount the plugin.
 *
 * The load is asynchronous because a workspace policy file may have to be
 * read. A malformed policy throws here, at load, which is the one place this
 * plugin is allowed to be loud: a policy that silently does not apply is worse
 * than a deployment that refuses to start.
 *
 * @param ctx - the cordis context the plugin is loaded into.
 * @param config - the plugin configuration from the mount.
 */
export async function apply(ctx: Context, config: unknown = {}): Promise<void> {
  const policy: Policy = await loadPolicy(config)

  const report = (error: unknown): void => {
    try {
      ctx.logger.warn(error)
    } catch {
      // The logger is unavailable. Drop the report.
    }
  }

  const ledger = new Ledger({
    secretPaths: policy.secretPaths,
    untrustedSources: policy.untrustedSources,
  })
  const declassifier = new Declassifier({ allow: policy.declassify.allow })
  const asks = new AskCorrelator()
  const evidence = new EvidenceSink({
    path: policy.evidence.path,
    jsonl: policy.evidence.jsonl,
    otlp: policy.evidence.otlp,
    report,
  })

  const guardRules = selectRules(policy, GUARD_SEAM)
  const askRules = selectRules(policy, APPROVAL_SEAM)
  const providerRules = selectRules(policy, PROVIDER_SEAM)

  /**
   * Record one decision. Evidence is a by-product of deciding, so a failure to
   * record must never change what was decided.
   */
  const record = (fields: {
    sessionId: string
    tool: string
    callId?: string
    capabilities: readonly Capability[]
    outcome: Outcome
    label: Label
    rule?: string
    origin?: string
  }): void => {
    try {
      evidence.emit(decisionRecord(fields))
    } catch (error) {
      report(error)
    }
  }

  /** The origin line for whichever axis a rule constrained. */
  const originOf = (context: ContextLabel, ruleId: string | undefined): string | undefined => {
    const rule = policy.rules.find((candidate) => candidate.id === ruleId)
    const bySensitivity = rule?.when?.sensitivity !== undefined
    const provenance = bySensitivity ? context.sensitivityOrigin : context.trustOrigin
    return (provenance ?? context.trustOrigin ?? context.sensitivityOrigin)?.description
  }

  /**
   * Turn one approved airlock ask into a recorded clearance.
   *
   * The harness's own grant is one-shot and the plugin never sees it as a
   * return value, so this is where an approval becomes something that outlives
   * the call: a session-scoped grant over the capability class and the label the
   * human was shown, narrowed to the one tool they approved.
   *
   * @param ask - the question the approval answered.
   */
  const grantFromApproval = (ask: AirlockAsk): void => {
    const grant = declassifier.grant(ask.sessionId, {
      capability: ask.capability,
      tool: ask.tool,
      label: ask.label,
      actor: 'the approval answerer',
      reason: `approved the airlock ask about \`${ask.tool}\``,
      callId: ask.callId,
      ...ask.rule === undefined ? {} : { rule: ask.rule },
    })
    // Declassification is disabled, or the store refused. Either way the rule
    // that raised the question stays in force.
    if (grant === undefined) return
    try {
      evidence.emit(declassificationRecord(grant, {
        tool: ask.tool,
        capabilities: ask.capabilities,
        callId: ask.callId,
      }))
    } catch (error) {
      report(error)
    }
  }

  /**
   * Observe the approval audit pair on the session log.
   *
   * `approval/asked` and `approval/decided` are durable and log-only, so they
   * never reach the model transcript and nothing here reads model output. The
   * attribution rules that decide whether an approval is this plugin's live in
   * {@link AskCorrelator}.
   *
   * @param sessionId - the session the event was appended to.
   * @param event - the event, exactly as the session log recorded it.
   */
  const observeApproval = (sessionId: string, event: SessionEvent): void => {
    if (event.type === APPROVAL_ASKED_EVENT) {
      asks.asked(sessionId, event.data)
      return
    }
    if (event.type !== APPROVAL_DECIDED_EVENT) return

    const data = event.data as { id?: unknown; outcome?: unknown } | undefined
    const id = data?.id
    if (typeof id !== 'string' || id.length === 0) return

    // Take the entry whatever the outcome was: a question is answered once.
    const ask = asks.resolve(sessionId, id)
    if (ask === undefined) return
    // `rejected`, `cancelled`, and `unavailable` clear nothing.
    if (data?.outcome !== APPROVAL_GRANTED_OUTCOME) return
    grantFromApproval(ask)
  }

  listen(ctx, 'session/event', (session: Session, event: SessionEvent) => {
    try {
      ledger.for(session.id).apply(event)
    } catch (error) {
      // A ledger failure must not take the agent loop down. The gate then reads
      // a stale index, which can only over-approximate.
      report(error)
    }
    try {
      observeApproval(session.id, event)
    } catch (error) {
      // A failure to notice an approval costs the operator a repeated question,
      // which is the direction that leaves the restriction standing.
      report(error)
    }
  })

  const forget = (id: string | undefined): void => {
    if (id === undefined) return
    ledger.drop(id)
    // A clearance must not outlive the session a human granted it in.
    declassifier.drop(id)
    asks.drop(id)
  }

  listen(ctx, 'session/disposed', (session: Session) => forget(session.id))
  listen(ctx, 'agent/disposed', (payload: { agent?: Agent }) => forget(payload.agent?.id))

  installGates()

  ctx.logger.debug(
    'airlock ready, posture %c, %c deny rules, %c ask rules, dry run %c',
    policy.posture,
    guardRules.length,
    askRules.length,
    policy.dryRun,
  )

  function installGates(): void {
    const tools = toolRuntime(ctx)

    if (tools === undefined) {
      ctx.logger.warn('no tool runtime on the context, the capability gates are not installed')
    } else {
      // Gate A. Monotonic and final: no later listener can revive this denial.
      const dispose = tools.guard((exec: ToolExecution): string | undefined => {
        try {
          const decision = evaluate(exec, ledger, guardRules, { classes: policy.classes })
          if (decision.reason === undefined) return undefined

          const sessionId = exec.agent?.id ?? 'unknown'
          const clearance = declassifier.find(sessionId, {
            capability: decision.rule?.capability ?? 'egress',
            tool: exec.name,
            label: decision.context.label,
          })

          if (clearance !== undefined) {
            record({
              sessionId,
              tool: exec.name,
              callId: exec.callId,
              capabilities: decision.capabilities,
              outcome: 'declassify',
              label: decision.context.label,
              // The origin of a declassification is the human who granted it.
              origin: describeGrant(clearance),
              ...decision.rule === undefined ? {} : { rule: decision.rule.id },
            })
            return undefined
          }

          record({
            sessionId,
            tool: exec.name,
            callId: exec.callId,
            capabilities: decision.capabilities,
            outcome: policy.dryRun ? 'allow' : 'deny',
            label: decision.context.label,
            ...decision.rule === undefined ? {} : { rule: decision.rule.id },
            ...originOf(decision.context, decision.rule?.id) === undefined
              ? {}
              : { origin: originOf(decision.context, decision.rule?.id)! },
          })

          if (policy.dryRun) {
            ctx.logger.info('dry run, would deny: %s', decision.reason)
            return undefined
          }

          ctx.logger.info(decision.reason)
          return decision.reason
        } catch (error) {
          // A guard that throws must not become a guard that allows, but it also
          // cannot deny what it failed to judge. Abstain and report: Gate A is
          // one layer, and the pre-execute gate still ran.
          report(error)
          return undefined
        }
      })
      ctx.effect(() => dispose, 'dsh-airlock: capability gate')

      // The ask. The harness routes it through ctx.approval after this
      // waterfall and degrades it to a denial when no approver is mounted.
      listen(ctx, 'tools/pre-execute', async (
        exec: ToolExecution,
        next: () => Promise<PreToolDecision>,
      ): Promise<PreToolDecision> => {
        try {
          const hint = postureHint(approvalService(ctx))
          const evaluation = evaluateAskDetail(exec, ledger, askRules, {
            posture: policy.posture,
            ...hint === undefined ? {} : { hint },
            classes: policy.classes,
            declassification: declassifier,
          })

          if (evaluation.abstained) return next()

          const sessionId = exec.agent?.id ?? 'unknown'
          // A matched rule that did not ask either refused, was excepted by an
          // `allow`, or was answered by a live clearance. The record names which
          // one, because a clearance recorded as a denial is a false audit line.
          const outcome: Outcome = evaluation.decision.kind === 'ask'
            ? 'ask'
            : evaluation.decision.kind === 'deny'
              ? 'deny'
              : evaluation.declassifiedBy === undefined ? 'allow' : 'declassify'

          if (policy.dryRun) {
            ctx.logger.info('dry run, would %s: %s', outcome, evaluation.tool)
            return next()
          }

          record({
            sessionId,
            tool: exec.name,
            callId: exec.callId,
            capabilities: evaluation.capabilities,
            outcome,
            label: evaluation.context.label,
            ...evaluation.rule === undefined ? {} : { rule: evaluation.rule.id },
          })

          // Remember what was asked, so the approval this raises can be
          // recognised as ours when it lands on the session log.
          if (evaluation.decision.kind === 'ask'
            && evaluation.decision.reason !== undefined
            && evaluation.rule !== undefined) {
            asks.raised({
              sessionId,
              tool: exec.name,
              callId: exec.callId,
              capability: evaluation.rule.capability,
              capabilities: evaluation.capabilities,
              label: evaluation.context.label,
              reason: evaluation.decision.reason,
              rule: evaluation.rule.id,
            })
          }

          return evaluation.decision
        } catch (error) {
          report(error)
          return next()
        }
      })

      // Withholding a secret, and framing untrusted data as data.
      listen(ctx, 'tools/post-execute', async (
        exec: ToolExecution,
        result: ToolExecutionResult,
        next: () => Promise<PostToolDecision>,
      ): Promise<PostToolDecision> => {
        try {
          const sessionId = exec.agent?.id ?? 'unknown'
          const resolved = resultLabelFor(exec.name, callArguments(exec), {
            secretPaths: policy.secretPaths,
            untrustedSources: policy.untrustedSources,
          })
          const cleared = declassifier.isDeclassified(sessionId, {
            capability: 'read',
            tool: exec.name,
            label: resolved.label,
          })

          const decision = decideResult(exec, result, {
            label: resolved.label,
            ...resolved.matchedGlob === undefined ? {} : { matchedGlob: resolved.matchedGlob },
            ...resolved.path === undefined ? {} : { path: resolved.path },
            declassified: cleared,
          }, {
            untrustedSources: policy.untrustedSources,
            allowDeclassified: policy.declassify.allow,
          })

          if (decision.kind === 'block') {
            if (policy.dryRun) {
              ctx.logger.info('dry run, would withhold the result of %s', exec.name)
              return next()
            }
            record({
              sessionId,
              tool: exec.name,
              callId: exec.callId,
              capabilities: ['read'],
              outcome: 'redact',
              label: resolved.label,
              ...resolved.matchedGlob === undefined ? {} : { origin: resolved.matchedGlob },
            })
          }

          return decision
        } catch (error) {
          report(error)
          return next()
        }
      })
    }

    // Gate B. It sees only the messages entering this step, never history.
    listen(ctx, 'agent/pre-step', async (
      payload: PreStepPayload,
      next: () => Promise<PreStepDecision>,
    ): Promise<PreStepDecision> => {
      try {
        return await applyPreStep(payload, next, ledger, policy.preStep)
      } catch (error) {
        report(error)
        return next()
      }
    })

    // The provider backstop. Disabled unless the policy arms it, and armed by
    // the operator's own rules rather than by a default threshold: a rule
    // written `when: {trust: untrusted, boundary: provider}` blocks on trust,
    // which is what it says.
    const backstop: BackstopPolicy = {
      enabled: providerRules.length > 0,
      rules: providerRules,
      auxiliary: policy.backstop.auxiliary,
    }
    listen(ctx, 'llm/stream', (
      options: GenerateOptions,
      next: () => AsyncIterable<StreamChunk>,
    ): AsyncIterable<StreamChunk> => {
      try {
        return backstopStream(options, next, ledger, backstop)
      } catch (error) {
        report(error)
        return next()
      }
    })
  }
}
