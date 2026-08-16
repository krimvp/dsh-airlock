/**
 * dsh-airlock — provenance-gated tool use.
 *
 * The plugin labels every piece of content entering the agent's context by
 * where it came from, propagates those labels through the session's own
 * lineage records, and denies capabilities over the labels. It matches no
 * argument strings, because argument strings are what a model reformulates.
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent, Session, SessionEvent, ToolExecution } from './dsh.js'
import { listen, toolRuntime } from './dsh.js'
import { evaluate } from './gate.js'
import { Ledger } from './ledger.js'
import { DEFAULT_RULES, DEFAULT_SECRET_PATHS } from './policy.js'

export type { Capability, Rule } from './policy.js'
export type { ContextLabel, LabelledNode, Provenance } from './ledger.js'
export type { Decision } from './gate.js'
export type { Label, Sensitivity, Trust } from './labels.js'
export { BOTTOM, formatLabel, join, joinAll } from './labels.js'
export { Ledger, SessionLedger } from './ledger.js'
export { classify, DEFAULT_RULES, DEFAULT_SECRET_PATHS } from './policy.js'
export { denialMessage, evaluate } from './gate.js'

export const name = 'dsh-airlock'

/** Plugin configuration. The first milestone deliberately ships almost none. */
export interface Config {
  /**
   * Globs whose contents are labelled `secret` when a tool reads them.
   * Defaults to {@link DEFAULT_SECRET_PATHS}.
   */
  secretPaths?: string[]
  /**
   * `true` logs what the gate would have denied without denying it. Use it to
   * measure over-blocking against a real workload before enforcing.
   */
  dryRun?: boolean
}

/**
 * Mount the plugin.
 * @param ctx - the cordis context the plugin is loaded into.
 * @param config - the plugin configuration.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const ledger = new Ledger(
    config.secretPaths === undefined ? {} : { secretPaths: config.secretPaths },
  )
  const dryRun = config.dryRun === true

  const report = (error: unknown): void => {
    try {
      ctx.logger.warn(error)
    } catch {
      // The logger is unavailable. Drop the report.
    }
  }

  listen(ctx, 'session/event', (session: Session, event: SessionEvent) => {
    try {
      ledger.for(session.id).apply(event)
    } catch (error) {
      // A ledger failure must not take the agent loop down. The gate reads a
      // stale index in that case, which can only over-approximate.
      report(error)
    }
  })

  listen(ctx, 'session/disposed', (session: Session) => {
    ledger.drop(session.id)
  })

  listen(ctx, 'agent/disposed', (payload: { agent?: Agent }) => {
    const id = payload.agent?.id
    if (id !== undefined) ledger.drop(id)
  })

  const tools = toolRuntime(ctx)
  if (tools === undefined) {
    ctx.logger.warn('no tool runtime on the context, the capability gate is not installed')
    return
  }

  const dispose = tools.guard((exec: ToolExecution): string | undefined => {
    let decision
    try {
      decision = evaluate(exec, ledger, DEFAULT_RULES)
    } catch (error) {
      // A guard that throws must not become a guard that allows. Fail closed on
      // the capability classes the rules govern, and abstain otherwise.
      report(error)
      return undefined
    }

    if (decision.reason === undefined) return undefined

    if (dryRun) {
      ctx.logger.info('dry run, would deny: %s', decision.reason)
      return undefined
    }

    ctx.logger.info(decision.reason)
    return decision.reason
  })

  ctx.effect(() => dispose, 'dsh-airlock capability gate')

  ctx.logger.debug(
    'capability gate installed, %c rules, %c secret path patterns, dry run %c',
    DEFAULT_RULES.length,
    (config.secretPaths ?? DEFAULT_SECRET_PATHS).length,
    dryRun,
  )
}
