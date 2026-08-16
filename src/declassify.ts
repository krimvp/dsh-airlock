/**
 * Declassification — the approved exception, written down.
 *
 * A denial that cannot be overridden is a dead end, and a dead end is what
 * makes an operator turn a gate off. Declassification is the other half of the
 * ask posture: a human clears a label for a named action, and the clearance
 * becomes an audit record rather than a disabled plugin.
 *
 * The harness grants nothing durable. `ctx.approval` has `allowed-once` and no
 * `allow-always`, no remembered rule, and no grant store (verified against
 * `packages/interaction/user-approval/README.md` at 0.1.0-rc.5). A plugin that
 * wants a clearance to outlive one call therefore keeps its own store, which is
 * this module.
 *
 * A grant is scoped by capability class and optionally by tool name, and it is
 * bounded on both axes that can leak: a session holds at most
 * {@link DEFAULT_MAX_GRANTS} grants, and the store remembers at most
 * {@link DEFAULT_MAX_SESSIONS} sessions. Nothing here decides over an argument
 * string or over tool output; a tool name is configuration about tools, which
 * is the same data the capability classes are built from.
 *
 * The read path is synchronous, because the monotonic guard is synchronous by
 * contract. Nothing here throws: a failed lookup is a missing clearance, which
 * leaves the restriction standing.
 */

import type { DecisionRecord } from './evidence.js'
import { decisionRecord } from './evidence.js'
import type { Label } from './labels.js'
import { formatLabel, sensitivityRank, trustRank } from './labels.js'
import type { Capability } from './policy.js'

/** How many grants one session may hold at once. */
export const DEFAULT_MAX_GRANTS = 16

/** How many sessions the store remembers before it forgets the oldest. */
export const DEFAULT_MAX_SESSIONS = 1_024

/**
 * What a grant covers.
 *
 * The capability class is the unit, because the capability class is what a rule
 * governs. A grant that also names a tool covers that tool alone, which is the
 * narrower clearance an operator should prefer.
 */
export interface GrantScope {
  /** The capability class the clearance applies to. */
  readonly capability: Capability
  /** The single tool the clearance applies to. Absent covers the whole class. */
  readonly tool?: string
}

/** What a caller asks the store to record. */
export interface GrantRequest extends GrantScope {
  /** The context label the human cleared. See {@link Declassifier.isDeclassified}. */
  readonly label: Label
  /** Who cleared it, for the audit record. */
  readonly actor: string
  /** Why it was cleared, in one line, for the audit record. */
  readonly reason: string
  /** The rule the clearance excepts, by its stable id, when there is one. */
  readonly rule?: string
  /** The call the clearance was granted against, when there is one. */
  readonly callId?: string
  /** How long this grant lives, in milliseconds. Overrides the store default. */
  readonly ttlMs?: number
}

/** One recorded clearance. */
export interface Grant extends GrantScope {
  /** A stable identifier, quoted in evidence and accepted by {@link Declassifier.revoke}. */
  readonly id: string
  /** The session the clearance belongs to. */
  readonly sessionId: string
  /** The context label the human cleared. */
  readonly label: Label
  /** When it was granted, in epoch milliseconds. */
  readonly grantedAt: number
  /** When it stops applying, in epoch milliseconds. Absent means no expiry. */
  readonly expiresAt?: number
  /** Who cleared it. */
  readonly actor: string
  /** Why it was cleared. */
  readonly reason: string
  /** The rule the clearance excepts, by its stable id. */
  readonly rule?: string
  /** The call the clearance was granted against. */
  readonly callId?: string
}

/** What a caller asks the store about. */
export interface GrantQuery {
  /** The capability class of the call being decided. */
  readonly capability: Capability
  /** The tool being called. */
  readonly tool?: string
  /** The context label of the step being decided. */
  readonly label: Label
}

/**
 * The synchronous read a gate performs.
 *
 * Declared as an interface so a gate depends on the question rather than on
 * this class, and a test can answer it with two lines.
 */
export interface DeclassificationLookup {
  /**
   * @param sessionId - the session the call belongs to.
   * @param query - the capability class, tool, and context label to clear.
   * @returns `true` when a live grant covers the query.
   */
  isDeclassified(sessionId: string, query: GrantQuery): boolean
  /**
   * The covering grant itself, when the implementation can name it. A gate uses
   * it to cite the clearance in evidence; the decision never depends on it.
   *
   * @param sessionId - the session the call belongs to.
   * @param query - the capability class, tool, and context label to clear.
   * @returns the covering grant, or `undefined` when there is none.
   */
  find?(sessionId: string, query: GrantQuery): Grant | undefined
}

/** How the store is configured. */
export interface DeclassifierOptions {
  /**
   * `false` disables declassification, so every lookup is `false` and no grant
   * is recorded. Mirrors `declassify.allow` on the resolved policy. Defaults to
   * enabled.
   */
  readonly allow?: boolean
  /** How many grants one session may hold. Defaults to {@link DEFAULT_MAX_GRANTS}. */
  readonly maxGrants?: number
  /** How many sessions the store remembers. Defaults to {@link DEFAULT_MAX_SESSIONS}. */
  readonly maxSessions?: number
  /**
   * How long a grant lives, in milliseconds. Absent means a grant lives until
   * its session is dropped or the cap evicts it.
   */
  readonly ttlMs?: number
  /**
   * The clock, in epoch milliseconds. Injected rather than read from
   * `Date.now()` directly, so an expiry test states the time it means.
   * Defaults to `Date.now`.
   */
  readonly now?: () => number
}

/**
 * Read a positive whole number out of configuration.
 * @param value - the configured value.
 * @param fallback - the value to use when the configured one is unusable.
 * @returns the sanitised bound, never below one.
 */
function bound(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback
  const whole = Math.floor(value)
  return whole < 1 ? 1 : whole
}

/**
 * Test whether one label sits at or below another on both axes.
 *
 * This is what makes a grant safe to reuse. The human cleared a step whose
 * context was some label; a later step whose context is at or below that label
 * carries nothing the human did not already see. A step that has since picked
 * up a higher label is a different question, and it is asked again.
 *
 * @param label - the label being tested.
 * @param ceiling - the label that was cleared.
 * @returns `true` when `label` is dominated by `ceiling`.
 */
export function labelAtOrBelow(label: Label, ceiling: Label): boolean {
  return trustRank(label.trust) <= trustRank(ceiling.trust)
    && sensitivityRank(label.sensitivity) <= sensitivityRank(ceiling.sensitivity)
}

/**
 * Test whether one grant answers one query.
 * @param grant - the recorded clearance.
 * @param query - the call being decided.
 * @returns `true` when the grant covers the query.
 */
function covers(grant: Grant, query: GrantQuery): boolean {
  if (grant.capability !== query.capability) return false
  if (grant.tool !== undefined && grant.tool !== query.tool) return false
  return labelAtOrBelow(query.label, grant.label)
}

/**
 * Test whether a grant has expired.
 * @param grant - the recorded clearance.
 * @param now - the current instant, in epoch milliseconds.
 * @returns `true` when the grant no longer applies.
 */
function expired(grant: Grant, now: number): boolean {
  return grant.expiresAt !== undefined && now >= grant.expiresAt
}

/**
 * Session-scoped declassification grants.
 *
 * The store is authoritative for nothing. Losing it costs the operator a repeat
 * of the question, which is the failure that leaves the restriction standing.
 */
export class Declassifier implements DeclassificationLookup {
  /** Whether declassification is enabled at all. */
  readonly allow: boolean

  private readonly maxGrants: number

  private readonly maxSessions: number

  private readonly ttlMs: number | undefined

  private readonly clock: () => number

  /** Live grants, keyed by session id, oldest grant first. */
  private readonly sessions = new Map<string, Grant[]>()

  /** Source of grant ids. Monotonic within one store. */
  private counter = 0

  constructor(options: DeclassifierOptions = {}) {
    this.allow = options.allow !== false
    this.maxGrants = bound(options.maxGrants, DEFAULT_MAX_GRANTS)
    this.maxSessions = bound(options.maxSessions, DEFAULT_MAX_SESSIONS)
    this.ttlMs = options.ttlMs === undefined || !Number.isFinite(options.ttlMs)
      ? undefined
      : Math.max(0, options.ttlMs)
    this.clock = options.now ?? Date.now
  }

  /**
   * Record one clearance.
   *
   * The oldest grant of a session is evicted once the session is at its cap, so
   * a session that keeps approving loses its earliest clearance rather than
   * growing without bound. Eviction can only remove permission.
   *
   * @param sessionId - the session the clearance belongs to.
   * @param request - what the human cleared, and why.
   * @returns the recorded grant, or `undefined` when declassification is
   *   disabled or the store could not record it.
   */
  grant(sessionId: string, request: GrantRequest): Grant | undefined {
    if (!this.allow) return undefined
    try {
      const now = this.readClock()
      if (now === undefined) return undefined
      const ttl = request.ttlMs ?? this.ttlMs
      this.counter += 1
      const grant: Grant = {
        id: `airlock-grant-${this.counter}`,
        sessionId,
        capability: request.capability,
        label: request.label,
        grantedAt: now,
        actor: request.actor,
        reason: request.reason,
        ...request.tool === undefined ? {} : { tool: request.tool },
        ...ttl === undefined || !Number.isFinite(ttl) ? {} : { expiresAt: now + ttl },
        ...request.rule === undefined ? {} : { rule: request.rule },
        ...request.callId === undefined ? {} : { callId: request.callId },
      }

      const held = this.open(sessionId)
      const live = held.filter((existing) => !expired(existing, now))
      while (live.length >= this.maxGrants) live.shift()
      live.push(grant)
      this.sessions.set(sessionId, live)
      return grant
    } catch {
      // A store that cannot record a clearance simply has none. The rule that
      // prompted the question stays in force.
      return undefined
    }
  }

  /**
   * Find the grant that clears one call.
   * @param sessionId - the session the call belongs to.
   * @param query - the capability class, tool, and context label to clear.
   * @returns the covering grant, or `undefined` when there is none.
   */
  find(sessionId: string, query: GrantQuery): Grant | undefined {
    if (!this.allow) return undefined
    try {
      const now = this.readClock()
      // A clock this store cannot read is a store that cannot prove a grant is
      // still live. Answering `undefined` leaves the restriction standing.
      if (now === undefined) return undefined
      const held = this.sessions.get(sessionId)
      if (held === undefined || held.length === 0) return undefined

      const live = held.filter((grant) => !expired(grant, now))
      if (live.length !== held.length) this.sessions.set(sessionId, live)

      // The newest covering grant answers, because it is the one the human saw
      // most recently.
      for (let index = live.length - 1; index >= 0; index -= 1) {
        const grant = live[index]
        if (grant !== undefined && covers(grant, query)) return grant
      }
      return undefined
    } catch {
      return undefined
    }
  }

  /**
   * Whether a live grant clears one call. Synchronous, because the monotonic
   * guard is synchronous by contract.
   *
   * @param sessionId - the session the call belongs to.
   * @param query - the capability class, tool, and context label to clear.
   * @returns `true` when a live grant covers the query.
   */
  isDeclassified(sessionId: string, query: GrantQuery): boolean {
    return this.find(sessionId, query) !== undefined
  }

  /**
   * Withdraw one grant.
   * @param sessionId - the session that holds it.
   * @param grantId - the grant's {@link Grant.id}.
   * @returns `true` when a grant was removed.
   */
  revoke(sessionId: string, grantId: string): boolean {
    const held = this.sessions.get(sessionId)
    if (held === undefined) return false
    const kept = held.filter((grant) => grant.id !== grantId)
    if (kept.length === held.length) return false
    this.sessions.set(sessionId, kept)
    return true
  }

  /**
   * Withdraw every grant of one session, keeping the session known.
   * @param sessionId - the session to clear.
   */
  clear(sessionId: string): void {
    if (this.sessions.has(sessionId)) this.sessions.set(sessionId, [])
  }

  /**
   * Forget one session entirely.
   *
   * A clearance must not survive the session it was given in, so the plugin
   * calls this from the disposal listeners the ledger is dropped from.
   *
   * @param sessionId - the session to forget.
   */
  drop(sessionId: string): void {
    this.sessions.delete(sessionId)
  }

  /**
   * @param sessionId - the session to read.
   * @returns that session's live grants, oldest first. Exposed for evidence and
   *   for tests.
   */
  grants(sessionId: string): readonly Grant[] {
    const now = this.readClock()
    if (now === undefined) return []
    return (this.sessions.get(sessionId) ?? []).filter((grant) => !expired(grant, now))
  }

  /** @returns how many sessions the store currently remembers. */
  sessionCount(): number {
    return this.sessions.size
  }

  /**
   * Open a session's grant list, evicting the oldest session past the cap.
   * @param sessionId - the session to open.
   * @returns the session's current grants.
   */
  private open(sessionId: string): Grant[] {
    const held = this.sessions.get(sessionId)
    if (held !== undefined) return held
    while (this.sessions.size >= this.maxSessions) {
      const oldest = this.sessions.keys().next()
      if (oldest.done === true) break
      this.sessions.delete(oldest.value)
    }
    const created: Grant[] = []
    this.sessions.set(sessionId, created)
    return created
  }

  /**
   * Read the injected clock.
   * @returns the current instant in epoch milliseconds, or `undefined` when the
   *   clock misbehaves. Every caller treats that as no clearance.
   */
  private readClock(): number | undefined {
    try {
      const now = this.clock()
      return Number.isFinite(now) ? now : undefined
    } catch {
      return undefined
    }
  }
}

/** What the caller knows about the call a grant is being applied to. */
export interface DeclassifiedCall {
  /** The registered tool name, as the model called it. */
  readonly tool: string
  /** Every capability class the tool belongs to. */
  readonly capabilities: readonly Capability[]
  /** The harness call id, when the caller has one. */
  readonly callId?: string
  /** The turn the call ran in, when the caller knows it. */
  readonly turn?: number
  /** The step within the turn, when the caller knows it. */
  readonly step?: number
}

/**
 * Render a grant as the origin line of an evidence record.
 * @param grant - the clearance that was applied.
 * @returns one line naming who cleared what, and when.
 */
export function describeGrant(grant: Grant): string {
  let when = String(grant.grantedAt)
  try {
    when = new Date(grant.grantedAt).toISOString()
  } catch {
    // An unrepresentable instant still describes the grant well enough.
  }
  const scope = grant.tool === undefined ? `${grant.capability} tools` : `\`${grant.tool}\``
  return `grant ${grant.id}: ${grant.actor} cleared ${formatLabel(grant.label)}`
    + ` for ${scope} at ${when} (${grant.reason})`
}

/**
 * Build the evidence record for a declassified call.
 *
 * The field names are {@link DecisionRecord}'s, so the caller hands the result
 * straight to the evidence sink. The `origin` line names the actor and the
 * instant, because a declassification's origin is the human who granted it
 * rather than an event on the surface.
 *
 * @param grant - the clearance that was applied.
 * @param call - what the caller knows about the call.
 * @param now - the instant to stamp, defaulting to the current time.
 * @returns the record, ready for the evidence sink.
 */
export function declassificationRecord(
  grant: Grant,
  call: DeclassifiedCall,
  now: Date = new Date(),
): DecisionRecord {
  return decisionRecord({
    sessionId: grant.sessionId,
    tool: call.tool,
    capabilities: [...call.capabilities],
    outcome: 'declassify',
    label: grant.label,
    origin: describeGrant(grant),
    ...call.callId === undefined ? {} : { callId: call.callId },
    ...call.turn === undefined ? {} : { turn: call.turn },
    ...call.step === undefined ? {} : { step: call.step },
    ...grant.rule === undefined ? {} : { rule: grant.rule },
  }, now)
}
