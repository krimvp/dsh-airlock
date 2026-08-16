/**
 * The label ledger.
 *
 * The ledger is a projection over `session/event`. It assigns an intrinsic
 * label to every event that reaches the model-visible surface, propagates
 * labels through surface replacement, and answers one question for the gate:
 * what is the label of the context this step is running on.
 *
 * The projection is rebuildable. Nothing here is authoritative state — the
 * session log is, and replaying it reproduces this index exactly.
 */

import type { MessageEventData, SessionEvent, SurfaceOp, ToolCallData, ToolResultData } from './dsh.js'
import type { Label } from './labels.js'
import { BOTTOM, join, sensitivityRank, trustRank } from './labels.js'
import { DEFAULT_SECRET_PATHS, isUntrustedSource, matchSecretPath } from './policy.js'

/** The event types eligible for the ordered surface. Only these carry surface metadata. */
const SURFACE_TYPES: readonly string[] = ['user/message', 'assistant/message', 'tool/result']

/** Tool-call argument keys that name a filesystem path. */
const PATH_KEYS: readonly string[] = ['file_path', 'path', 'filePath', 'absolute_path']

/**
 * How many labelled nodes one session retains for replacement lookups.
 * A node still on the live surface is never forgotten silently; see
 * {@link SessionLedger.evict}.
 */
const MAX_TRACKED_NODES = 20_000

/** Why a node carries the label it carries. */
export interface Provenance {
  /** The seq of the event that introduced the label. */
  readonly seq: number
  /** One line naming the origin, for a denial message or a log line. */
  readonly description: string
}

/** One labelled node. */
export interface LabelledNode {
  readonly seq: number
  readonly label: Label
  readonly provenance: Provenance
}

/** The label of a step's context, with the nodes that decided each axis. */
export interface ContextLabel {
  readonly label: Label
  /** The node that raised trust above `user`, when one did. */
  readonly trustOrigin?: Provenance
  /** The node that raised sensitivity above `public`, when one did. */
  readonly sensitivityOrigin?: Provenance
}

/** Options that change how events are labelled. */
export interface LedgerOptions {
  /** Globs whose contents are `secret`. Defaults to {@link DEFAULT_SECRET_PATHS}. */
  readonly secretPaths?: readonly string[]
  /** Tool name patterns whose results are `untrusted`. Defaults to the built-in list. */
  readonly untrustedSources?: readonly string[]
}

/** What a tool result carries on its own, before inheritance. */
export interface ResultLabel {
  readonly label: Label
  /** The secret glob that matched, when one did. */
  readonly matchedGlob?: string
  /** The path the call named, when it named one. */
  readonly path?: string
}

/**
 * The label a tool result carries, computed from the call that produced it.
 *
 * The gate at `tools/post-execute` runs before the `tool/result` event is
 * appended, so it cannot ask the ledger for a label that does not exist yet.
 * Both callers therefore share this one function, and a result is labelled the
 * same whether it is being judged live or replayed from the log.
 *
 * @param name - the tool that produced the result.
 * @param args - the parsed arguments of the call, when they are known.
 * @param options - the secret globs and untrusted sources in force.
 * @returns the intrinsic label, with the matched glob and path when relevant.
 */
export function resultLabelFor(
  name: string,
  args: Record<string, unknown> | undefined,
  options: LedgerOptions = {},
): ResultLabel {
  const secretPaths = options.secretPaths ?? DEFAULT_SECRET_PATHS
  const untrustedSources = options.untrustedSources

  if (isUntrustedSource(name, untrustedSources)) {
    return { label: { trust: 'untrusted', sensitivity: 'public' } }
  }

  const path = argumentPath(args)
  if (path !== undefined) {
    const matchedGlob = matchSecretPath(path, secretPaths)
    if (matchedGlob !== undefined) {
      return { label: { trust: 'workspace', sensitivity: 'secret' }, matchedGlob, path }
    }
  }

  return {
    label: { trust: 'workspace', sensitivity: 'public' },
    ...path === undefined ? {} : { path },
  }
}

/**
 * Parse the raw argument string a model produced.
 * @param raw - the unparsed JSON string from a `tool/call` event.
 * @returns the parsed object, or `undefined` when it is absent or malformed.
 */
function parseArguments(raw: string | undefined): Record<string, unknown> | undefined {
  if (typeof raw !== 'string') return undefined
  try {
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
    return parsed as Record<string, unknown>
  } catch {
    // A malformed argument string never reaches a tool body. Nothing to label.
    return undefined
  }
}

/**
 * Pull the filesystem path out of parsed tool arguments.
 * @param args - the parsed arguments.
 * @returns the first path-shaped value, or `undefined`.
 */
function argumentPath(args: Record<string, unknown> | undefined): string | undefined {
  if (args === undefined) return undefined
  for (const key of PATH_KEYS) {
    const value = args[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

/** One session's labels. */
export class SessionLedger {
  private readonly secretPaths: readonly string[]

  /** Live surface node seqs, in surface order. */
  private surface: number[] = []

  /** Every labelled node this session still remembers, keyed by seq. */
  private readonly nodes = new Map<number, LabelledNode>()

  /** `callId` to the `tool/call` that issued it. */
  private readonly calls = new Map<string, { name: string; args: Record<string, unknown> | undefined }>()

  /**
   * The floor forced by eviction. A node dropped from {@link nodes} while it
   * was still on the surface folds its label in here, so forgetting a node can
   * only ever over-approximate.
   */
  private evictionFloor: Label = BOTTOM

  /** Provenance for {@link evictionFloor}, when it is above bottom. */
  private evictionProvenance: Provenance | undefined

  private readonly untrustedSources: readonly string[] | undefined

  constructor(options: LedgerOptions = {}) {
    this.secretPaths = options.secretPaths ?? DEFAULT_SECRET_PATHS
    this.untrustedSources = options.untrustedSources
  }

  /**
   * Fold one session event into the index.
   * @param event - the event, exactly as the session log recorded it.
   */
  apply(event: SessionEvent): void {
    if (event.type === 'tool/call') {
      this.recordCall(event)
      return
    }
    if (!SURFACE_TYPES.includes(event.type)) return
    this.recordSurface(event)
  }

  /**
   * The label of the context the model is running on right now.
   *
   * This is a join over the live surface, not a sticky per-session flag. A
   * compaction that drops a node from the surface lowers the label, unless the
   * replacing node inherited it — which the harness guarantees it does, because
   * a `replace` must cite every node it shadows.
   *
   * @returns the joined label and the node that decided each axis.
   */
  contextLabel(): ContextLabel {
    let label = this.evictionFloor
    let trustOrigin = this.evictionProvenance
    let sensitivityOrigin = this.evictionProvenance

    for (const seq of this.surface) {
      const node = this.nodes.get(seq)
      if (node === undefined) continue
      if (trustRank(node.label.trust) > trustRank(label.trust)) trustOrigin = node.provenance
      if (sensitivityRank(node.label.sensitivity) > sensitivityRank(label.sensitivity)) {
        sensitivityOrigin = node.provenance
      }
      label = join(label, node.label)
    }

    return {
      label,
      ...label.trust === 'user' || trustOrigin === undefined ? {} : { trustOrigin },
      ...label.sensitivity === 'public' || sensitivityOrigin === undefined
        ? {}
        : { sensitivityOrigin },
    }
  }

  /** @returns the live surface seqs, in order. Exposed for tests and diagnostics. */
  surfaceSeqs(): readonly number[] {
    return [...this.surface]
  }

  /**
   * @param seq - the event seq to look up.
   * @returns that node's label, or `undefined` when it is unknown or forgotten.
   */
  labelOf(seq: number): Label | undefined {
    return this.nodes.get(seq)?.label
  }

  private recordCall(event: SessionEvent): void {
    const data = event.data as ToolCallData | undefined
    const callId = data?.callId
    const name = data?.name
    if (typeof callId !== 'string' || typeof name !== 'string') return
    this.calls.set(callId, { name, args: parseArguments(data?.arguments) })
    // The call map only needs to outlive its own result.
    if (this.calls.size > MAX_TRACKED_NODES) {
      const oldest = this.calls.keys().next()
      if (oldest.done !== true) this.calls.delete(oldest.value)
    }
  }

  private recordSurface(event: SessionEvent): void {
    const intrinsic = this.intrinsicLabel(event)
    const inherited = this.inheritedLabel(event)
    const label = join(inherited.label, intrinsic.label)

    // The axis that ends up deciding the node's label owns the provenance.
    const provenance = trustRank(intrinsic.label.trust) >= trustRank(inherited.label.trust)
      && sensitivityRank(intrinsic.label.sensitivity) >= sensitivityRank(inherited.label.sensitivity)
      ? intrinsic.provenance
      : inherited.provenance ?? intrinsic.provenance

    this.remember({ seq: event.seq, label, provenance })
    this.placeOnSurface(event.seq, event.surfaceOp)
  }

  /**
   * The label an event carries on its own, before inheritance.
   * @param event - a surface-eligible event.
   * @returns the intrinsic label and why it applies.
   */
  private intrinsicLabel(event: SessionEvent): { label: Label; provenance: Provenance } {
    const seq = event.seq

    if (event.type === 'tool/result') {
      return this.toolResultLabel(event)
    }

    if (event.type === 'user/message') {
      const data = event.data as MessageEventData | undefined
      const source = data?.source ?? data?.message?.source
      const kind = source?.kind
      if (kind === 'user') {
        return {
          label: { trust: 'user', sensitivity: 'public' },
          provenance: { seq, description: `seq ${seq} (a message you typed)` },
        }
      }
      // `agent.inject()` content arrives as a user-role message: a subdirectory
      // AGENTS.md, a skill body, a cron notice. It reads to the model exactly
      // like human input, which is the gap injections live in. The event type
      // tells them apart, so the ledger can even though the model cannot.
      const plugin = typeof source?.plugin === 'string' ? source.plugin : 'a plugin'
      return {
        label: { trust: 'workspace', sensitivity: 'public' },
        provenance: { seq, description: `seq ${seq} (context injected by ${plugin})` },
      }
    }

    // `assistant/message` cites `assistant/chunk` events, which never reach the
    // surface and carry no label. The model's own output therefore contributes
    // nothing on its own; the untrusted node it paraphrased is still on the
    // surface contributing its label directly.
    return {
      label: BOTTOM,
      provenance: { seq, description: `seq ${seq} (model output)` },
    }
  }

  private toolResultLabel(event: SessionEvent): { label: Label; provenance: Provenance } {
    const seq = event.seq
    const data = event.data as ToolResultData | undefined
    const callId = data?.message?.source?.callId
    const call = typeof callId === 'string' ? this.calls.get(callId) : undefined

    if (call === undefined) {
      // An unpaired result is a result whose origin is unknown. Treat unknown
      // origin as workspace rather than user: it was not typed by a human.
      return {
        label: { trust: 'workspace', sensitivity: 'public' },
        provenance: { seq, description: `seq ${seq} (a tool result of unknown origin)` },
      }
    }

    const resolved = resultLabelFor(call.name, call.args, {
      secretPaths: this.secretPaths,
      ...this.untrustedSources === undefined ? {} : { untrustedSources: this.untrustedSources },
    })

    const description = resolved.matchedGlob !== undefined
      ? `seq ${seq} (\`${call.name}\` read ${resolved.path}, matching ${resolved.matchedGlob})`
      : `seq ${seq} (\`${call.name}\` result)`

    return { label: resolved.label, provenance: { seq, description } }
  }

  /**
   * The label an event inherits from the events it cites.
   *
   * This is what makes compaction sound. A `replace` node must list every
   * surface node it shadows, so the summary of a poisoned page inherits that
   * page's label. Taint cannot be laundered by summarising it.
   *
   * @param event - a surface-eligible event.
   * @returns the joined label of its cited sources.
   */
  private inheritedLabel(event: SessionEvent): { label: Label; provenance: Provenance | undefined } {
    const sources = event.sourceEventSeqs
    if (sources === undefined || sources.length === 0) {
      return { label: BOTTOM, provenance: undefined }
    }

    let label = BOTTOM
    let provenance: Provenance | undefined
    for (const seq of sources) {
      const node = this.nodes.get(seq)
      if (node === undefined) continue
      const next = join(label, node.label)
      if (trustRank(next.trust) > trustRank(label.trust)
        || sensitivityRank(next.sensitivity) > sensitivityRank(label.sensitivity)) {
        provenance = node.provenance
      }
      label = next
    }
    return { label, provenance }
  }

  private placeOnSurface(seq: number, surfaceOp: SurfaceOp | undefined): void {
    if (surfaceOp === undefined) return

    if (surfaceOp === 'append') {
      this.surface.push(seq)
      return
    }

    if (typeof surfaceOp === 'object' && surfaceOp.op === 'replace') {
      const { start, end } = surfaceOp
      const kept = this.surface.filter((node) => node < start || node > end)
      const insertAt = kept.findIndex((node) => node > end)
      if (insertAt < 0) kept.push(seq)
      else kept.splice(insertAt, 0, seq)
      this.surface = kept
    }
  }

  private remember(node: LabelledNode): void {
    this.nodes.set(node.seq, node)
    this.evict()
  }

  /**
   * Drop the oldest tracked nodes past the cap.
   *
   * A node still on the live surface folds its label into {@link evictionFloor}
   * before it goes, so the ledger loses precision under memory pressure but
   * never loses a restriction.
   */
  private evict(): void {
    while (this.nodes.size > MAX_TRACKED_NODES) {
      const oldest = this.nodes.keys().next()
      if (oldest.done === true) return
      const seq = oldest.value
      const node = this.nodes.get(seq)
      if (node !== undefined && this.surface.includes(seq)) {
        const floor = join(this.evictionFloor, node.label)
        if (trustRank(floor.trust) > trustRank(this.evictionFloor.trust)
          || sensitivityRank(floor.sensitivity) > sensitivityRank(this.evictionFloor.sensitivity)) {
          this.evictionProvenance = node.provenance
        }
        this.evictionFloor = floor
      }
      this.nodes.delete(seq)
    }
  }
}

/** Every live session's ledger, keyed by session id. */
export class Ledger {
  private readonly sessions = new Map<string, SessionLedger>()

  constructor(private readonly options: LedgerOptions = {}) {}

  /**
   * @param sessionId - the session to read or open.
   * @returns that session's ledger, creating it when the session is new.
   */
  for(sessionId: string): SessionLedger {
    const existing = this.sessions.get(sessionId)
    if (existing !== undefined) return existing
    const created = new SessionLedger(this.options)
    this.sessions.set(sessionId, created)
    return created
  }

  /**
   * @param sessionId - the session to read without opening one.
   * @returns that session's ledger, or `undefined` when it has none.
   */
  peek(sessionId: string): SessionLedger | undefined {
    return this.sessions.get(sessionId)
  }

  /** @param sessionId - the session to forget, on disposal. */
  drop(sessionId: string): void {
    this.sessions.delete(sessionId)
  }
}
