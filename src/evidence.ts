/**
 * The evidence sink.
 *
 * Every decision the plugin makes — allow, deny, ask, redact, declassify —
 * emits one record. Two sinks carry it:
 *
 * 1. A hash-chained JSONL file. Each line carries the sha256 of the previous
 *    line's hash together with this line's content, so removing, reordering, or
 *    editing a line breaks the chain at that line and at every line after it.
 *    {@link verifyChain} finds the first break.
 * 2. An OpenTelemetry span event on the current active span, so a decision
 *    rides along the span `dsh-otel` already produces for the step.
 *
 * The OpenTelemetry sink is optional. `@opentelemetry/api` is loaded through a
 * dynamic import guarded by try/catch, resolved once and cached; when the
 * package is absent the sink is a silent no-op. The plugin therefore keeps its
 * zero runtime dependencies.
 *
 * Nothing here may throw into the caller. A failing audit log degrades the
 * evidence, never the agent loop, so every entry point contains its own errors
 * and hands them to the injected {@link EvidenceOptions.report} callback.
 */

import { createHash } from 'node:crypto'
import { appendFileSync, closeSync, fstatSync, mkdirSync, openSync, readSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join as joinPath } from 'node:path'

import type { Label } from './labels.js'
import type { Capability } from './policy.js'

/** What the plugin did about one call. */
export type Outcome = 'allow' | 'deny' | 'ask' | 'redact' | 'declassify'

/** Where the JSONL sink writes when the operator configures no path. */
export const DEFAULT_EVIDENCE_PATH = '~/.dsh/airlock/decisions.jsonl'

/** The span event name every decision is emitted under. */
export const SPAN_EVENT_NAME = 'airlock.decision'

/** The record schema version, carried on every line so a reader can migrate. */
export const RECORD_VERSION = 1

/**
 * The hash the first record chains from.
 *
 * `sha256('dsh-airlock/evidence/genesis/1')`. It is written out rather than
 * computed so that a reader can check the constant without running this code.
 */
export const GENESIS_HASH = '139e75e4444ed46e8803b8d79e07166f6e450ab54e47b9ee104e0a6aac3fb2ec'

/** How many bytes of an existing file are read to recover the chain head. */
const TAIL_BYTES = 64 * 1024

/**
 * One decision, before it is chained.
 *
 * The shape answers the four questions an auditor asks of a denial: what was
 * attempted, what the context was, which rule fired, and where the label came
 * from. Optional fields are absent rather than null when the plugin does not
 * know them, and a canonical serialization drops them entirely.
 */
export interface DecisionRecord {
  /** The record schema version. See {@link RECORD_VERSION}. */
  readonly version: number
  /** When the decision was made, ISO 8601 in UTC. */
  readonly timestamp: string
  /** The session the call belongs to, which is also the agent id. */
  readonly sessionId: string
  /** The turn the call ran in, when the plugin knows it. */
  readonly turn?: number
  /** The step within the turn, when the plugin knows it. */
  readonly step?: number
  /** The registered tool name, as the model called it. */
  readonly tool: string
  /** The harness call id, when the decision was made about a call. */
  readonly callId?: string
  /** Every capability class the tool belongs to. */
  readonly capabilities: readonly Capability[]
  /** What the plugin did. */
  readonly outcome: Outcome
  /** The rule that fired, by its stable id, or absent when none did. */
  readonly rule?: string
  /** The label of the context the step was running on. */
  readonly label: Label
  /** One line naming the event the label came from, when there is one. */
  readonly origin?: string
}

/** A decision record with its place in the chain. */
export interface ChainedRecord extends DecisionRecord {
  /** sha256 over the previous record's hash together with this record's content. */
  readonly hash: string
}

/** The structural part of `@opentelemetry/api` this module uses. */
interface OtelSpan {
  addEvent: (name: string, attributes?: Record<string, unknown>) => unknown
}

/** The structural part of `@opentelemetry/api` this module uses. */
interface OtelApi {
  readonly trace: { getActiveSpan: () => OtelSpan | undefined }
}

/** Loads the OpenTelemetry api, or resolves `undefined` when it is absent. */
export type OtelLoader = () => Promise<unknown>

/** How the sinks are configured. */
export interface EvidenceOptions {
  /** Where the JSONL sink writes. A leading `~/` is expanded. Defaults to {@link DEFAULT_EVIDENCE_PATH}. */
  readonly path?: string
  /** `false` disables the JSONL sink. Defaults to enabled. */
  readonly jsonl?: boolean
  /** `false` disables the OpenTelemetry sink. Defaults to enabled. */
  readonly otlp?: boolean
  /**
   * Where a sink failure goes. The plugin passes its logger here rather than
   * this module importing one, so the module stays testable and dependency
   * free. Defaults to dropping the error.
   */
  readonly report?: (error: unknown) => void
  /**
   * How the OpenTelemetry api is loaded. Defaults to a dynamic import of
   * `@opentelemetry/api`. Present so a test can supply a double.
   */
  readonly loadOtel?: OtelLoader
}

/**
 * Expand a leading `~/` against the current home directory.
 * @param path - the configured path.
 * @returns the path with `~` replaced, or the path unchanged when it has none.
 */
export function expandHome(path: string): string {
  if (path === '~') return homedir()
  if (!path.startsWith('~/') && !path.startsWith('~\\')) return path
  return joinPath(homedir(), path.slice(2))
}

/**
 * Rewrite a value with every object key in sorted order.
 * @param value - the value to rewrite.
 * @returns the same data with deterministic key order.
 */
function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (typeof value === 'object' && value !== null) {
    const source = value as Record<string, unknown>
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(source).sort()) {
      const entry = source[key]
      // An absent optional field and a field set to `undefined` must hash the
      // same, because `exactOptionalPropertyTypes` lets a caller write either.
      if (entry === undefined) continue
      sorted[key] = canonicalValue(entry)
    }
    return sorted
  }
  return value
}

/**
 * Serialize a value with stable key order.
 *
 * Object keys are sorted at every depth, so a record built by two different
 * code paths hashes identically. Array order is data and is left alone.
 *
 * @param value - the value to serialize.
 * @returns the canonical JSON text.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(canonicalValue(value)) ?? 'null'
}

/**
 * Compute one link of the chain.
 * @param previousHash - the previous record's hash, or {@link GENESIS_HASH}.
 * @param record - the record's content, without its own hash.
 * @returns the hex sha256 of the pair.
 */
export function hashRecord(previousHash: string, record: DecisionRecord): string {
  // The pair is hashed as one canonical object rather than as concatenated
  // text, so no field value can be crafted to look like the delimiter.
  const preimage = canonicalize({ previous: previousHash, record })
  return createHash('sha256').update(preimage, 'utf8').digest('hex')
}

/**
 * Chain one record onto the previous hash.
 * @param previousHash - the previous record's hash, or {@link GENESIS_HASH}.
 * @param record - the record's content.
 * @returns the record with its `hash` field.
 */
export function chainRecord(previousHash: string, record: DecisionRecord): ChainedRecord {
  return { ...record, hash: hashRecord(previousHash, record) }
}

/**
 * Split a chained record back into its content and its hash.
 * @param line - one JSONL line.
 * @returns the content and the claimed hash, or `undefined` when the line is
 *   not a chained record.
 */
function parseLine(line: string): { content: DecisionRecord; hash: string } | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
  const { hash, ...content } = parsed as Record<string, unknown>
  if (typeof hash !== 'string' || hash.length === 0) return undefined
  return { content: content as unknown as DecisionRecord, hash }
}

/**
 * Walk a file's lines and find the first place the chain breaks.
 *
 * A break is an unparsable line, a line without a hash, or a line whose hash is
 * not the sha256 of its predecessor's hash together with its own content.
 * Editing, removing, or reordering a line therefore reports at that line.
 * Blank lines are skipped, so a trailing newline is not a break.
 *
 * @param lines - the file's lines, in file order.
 * @returns the index of the first broken line, or `undefined` when intact.
 */
export function verifyChain(lines: Iterable<string>): number | undefined {
  let previous = GENESIS_HASH
  let index = -1
  for (const line of lines) {
    index += 1
    if (line.trim().length === 0) continue
    const parsed = parseLine(line)
    if (parsed === undefined) return index
    if (parsed.hash !== hashRecord(previous, parsed.content)) return index
    previous = parsed.hash
  }
  return undefined
}

/**
 * Read the chain head out of an existing file.
 *
 * Only the tail is read, because the head is the last line and the file grows
 * without bound. A file that ends in a partial line falls back to the last line
 * that parses; the partial bytes still break {@link verifyChain} at their own
 * index, which is the honest report.
 *
 * @param path - the expanded file path.
 * @returns the last recorded hash, or {@link GENESIS_HASH} for a new file.
 */
function readChainHead(path: string): string {
  let fd: number
  try {
    fd = openSync(path, 'r')
  } catch {
    // No file yet, or it cannot be read. Either way the chain starts fresh.
    return GENESIS_HASH
  }
  try {
    const size = fstatSync(fd).size
    if (size === 0) return GENESIS_HASH
    const length = Math.min(size, TAIL_BYTES)
    const buffer = Buffer.alloc(length)
    readSync(fd, buffer, 0, length, size - length)
    const lines = buffer.toString('utf8').split('\n')
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      const line = lines[index] ?? ''
      if (line.trim().length === 0) continue
      const parsed = parseLine(line)
      if (parsed !== undefined) return parsed.hash
    }
    return GENESIS_HASH
  } finally {
    closeSync(fd)
  }
}

/**
 * Render a record as span event attributes.
 *
 * Attribute values stay primitive, because the OpenTelemetry attribute type
 * admits strings, numbers, booleans, and arrays of those and nothing else.
 *
 * @param record - the chained record.
 * @returns the attributes for the span event.
 */
export function spanAttributes(record: ChainedRecord | DecisionRecord): Record<string, unknown> {
  const hash = (record as ChainedRecord).hash
  return {
    'airlock.capabilities': [...record.capabilities],
    'airlock.hash': typeof hash === 'string' ? hash : '',
    'airlock.outcome': record.outcome,
    'airlock.sensitivity': record.label.sensitivity,
    'airlock.session_id': record.sessionId,
    'airlock.timestamp': record.timestamp,
    'airlock.tool': record.tool,
    'airlock.trust': record.label.trust,
    'airlock.version': record.version,
    ...record.callId === undefined ? {} : { 'airlock.call_id': record.callId },
    ...record.origin === undefined ? {} : { 'airlock.origin': record.origin },
    ...record.rule === undefined ? {} : { 'airlock.rule': record.rule },
    ...record.step === undefined ? {} : { 'airlock.step': record.step },
    ...record.turn === undefined ? {} : { 'airlock.turn': record.turn },
  }
}

/** The cached load of `@opentelemetry/api`, started at most once per process. */
let defaultOtelLoad: Promise<unknown> | undefined

/**
 * Import `@opentelemetry/api` once.
 *
 * The specifier is held in a variable so the compiler does not resolve it: the
 * package is an optional peer and is not installed in this repository. A
 * missing package rejects the import, which resolves to `undefined` here.
 *
 * @returns the module namespace, or `undefined` when the package is absent.
 */
function loadOtelApi(): Promise<unknown> {
  if (defaultOtelLoad === undefined) {
    const specifier = '@opentelemetry/api'
    defaultOtelLoad = import(specifier).catch(() => undefined)
  }
  return defaultOtelLoad
}

/**
 * Narrow a loaded module to the part this module calls.
 * @param loaded - whatever the loader resolved.
 * @returns the api, or `undefined` when the shape is not the one expected.
 */
function asOtelApi(loaded: unknown): OtelApi | undefined {
  if (typeof loaded !== 'object' || loaded === null) return undefined
  const trace = (loaded as { trace?: unknown }).trace
  if (typeof trace !== 'object' || trace === null) return undefined
  if (typeof (trace as { getActiveSpan?: unknown }).getActiveSpan !== 'function') return undefined
  return loaded as OtelApi
}

/**
 * The hash-chained JSONL sink.
 *
 * The file is opened lazily: constructing a sink touches no filesystem, so a
 * plugin that never makes a decision never creates a directory.
 */
export class JsonlSink {
  /** The expanded path this sink appends to. */
  readonly path: string

  private readonly report: (error: unknown) => void

  /** The last hash written, read back from the file on the first append. */
  private head: string | undefined

  constructor(options: EvidenceOptions = {}) {
    this.path = expandHome(options.path ?? DEFAULT_EVIDENCE_PATH)
    this.report = options.report ?? (() => {})
  }

  /**
   * Append one record and advance the chain.
   *
   * The append is synchronous. `ctx.tools.guard()` is synchronous by contract,
   * so a decision made there cannot await a queued write; an async queue would
   * return the denial to the harness before its evidence existed, and a crash
   * in that window would lose the record that explains the denial. One
   * `appendFileSync` of one short line, written under `O_APPEND`, keeps the
   * file and the in-memory chain head in agreement and cannot interleave a
   * partial line with a concurrent decision in this process.
   *
   * @param record - the decision to write.
   * @returns the chained record, or `undefined` when the write failed.
   */
  append(record: DecisionRecord): ChainedRecord | undefined {
    try {
      if (this.head === undefined) {
        mkdirSync(dirname(this.path), { recursive: true })
        this.head = readChainHead(this.path)
      }
      const chained = chainRecord(this.head, record)
      appendFileSync(this.path, `${canonicalize(chained)}\n`, 'utf8')
      // The head advances only after the bytes are on disk, so a failed write
      // leaves the chain where it was rather than opening a gap.
      this.head = chained.hash
      return chained
    } catch (error) {
      this.reportSafely(error)
      return undefined
    }
  }

  /** @returns the hash the next record will chain from. */
  chainHead(): string {
    return this.head ?? GENESIS_HASH
  }

  private reportSafely(error: unknown): void {
    try {
      this.report(error)
    } catch {
      // The reporter failed too. There is nowhere left to put this.
    }
  }
}

/**
 * The OpenTelemetry span event sink.
 *
 * The api is loaded once and cached. Until it resolves, an emit attaches to the
 * load's promise chain rather than buffering: an async continuation keeps the
 * caller's async context, so `getActiveSpan()` still finds the span the
 * decision was made under. Once the load has resolved every later emit is
 * synchronous.
 */
export class OtelSink {
  private readonly report: (error: unknown) => void

  private readonly load: OtelLoader

  private api: OtelApi | undefined

  /** Set once the load resolved without an api. Later emits return at once. */
  private absent = false

  constructor(options: EvidenceOptions = {}) {
    this.report = options.report ?? (() => {})
    this.load = options.loadOtel ?? loadOtelApi
  }

  /**
   * Emit one decision as a span event on the current active span.
   * @param record - the decision to emit.
   */
  emit(record: ChainedRecord | DecisionRecord): void {
    if (this.absent) return
    if (this.api !== undefined) {
      this.addEvent(this.api, record)
      return
    }
    try {
      void this.load().then(
        (loaded) => {
          const api = asOtelApi(loaded)
          if (api === undefined) {
            // No OpenTelemetry in this installation. Nothing to emit, ever.
            this.absent = true
            return
          }
          this.api = api
          this.addEvent(api, record)
        },
        (error: unknown) => {
          this.absent = true
          this.reportSafely(error)
        },
      )
    } catch (error) {
      // A loader that throws synchronously is still only a missing sink.
      this.absent = true
      this.reportSafely(error)
    }
  }

  private addEvent(api: OtelApi, record: ChainedRecord | DecisionRecord): void {
    try {
      api.trace.getActiveSpan()?.addEvent(SPAN_EVENT_NAME, spanAttributes(record))
    } catch (error) {
      // No active span, or an exporter that objected. Neither is the caller's
      // problem.
      this.reportSafely(error)
    }
  }

  private reportSafely(error: unknown): void {
    try {
      this.report(error)
    } catch {
      // The reporter failed too. There is nowhere left to put this.
    }
  }
}

/**
 * Both sinks behind one call.
 *
 * The JSONL sink runs first, so the hash it computes rides out on the span
 * event as well and a trace can be tied back to the exact line on disk.
 */
export class EvidenceSink {
  private readonly jsonl: JsonlSink | undefined

  private readonly otel: OtelSink | undefined

  constructor(options: EvidenceOptions = {}) {
    this.jsonl = options.jsonl === false ? undefined : new JsonlSink(options)
    this.otel = options.otlp === false ? undefined : new OtelSink(options)
  }

  /** @returns the JSONL path in use, or `undefined` when that sink is off. */
  get path(): string | undefined {
    return this.jsonl?.path
  }

  /**
   * Record one decision. This never throws.
   * @param record - the decision to record.
   * @returns the chained record, or `undefined` when nothing was written.
   */
  emit(record: DecisionRecord): ChainedRecord | undefined {
    const chained = this.jsonl?.append(record)
    this.otel?.emit(chained ?? record)
    return chained
  }
}

/**
 * Build a record for the current instant.
 *
 * A convenience for callers that have everything but the timestamp and the
 * version. Optional fields are spread conditionally, because
 * `exactOptionalPropertyTypes` distinguishes an absent field from `undefined`.
 *
 * @param fields - everything the caller knows about the decision.
 * @param now - the instant to stamp, defaulting to the current time.
 * @returns the record, ready for {@link EvidenceSink.emit}.
 */
export function decisionRecord(
  fields: Omit<DecisionRecord, 'version' | 'timestamp'>,
  now: Date = new Date(),
): DecisionRecord {
  return {
    version: RECORD_VERSION,
    timestamp: now.toISOString(),
    sessionId: fields.sessionId,
    tool: fields.tool,
    capabilities: [...fields.capabilities],
    outcome: fields.outcome,
    label: fields.label,
    ...fields.turn === undefined ? {} : { turn: fields.turn },
    ...fields.step === undefined ? {} : { step: fields.step },
    ...fields.callId === undefined ? {} : { callId: fields.callId },
    ...fields.rule === undefined ? {} : { rule: fields.rule },
    ...fields.origin === undefined ? {} : { origin: fields.origin },
  }
}
