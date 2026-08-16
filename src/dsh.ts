/*
 * Local structural copies of the dsh payload types.
 *
 * Source: https://github.com/deepseek-ai/deepseek-harness at 0.1.0-rc.6.
 * The plugin declares no dsh package as a dependency, so the cordis `Events`
 * interface holds no dsh event and `ctx.tools` is not typed. `listen` and
 * `toolRuntime` cast once at that seam, and each caller declares the shape it
 * relies on. Every field below is optional or defensively read, because a
 * compatibility break in the harness must degrade this plugin rather than
 * crash the agent loop.
 */

import type { Context } from '@deepseek-ai/cordis'

/** A live agent, whose `id` is the session id it runs. */
export interface Agent {
  readonly id: string
}

/** The session that owns a log. */
export interface Session {
  readonly id: string
}

/**
 * How a surface event entered the ordered surface.
 *
 * `replace` shadows the surface nodes from `start` through `end` inclusive.
 * The harness requires the replacing event's `sourceEventSeqs` to list every
 * node it shadows, which is what makes label propagation through compaction
 * total rather than best effort.
 */
export type SurfaceOp =
  | 'append'
  | { readonly op: 'replace'; readonly start: number; readonly end: number }

/** Where a message came from. Merge-extensible: switch on `kind` and let unknowns fall through. */
export interface MessageSource {
  readonly kind: string
  /** Present on `kind: 'plugin'` — the plugin that injected the content. */
  readonly plugin?: string
  /** Present on `kind: 'tool'` — pairs the result with its `tool/call`. */
  readonly callId?: string
  /** Present on producer-declared context; `'instructions'`, `'notice'`, and so on. */
  readonly form?: string
}

/** One message on the model-visible surface. */
export interface Message {
  readonly id?: string
  readonly role?: string
  readonly content?: readonly unknown[]
  readonly source?: MessageSource
}

/** One immutable entry in the session log. */
export interface SessionEvent {
  readonly type: string
  readonly seq: number
  readonly time: number
  readonly data: unknown
  /** Only present on the surface-eligible types. */
  readonly sourceEventSeqs?: readonly number[]
  /** Only present on the surface-eligible types. */
  readonly surfaceOp?: SurfaceOp
}

/** `data` of a `tool/call` event. `arguments` is the raw JSON string the model produced. */
export interface ToolCallData {
  readonly callId?: string
  readonly name?: string
  readonly arguments?: string
}

/** `data` of a `tool/result` event. */
export interface ToolResultData {
  readonly message?: Message
}

/** `data` of a `user/message` or `assistant/message` event. */
export interface MessageEventData {
  readonly message?: Message
  /** `user/message` carries the message inline rather than under `message`. */
  readonly source?: MessageSource
  readonly role?: string
}

/** The readonly pipeline view a guard receives. */
export interface ToolExecution {
  readonly callId: string
  readonly name: string
  readonly arguments: unknown
  readonly agent?: Agent
}

/**
 * A monotonic execution guard. Returning a string denies the call with that
 * reason; returning `undefined` abstains. A guard can never force-allow, so a
 * later listener cannot turn a denial back into permission.
 */
export type ToolGuard = (execution: ToolExecution) => string | undefined

/** The subset of `ctx.tools` this plugin uses. */
export interface ToolRuntime {
  guard(guard: ToolGuard): () => void
}

/** One model-facing content block. `text` is the only variant this plugin authors. */
export interface ContentBlock {
  readonly type: string
  readonly text?: string
  readonly [key: string]: unknown
}

/** A successful or failed tool outcome, as `tools/post-execute` receives it. */
export interface ToolExecutionResult {
  readonly isError: boolean
  readonly value?: unknown
  readonly content?: readonly ContentBlock[]
  readonly error?: { readonly message: string }
  readonly meta?: unknown
}

/**
 * The decision `tools/post-execute` returns.
 *
 * Replacing `content` is presentation policy only: the canonical `value`
 * survives, and a Code Mode program reads that value. Confidentiality therefore
 * requires `block`, or an `accept` that replaces the value. Setting both
 * `content` and `value` is a runtime error in the harness.
 */
export type PostToolDecision =
  | { readonly kind: 'accept'; readonly content?: readonly ContentBlock[] }
  | { readonly kind: 'accept'; readonly value: unknown }
  | { readonly kind: 'block'; readonly feedback: readonly ContentBlock[] }

/** The decision `tools/pre-execute` returns. Arguments cannot be rewritten here. */
export type PreToolDecision =
  | { readonly kind: 'allow' }
  | { readonly kind: 'deny'; readonly reason: string }
  | { readonly kind: 'ask'; readonly reason?: string }

/** The outcome of one approval question. Callers fail closed on `unavailable`. */
export type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'

/** What the harness asks an answerer. It carries no tool arguments, so `reason` must carry the detail. */
export interface ApprovalRequest {
  readonly agent: Agent
  readonly toolName: string
  readonly callId?: string
  readonly reason?: string
  readonly signal?: AbortSignal
}

/** The subset of `ctx.approval` this plugin uses. */
export interface ApprovalService {
  request(request: ApprovalRequest): Promise<ApprovalOutcome>
  readonly config?: { readonly policy?: 'ask' | 'never' }
}

/** One assembled model request, as `llm/stream` receives it. A loop-built request is deep-frozen. */
export interface GenerateOptions {
  readonly provider: string
  readonly model: string
  readonly messages: readonly Message[]
  readonly system?: string
  readonly sessionId?: string
  readonly purpose?: 'compaction' | 'session-title'
}

/** One chunk of a model response stream. */
export interface StreamChunk {
  readonly type: string
  readonly [key: string]: unknown
}

/** The messages entering a proposed step, as `agent/pre-step` receives them. */
export interface PreStepPayload {
  readonly agent?: Agent
  readonly messages?: readonly Message[]
  readonly turn?: number
  readonly step?: number
  readonly signal?: AbortSignal
}

/** Whether and with which messages the loop enters a proposed step. */
export type PreStepDecision =
  | { readonly kind: 'reject' }
  | { readonly kind: 'enter'; readonly messages: readonly Message[] }

type Listener = (...args: never[]) => unknown

/** Register a listener for a dsh event the cordis `Events` interface does not declare. */
export function listen<T extends Listener>(ctx: Context, name: string, listener: T): void {
  ;(ctx as unknown as { on(name: string, listener: T): unknown }).on(name, listener)
}

/**
 * Read the tool registry off the context.
 * @returns the registry, or `undefined` when no tool runtime is mounted.
 */
export function toolRuntime(ctx: Context): ToolRuntime | undefined {
  const runtime = (ctx as unknown as { tools?: unknown }).tools
  if (runtime === undefined || runtime === null) return undefined
  if (typeof (runtime as ToolRuntime).guard !== 'function') return undefined
  return runtime as ToolRuntime
}

/**
 * Read the approval seam off the context.
 *
 * The harness consumes this seam opportunistically with no static inject, and a
 * deployment without it keeps the ask-to-deny degrade. This plugin does the
 * same, so it stays loadable in a composition that mounts no approver.
 *
 * @returns the service, or `undefined` when no approval channel is mounted.
 */
export function approvalService(ctx: Context): ApprovalService | undefined {
  const service = (ctx as unknown as { approval?: unknown }).approval
  if (service === undefined || service === null) return undefined
  if (typeof (service as ApprovalService).request !== 'function') return undefined
  return service as ApprovalService
}
