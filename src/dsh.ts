/*
 * Local structural copies of the dsh payload types.
 *
 * Source: https://github.com/deepseek-ai/deepseek-harness at 0.1.0-rc.5.
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
