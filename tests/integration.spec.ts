/**
 * Integration tests over the mounted plugin.
 *
 * Every other suite tests one module in isolation. These drive `apply()`
 * against a fake context and assert on what the harness would actually see, so
 * a module that works alone but is wired to nothing is caught here.
 */

import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'

import { apply } from '../src/index.js'
import { verifyChain } from '../src/evidence.js'
import type {
  GenerateOptions,
  Message,
  PostToolDecision,
  PreStepDecision,
  PreToolDecision,
  SessionEvent,
  StreamChunk,
  ToolExecution,
  ToolExecutionResult,
  ToolGuard,
} from '../src/dsh.js'

const SESSION = 'session-1'

/** A fake cordis context capturing everything the plugin registers. */
function harness(): {
  ctx: unknown
  guards: ToolGuard[]
  listeners: Map<string, Function>
  warnings: unknown[]
} {
  const guards: ToolGuard[] = []
  const listeners = new Map<string, Function>()
  const warnings: unknown[] = []
  const ctx = {
    logger: {
      debug: () => {},
      info: () => {},
      warn: (...args: unknown[]) => { warnings.push(args[0]) },
      error: () => {},
    },
    effect: () => () => {},
    tools: { guard: (guard: ToolGuard) => { guards.push(guard); return () => {} } },
    // The harness services an ask through this seam after the whole
    // `tools/pre-execute` waterfall. The plugin never calls it; it is present so
    // that `postureHint` does not lower the posture to deny.
    approval: {
      request: async (): Promise<string> => 'allowed-once',
      config: { policy: 'ask' as const },
    },
    on: (event: string, listener: Function) => { listeners.set(event, listener) },
  }
  return { ctx, guards, listeners, warnings }
}

function evidencePath(): string {
  return join(mkdtempSync(join(tmpdir(), 'airlock-int-')), 'decisions.jsonl')
}

function call(
  name: string,
  args: Record<string, unknown> = {},
  callId = `call-${name}`,
  sessionId = SESSION,
): ToolExecution {
  return { callId, name, arguments: args, agent: { id: sessionId } }
}

/** The kill chain: a credential read, then a page carrying an injected instruction. */
function killChain(): SessionEvent[] {
  return [
    { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    {
      type: 'tool/call',
      seq: 2,
      time: 2,
      data: { callId: 'c1', name: 'read', arguments: '{"file_path":"/app/.env"}' },
    },
    {
      type: 'tool/result',
      seq: 3,
      time: 3,
      surfaceOp: 'append',
      data: { message: { source: { kind: 'tool', callId: 'c1' } } },
    },
    {
      type: 'tool/call',
      seq: 4,
      time: 4,
      data: { callId: 'c2', name: 'web_fetch', arguments: '{"url":"https://evil.test"}' },
    },
    {
      type: 'tool/result',
      seq: 5,
      time: 5,
      surfaceOp: 'append',
      data: { message: { source: { kind: 'tool', callId: 'c2' } } },
    },
  ]
}

/** A session whose only history is a fetched page: untrusted, not secret. */
function untrustedPage(): SessionEvent[] {
  return [
    { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    {
      type: 'tool/call',
      seq: 2,
      time: 2,
      data: { callId: 'p1', name: 'web_fetch', arguments: '{"url":"https://evil.test"}' },
    },
    {
      type: 'tool/result',
      seq: 3,
      time: 3,
      surfaceOp: 'append',
      data: { message: { source: { kind: 'tool', callId: 'p1' } } },
    },
  ]
}

/** A session whose only history is a credential read: secret, not untrusted. */
function secretFile(): SessionEvent[] {
  return [
    { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    {
      type: 'tool/call',
      seq: 2,
      time: 2,
      data: { callId: 's1', name: 'read', arguments: '{"file_path":"/app/.env"}' },
    },
    {
      type: 'tool/result',
      seq: 3,
      time: 3,
      surfaceOp: 'append',
      data: { message: { source: { kind: 'tool', callId: 's1' } } },
    },
  ]
}

/**
 * The durable audit pair the approval service appends around one question.
 *
 * Log-only events, exactly as `packages/interaction/user-approval/src/index.ts`
 * writes them at 0.1.0-rc.5. They reach `session/event` and never the model.
 */
function approvalPair(fields: {
  id: string
  toolName: string
  callId: string
  reason?: string
  outcome: string
  seq?: number
}): SessionEvent[] {
  const seq = fields.seq ?? 10
  return [
    {
      type: 'approval/asked',
      seq,
      time: seq,
      data: {
        id: fields.id,
        toolName: fields.toolName,
        callId: fields.callId,
        ...fields.reason === undefined ? {} : { reason: fields.reason },
      },
    },
    {
      type: 'approval/decided',
      seq: seq + 1,
      time: seq + 1,
      data: { id: fields.id, outcome: fields.outcome },
    },
  ]
}

function feed(
  listeners: Map<string, Function>,
  events: SessionEvent[],
  sessionId = SESSION,
): void {
  const fold = listeners.get('session/event')!
  for (const event of events) fold({ id: sessionId }, event)
}

/** Read the reason off an `ask` decision, failing the test when there is none. */
function askReason(decision: PreToolDecision): string {
  assert.equal(decision.kind, 'ask', 'the seam must have raised a question')
  const reason = decision.kind === 'ask' ? decision.reason : undefined
  assert.equal(typeof reason, 'string', 'an airlock ask always carries a reason')
  return reason as string
}

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const chunks: StreamChunk[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return chunks
}

/** A downstream adapter stream that records whether the backstop reached it. */
function downstream(): { next: () => AsyncIterable<StreamChunk>; called: boolean } {
  const state = {
    called: false,
    next: (): AsyncIterable<StreamChunk> => {
      state.called = true
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StreamChunk> {
          yield { type: 'finish', reason: { kind: 'stop' } }
        },
      }
    },
  }
  return state
}

function generateOptions(sessionId = SESSION): GenerateOptions {
  return { provider: 'deepseek', model: 'deepseek-chat', messages: [], sessionId }
}

/** A message a named plugin injected into a step. */
function injected(id: string, plugin: string, text: string): Message {
  return { id, role: 'user', content: [{ type: 'text', text }], source: { kind: 'plugin', plugin } }
}

/** A message the human typed. */
function typed(id: string, text: string): Message {
  return { id, role: 'user', content: [{ type: 'text', text }], source: { kind: 'user' } }
}

/** Read one message's text back out of a pre-step decision. */
function textOf(decision: PreStepDecision, id: string): string {
  assert.equal(decision.kind, 'enter', 'the step must have been entered')
  const messages = decision.kind === 'enter' ? decision.messages : []
  const message = messages.find((candidate) => candidate.id === id)
  assert.ok(message !== undefined, `message ${id} must survive the gate`)
  return JSON.stringify(message.content)
}

describe('the mounted plugin', () => {
  it('registers a guard and every gate seam', async () => {
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })

    assert.equal(guards.length, 1, 'the monotonic guard must be installed')
    for (const seam of [
      'session/event',
      'session/disposed',
      'agent/disposed',
      'tools/pre-execute',
      'tools/post-execute',
      'agent/pre-step',
      'llm/stream',
    ]) {
      assert.ok(listeners.has(seam), `${seam} must be registered`)
    }
  })

  it('denies the exfiltration through every egress tool', async () => {
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })
    feed(listeners, killChain())

    const guard = guards[0]!
    for (const tool of ['bash', 'pwsh', 'run_code', 'web_fetch', 'mcp__pastebin__create']) {
      assert.notEqual(guard(call(tool)), undefined, `${tool} must be denied`)
    }
  })

  it('leaves reading and searching open', async () => {
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })
    feed(listeners, killChain())

    const guard = guards[0]!
    for (const tool of ['read', 'glob', 'grep', 'lsp']) {
      assert.equal(guard(call(tool)), undefined, `${tool} must stay open`)
    }
  })

  it('withholds a secret result by blocking, not by replacing content', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })

    const post = listeners.get('tools/post-execute')!
    const result: ToolExecutionResult = {
      isError: false,
      value: 'AWS_SECRET_ACCESS_KEY=REALKEY',
      content: [{ type: 'text', text: 'AWS_SECRET_ACCESS_KEY=REALKEY' }],
    }
    const decision: PostToolDecision = await post(
      call('read', { file_path: '/app/.env' }),
      result,
      async () => ({ kind: 'accept' }),
    )

    // Replacing content would leave the canonical value readable by a Code Mode
    // program, so only a block actually withholds the secret.
    assert.equal(decision.kind, 'block')
    assert.ok(!JSON.stringify(decision).includes('REALKEY'), 'the secret must not survive')
  })

  it('records decisions to a verifiable hash chain', async () => {
    const path = evidencePath()
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: path, otlp: false } })
    feed(listeners, killChain())

    guards[0]!(call('bash'))
    guards[0]!(call('web_fetch'))

    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    assert.equal(lines.length, 2, 'both denials must be recorded')
    assert.equal(verifyChain(lines), undefined, 'the chain must verify')

    const first = JSON.parse(lines[0]!) as { outcome: string; rule: string; tool: string }
    assert.equal(first.outcome, 'deny')
    assert.equal(first.tool, 'bash')
    assert.ok(first.rule.length > 0, 'the record must name the rule')
  })

  it('denies nothing in dry run, but still records', async () => {
    const path = evidencePath()
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { dryRun: true, evidence: { jsonl: path, otlp: false } })
    feed(listeners, killChain())

    assert.equal(guards[0]!(call('bash')), undefined, 'dry run must not deny')
    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    assert.equal(verifyChain(lines), undefined)
    assert.equal((JSON.parse(lines[0]!) as { outcome: string }).outcome, 'allow')
  })

  it('abstains on a session it has never seen', async () => {
    const { ctx, guards } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })
    assert.equal(guards[0]!(call('bash')), undefined)
  })

  it('forgets a session when it is disposed', async () => {
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })
    feed(listeners, killChain())
    assert.notEqual(guards[0]!(call('bash')), undefined)

    listeners.get('session/disposed')!({ id: SESSION })
    assert.equal(guards[0]!(call('bash')), undefined, 'a dropped session carries no labels')
  })

  it('refuses a malformed policy at load rather than running without it', async () => {
    const { ctx } = harness()
    await assert.rejects(
      () => apply(ctx as never, { posture: 'sometimes' }),
      /posture/i,
      'a typo in a security policy must fail loudly',
    )
  })

  it('honours a policy that reclassifies a tool', async () => {
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: false, otlp: false },
      classes: { egress: ['courier'] },
    })
    feed(listeners, killChain())

    assert.notEqual(guards[0]!(call('courier')), undefined, 'a configured egress tool is denied')
  })

  it('mounts without a tool runtime instead of crashing', async () => {
    const { ctx, listeners, warnings } = harness()
    delete (ctx as { tools?: unknown }).tools
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })

    assert.ok(warnings.length > 0, 'the missing runtime must be reported')
    assert.ok(listeners.has('session/event'), 'the ledger still follows the log')
  })

  it('survives a malformed session event', async () => {
    const { ctx, listeners, warnings } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })

    const fold = listeners.get('session/event')!
    assert.doesNotThrow(() => fold({ id: SESSION }, undefined))
    assert.ok(warnings.length > 0, 'the failure must be reported, not swallowed silently')
  })
})

/** One `ask` rule, so the ask seam is the only thing deciding. */
const ASK_EGRESS = {
  id: 'ask-egress',
  when: { trust: 'untrusted' as const, capability: 'egress' as const },
  then: 'ask' as const,
}

const NEXT_ALLOW = async (): Promise<PreToolDecision> => ({ kind: 'allow' })

describe('an approved ask, becoming a clearance', () => {
  it('records a grant and permits the next matching call', async () => {
    const path = evidencePath()
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: path, otlp: false }, rules: [ASK_EGRESS] })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    const first: PreToolDecision = await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW)
    const reason = askReason(first)

    // The harness services the ask through `ctx.approval` after this waterfall
    // and appends the audit pair. The plugin only ever sees these two events.
    feed(listeners, approvalPair({
      id: 'a1',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason,
      outcome: 'allowed-once',
    }))

    const second: PreToolDecision = await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)
    assert.equal(second.kind, 'allow', 'the recorded clearance must answer the question again')

    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    assert.equal(verifyChain(lines), undefined, 'the chain must verify')
    assert.deepEqual(
      lines.map((line) => (JSON.parse(line) as { outcome: string }).outcome),
      ['ask', 'declassify', 'declassify'],
    )

    const granted = JSON.parse(lines[1]!) as { origin: string; tool: string; rule: string }
    assert.equal(granted.tool, 'web_fetch')
    assert.equal(granted.rule, 'ask-egress')
    assert.match(granted.origin, /cleared trust=untrusted sensitivity=secret/)
  })

  it('clears only the tool the human approved', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules: [ASK_EGRESS] })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    const reason = askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))
    feed(listeners, approvalPair({
      id: 'a1',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason,
      outcome: 'allowed-once',
    }))

    const other: PreToolDecision = await pre(call('bash', {}, 'c-2'), NEXT_ALLOW)
    assert.equal(other.kind, 'ask', 'a grant for one tool must not cover another')
  })

  it('grants nothing from another plugin\'s approval', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules: [ASK_EGRESS] })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))

    // A different question, about a different call, answered in this session.
    feed(listeners, approvalPair({
      id: 'a2',
      toolName: 'write',
      callId: 'c-other',
      reason: 'another plugin asks before writing',
      outcome: 'allowed-once',
    }))

    const second: PreToolDecision = await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)
    assert.equal(second.kind, 'ask', 'an unrelated approval must not clear an airlock label')
  })

  it('grants nothing when the question a human answered was worded by someone else', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules: [ASK_EGRESS] })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))

    // The call id and the tool match, but the human read another plugin's
    // wording. Airlock cannot claim consent for a question it did not put.
    feed(listeners, approvalPair({
      id: 'a3',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason: 'some other plugin re-asked about this call',
      outcome: 'allowed-once',
    }))

    const second: PreToolDecision = await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)
    assert.equal(second.kind, 'ask')
  })

  for (const outcome of ['rejected', 'cancelled', 'unavailable']) {
    it(`grants nothing on ${outcome}`, async () => {
      const { ctx, listeners } = harness()
      await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules: [ASK_EGRESS] })
      feed(listeners, killChain())

      const pre = listeners.get('tools/pre-execute')!
      const reason = askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))
      feed(listeners, approvalPair({
        id: 'a1',
        toolName: 'web_fetch',
        callId: 'c-1',
        reason,
        outcome,
      }))

      const second: PreToolDecision = await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)
      assert.equal(second.kind, 'ask', `${outcome} must leave the rule standing`)
    })
  }

  it('grants nothing when declassification is disabled', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: false, otlp: false },
      rules: [ASK_EGRESS],
      declassify: { allow: false },
    })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    const reason = askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))
    feed(listeners, approvalPair({
      id: 'a1',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason,
      outcome: 'allowed-once',
    }))

    const second: PreToolDecision = await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)
    assert.equal(second.kind, 'ask')
  })

  it('does not let a clearance outlive its session', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules: [ASK_EGRESS] })
    feed(listeners, killChain())

    const pre = listeners.get('tools/pre-execute')!
    const reason = askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))
    feed(listeners, approvalPair({
      id: 'a1',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason,
      outcome: 'allowed-once',
    }))
    assert.equal((await pre(call('web_fetch', {}, 'c-2'), NEXT_ALLOW)).kind, 'allow')

    listeners.get('session/disposed')!({ id: SESSION })
    feed(listeners, killChain())
    const after: PreToolDecision = await pre(call('web_fetch', {}, 'c-3'), NEXT_ALLOW)
    assert.equal(after.kind, 'ask', 'a disposed session keeps none of its clearances')
  })

  it('clears the monotonic guard too, once a human has approved', async () => {
    const path = evidencePath()
    const { ctx, guards, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: path, otlp: false },
      // The same condition at both seams: the guard denies, the ask seam asks.
      rules: [
        ASK_EGRESS,
        { id: 'deny-egress', when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
      ],
    })
    feed(listeners, killChain())
    assert.notEqual(guards[0]!(call('web_fetch', {}, 'c-0')), undefined, 'the guard denies first')

    const pre = listeners.get('tools/pre-execute')!
    const reason = askReason(await pre(call('web_fetch', {}, 'c-1'), NEXT_ALLOW))
    feed(listeners, approvalPair({
      id: 'a1',
      toolName: 'web_fetch',
      callId: 'c-1',
      reason,
      outcome: 'allowed-once',
    }))

    assert.equal(guards[0]!(call('web_fetch', {}, 'c-2')), undefined, 'the clearance reaches Gate A')

    const lines = readFileSync(path, 'utf8').trimEnd().split('\n')
    assert.equal(verifyChain(lines), undefined)
    const last = JSON.parse(lines[lines.length - 1]!) as { outcome: string; origin: string }
    assert.equal(last.outcome, 'declassify')
    assert.match(last.origin, /^grant airlock-grant-\d+: the approval answerer cleared /)
  })
})

describe('the entering-message gate, as configured', () => {
  it('redacts a producer the preStep section classifies as secret', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: false, otlp: false },
      preStep: { secretProducers: ['vault'] },
    })

    const gate = listeners.get('agent/pre-step')!
    const messages = [typed('m1', 'please deploy'), injected('m2', 'vault', 'AWS_KEY=REALKEY')]
    const decision: PreStepDecision = await gate(
      { agent: { id: SESSION }, messages },
      async () => ({ kind: 'enter', messages }),
    )

    assert.ok(!JSON.stringify(decision).includes('REALKEY'), 'the secret must not enter the step')
    assert.match(textOf(decision, 'm2'), /airlock withheld content from vault/)
    assert.match(textOf(decision, 'm1'), /please deploy/)
  })

  it('redacts nothing when the section is absent', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, { evidence: { jsonl: false, otlp: false } })

    const gate = listeners.get('agent/pre-step')!
    const messages = [injected('m2', 'vault', 'AWS_KEY=REALKEY')]
    const decision: PreStepDecision = await gate(
      { agent: { id: SESSION }, messages },
      async () => ({ kind: 'enter', messages }),
    )
    assert.match(textOf(decision, 'm2'), /REALKEY/, 'the gate is inert until it is configured')
  })

  it('rejects a step when preStep.reject names the axis', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: false, otlp: false },
      preStep: { reject: { sensitivity: 'secret' } },
    })
    feed(listeners, secretFile())

    const gate = listeners.get('agent/pre-step')!
    const decision: PreStepDecision = await gate(
      { agent: { id: SESSION }, messages: [] },
      async () => ({ kind: 'enter', messages: [] }),
    )
    assert.equal(decision.kind, 'reject')
  })

  it('leaves a step below the rejection threshold alone', async () => {
    const { ctx, listeners } = harness()
    await apply(ctx as never, {
      evidence: { jsonl: false, otlp: false },
      preStep: { reject: { sensitivity: 'secret' } },
    })
    feed(listeners, untrustedPage())

    const gate = listeners.get('agent/pre-step')!
    const decision: PreStepDecision = await gate(
      { agent: { id: SESSION }, messages: [] },
      async () => ({ kind: 'enter', messages: [] }),
    )
    assert.equal(decision.kind, 'enter')
  })
})

const PROVIDER_TRUST_RULE = {
  id: 'no-untrusted-at-provider',
  when: { trust: 'untrusted' as const, boundary: 'provider' as const },
  then: 'redact' as const,
}

const PROVIDER_SECRET_RULE = {
  id: 'no-secret-at-provider',
  when: { sensitivity: 'secret' as const, boundary: 'provider' as const },
  then: 'redact' as const,
}

const UNTRUSTED_SESSION = 'session-untrusted'
const SECRET_SESSION = 'session-secret'

/**
 * Mount the plugin with provider rules, and give it one session per axis.
 * @param rules - the provider rules to arm the backstop with.
 * @param config - anything else the mount config should carry.
 * @returns the `llm/stream` listener.
 */
async function providerSeam(
  rules: readonly unknown[],
  config: Record<string, unknown> = {},
): Promise<Function> {
  const { ctx, listeners } = harness()
  await apply(ctx as never, { evidence: { jsonl: false, otlp: false }, rules, ...config })
  feed(listeners, untrustedPage(), UNTRUSTED_SESSION)
  feed(listeners, secretFile(), SECRET_SESSION)
  return listeners.get('llm/stream')!
}

/**
 * Drive one request through the mounted backstop.
 * @param stream - the `llm/stream` listener.
 * @param options - the assembled request.
 * @returns whether the adapter was reached, and the chunks that came back.
 */
async function through(
  stream: Function,
  options: GenerateOptions,
): Promise<{ reached: boolean; chunks: StreamChunk[] }> {
  const down = downstream()
  const chunks = await collect(stream(options, down.next) as AsyncIterable<StreamChunk>)
  return { reached: down.called, chunks }
}

describe('the provider backstop, armed by the rule the operator wrote', () => {
  it('blocks on trust, and does not become a sensitivity rule', async () => {
    const stream = await providerSeam([PROVIDER_TRUST_RULE])

    const blocked = await through(stream, generateOptions(UNTRUSTED_SESSION))
    assert.equal(blocked.reached, false, 'an untrusted context must not reach the provider')
    assert.match(String(blocked.chunks[1]?.['text']), /trust=untrusted/)

    const open = await through(stream, generateOptions(SECRET_SESSION))
    assert.equal(open.reached, true, 'a trust rule must not silently block on sensitivity')
  })

  it('blocks on sensitivity, and does not become a trust rule', async () => {
    const stream = await providerSeam([PROVIDER_SECRET_RULE])

    const blocked = await through(stream, generateOptions(SECRET_SESSION))
    assert.equal(blocked.reached, false, 'a secret context must not reach the provider')
    assert.match(String(blocked.chunks[1]?.['text']), /sensitivity=secret/)
    assert.match(String(blocked.chunks[1]?.['text']), /\.env/)

    const open = await through(stream, generateOptions(UNTRUSTED_SESSION))
    assert.equal(open.reached, true, 'a sensitivity rule must not silently block on trust')
  })

  it('blocks when any of several rules matches', async () => {
    const stream = await providerSeam([PROVIDER_TRUST_RULE, PROVIDER_SECRET_RULE])
    assert.equal((await through(stream, generateOptions(UNTRUSTED_SESSION))).reached, false)
    assert.equal((await through(stream, generateOptions(SECRET_SESSION))).reached, false)
  })

  it('honours a provider allow written above the rule it excepts', async () => {
    const stream = await providerSeam([
      { id: 'let-fetches-through', when: { trust: 'untrusted', boundary: 'provider' }, then: 'allow' },
      PROVIDER_TRUST_RULE,
    ])
    assert.equal((await through(stream, generateOptions(UNTRUSTED_SESSION))).reached, true)
  })

  it('stays disabled when the policy arms no provider rule', async () => {
    const stream = await providerSeam([])
    assert.equal((await through(stream, generateOptions(SECRET_SESSION))).reached, true)
    assert.equal((await through(stream, generateOptions(UNTRUSTED_SESSION))).reached, true)
  })

  it('claims auxiliary calls only when backstop.auxiliary says so', async () => {
    const open = await providerSeam([PROVIDER_SECRET_RULE])
    const compaction: GenerateOptions = {
      ...generateOptions(SECRET_SESSION),
      purpose: 'compaction',
    }
    assert.equal((await through(open, compaction)).reached, true, 'compaction stays open by default')

    const claimed = await providerSeam([PROVIDER_SECRET_RULE], { backstop: { auxiliary: true } })
    assert.equal((await through(claimed, compaction)).reached, false)
  })
})
