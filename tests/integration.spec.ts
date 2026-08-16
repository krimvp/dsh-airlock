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
  PostToolDecision,
  PreToolDecision,
  SessionEvent,
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
    on: (event: string, listener: Function) => { listeners.set(event, listener) },
  }
  return { ctx, guards, listeners, warnings }
}

function evidencePath(): string {
  return join(mkdtempSync(join(tmpdir(), 'airlock-int-')), 'decisions.jsonl')
}

function call(name: string, args: Record<string, unknown> = {}): ToolExecution {
  return { callId: `call-${name}`, name, arguments: args, agent: { id: SESSION } }
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

function feed(listeners: Map<string, Function>, events: SessionEvent[]): void {
  const fold = listeners.get('session/event')!
  for (const event of events) fold({ id: SESSION }, event)
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
