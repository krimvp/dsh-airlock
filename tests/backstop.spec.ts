import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { GenerateOptions, SessionEvent, StreamChunk } from '../src/dsh.js'
import type { BackstopPolicy, BackstopRule } from '../src/backstop.js'
import { backstopStream, refusalStream, shouldBlockRequest } from '../src/backstop.js'
import { sensitivityAtLeast, trustAtLeast } from '../src/labels.js'
import { Ledger } from '../src/ledger.js'

const SESSION = 'session-1'

const ENABLED: BackstopPolicy = { enabled: true }

function request(overrides: Partial<GenerateOptions> = {}): GenerateOptions {
  return {
    provider: 'deepseek',
    model: 'deepseek-chat',
    messages: [],
    sessionId: SESSION,
    ...overrides,
  }
}

function feed(ledger: Ledger, events: readonly SessionEvent[], sessionId = SESSION): void {
  const session = ledger.for(sessionId)
  for (const event of events) session.apply(event)
}

function webFetch(callSeq: number, resultSeq: number, callId: string): SessionEvent[] {
  return [
    {
      type: 'tool/call',
      seq: callSeq,
      time: callSeq,
      data: { callId, name: 'web_fetch', arguments: '{"url":"https://evil.test"}' },
    },
    {
      type: 'tool/result',
      seq: resultSeq,
      time: resultSeq,
      surfaceOp: 'append',
      data: { message: { role: 'user', source: { kind: 'tool', callId }, content: [] } },
    },
  ]
}

function secretRead(callSeq: number, resultSeq: number, callId: string): SessionEvent[] {
  return [
    {
      type: 'tool/call',
      seq: callSeq,
      time: callSeq,
      data: { callId, name: 'read', arguments: '{"file_path":"/srv/app/.env"}' },
    },
    {
      type: 'tool/result',
      seq: resultSeq,
      time: resultSeq,
      surfaceOp: 'append',
      data: { message: { role: 'user', source: { kind: 'tool', callId }, content: [] } },
    },
  ]
}

/** A downstream adapter stream that records whether the backstop reached it. */
interface Downstream {
  readonly next: () => AsyncIterable<StreamChunk>
  called: boolean
  consumed: boolean
}

function downstream(): Downstream {
  const state: Downstream = {
    called: false,
    consumed: false,
    next: (): AsyncIterable<StreamChunk> => {
      state.called = true
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<StreamChunk> {
          state.consumed = true
          yield { type: 'text-delta', index: 0, text: 'the model answered' }
          yield { type: 'finish', reason: { kind: 'stop' } }
        },
      }
    },
  }
  return state
}

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const chunks: StreamChunk[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return chunks
}

/**
 * Enforce the harness's stream grammar over a chunk run.
 *
 * This mirrors `packages/llm/llm/src/invariant.ts:36-84` at 0.1.0-rc.5. A
 * short-circuit that fails here would reach a consumer's switch as a chunk the
 * union does not describe.
 */
function assertValidStream(chunks: readonly StreamChunk[]): void {
  const open = new Map<number, unknown>()
  let usageSeen = false
  let finished = false

  for (const chunk of chunks) {
    assert.equal(finished, false, `${chunk.type} follows the terminal finish`)
    const index = chunk['index']
    switch (chunk.type) {
      case 'block-start':
        assert.equal(typeof index, 'number')
        assert.equal(open.has(index as number), false, 'repeated block-start index')
        open.set(index as number, chunk['blockType'])
        break
      case 'text-delta':
        assert.equal(open.get(index as number), 'text', 'a text delta needs an open text block')
        assert.equal(typeof chunk['text'], 'string')
        break
      case 'block-end': {
        const blockType = open.get(index as number)
        assert.notEqual(blockType, undefined, 'block-end with no open block')
        const block = chunk['block'] as { type?: unknown } | undefined
        assert.equal(block?.type, blockType, 'block-end closes another type')
        open.delete(index as number)
        break
      }
      case 'usage':
        assert.equal(usageSeen, false, 'usage more than once')
        usageSeen = true
        break
      case 'finish': {
        const reason = chunk['reason'] as { kind?: unknown } | undefined
        assert.equal(typeof reason?.kind, 'string', 'finish carries a reason kind')
        assert.equal(open.size, 0, 'finish with open blocks')
        finished = true
        break
      }
      default:
        assert.fail(`unknown chunk type ${chunk.type}`)
    }
  }

  assert.equal(finished, true, 'the stream ended without a terminal finish')
}

describe('the provider backstop, deciding', () => {
  it('is disabled by default, even with a secret in context', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    assert.deepEqual(shouldBlockRequest(request(), ledger), { blocked: false })
    assert.deepEqual(shouldBlockRequest(request(), ledger, {}), { blocked: false })
    assert.deepEqual(shouldBlockRequest(request(), ledger, { enabled: false }), { blocked: false })
  })

  it('blocks a secret context once an operator enables it', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const decision = shouldBlockRequest(request(), ledger, ENABLED)
    assert.equal(decision.blocked, true)
    assert.match(decision.blocked ? decision.reason : '', /airlock blocked this model request/)
    assert.match(decision.blocked ? decision.reason : '', /\.env/)
  })

  it('leaves an enabled backstop silent on a context below the threshold', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    assert.deepEqual(shouldBlockRequest(request(), ledger, ENABLED), { blocked: false })
  })

  it('reads the trust axis when the policy names it', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const policy: BackstopPolicy = { enabled: true, trust: 'untrusted' }
    assert.equal(shouldBlockRequest(request(), ledger, policy).blocked, true)
  })

  it('keys off the session id, because this seam is not scope-filtered', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    feed(ledger, [
      { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    ], 'session-2')

    assert.equal(shouldBlockRequest(request(), ledger, ENABLED).blocked, true)
    assert.deepEqual(
      shouldBlockRequest(request({ sessionId: 'session-2' }), ledger, ENABLED),
      { blocked: false },
    )
    assert.deepEqual(
      shouldBlockRequest(request({ sessionId: 'session-3' }), ledger, ENABLED),
      { blocked: false },
    )
  })

  it('abstains on a request the loop stamped no session on', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const handBuilt: GenerateOptions = { provider: 'deepseek', model: 'deepseek-chat', messages: [] }
    assert.deepEqual(shouldBlockRequest(handBuilt, ledger, ENABLED), { blocked: false })
  })

  it('leaves auxiliary calls alone unless the policy claims them', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    for (const purpose of ['compaction', 'session-title'] as const) {
      assert.deepEqual(
        shouldBlockRequest(request({ purpose }), ledger, ENABLED),
        { blocked: false },
        `${purpose} must stay open`,
      )
      assert.equal(
        shouldBlockRequest(request({ purpose }), ledger, { ...ENABLED, auxiliary: true }).blocked,
        true,
        `${purpose} must block when the policy claims it`,
      )
    }
  })
})

describe('the provider backstop, streaming', () => {
  it('reaches the adapter when nothing blocks', async () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const down = downstream()
    const chunks = await collect(backstopStream(request(), down.next, ledger))
    assert.equal(down.called, true)
    assert.equal(down.consumed, true)
    assert.equal(chunks.length, 2)
  })

  it('short-circuits without calling next, and yields a valid terminal finish', async () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const down = downstream()
    const chunks = await collect(backstopStream(request(), down.next, ledger, ENABLED))

    assert.equal(down.called, false, 'the adapter must not be reached')
    assert.equal(down.consumed, false, 'the adapter stream must not be consumed')
    assertValidStream(chunks)
    assert.deepEqual(chunks[0], { type: 'block-start', index: 0, blockType: 'text' })
    assert.equal(chunks[1]?.type, 'text-delta')
    assert.equal(chunks[2]?.type, 'block-end')
    assert.deepEqual(chunks[3], { type: 'finish', reason: { kind: 'stop' } })
    assert.equal(chunks.length, 4)
    assert.match(String(chunks[1]?.['text']), /no content left the machine/)
  })

  it('yields a stream the harness grammar accepts', async () => {
    assertValidStream(await collect(refusalStream('blocked')))
  })

  it('passes through when a disabled backstop fails internally', async () => {
    const broken = { peek: (): never => { throw new Error('ledger unavailable') } } as unknown as Ledger
    const down = downstream()
    // Nothing was armed, so a bug here must not become the first denial.
    const chunks = await collect(backstopStream(request(), down.next, broken))
    assert.equal(down.consumed, true)
    assert.equal(chunks.length, 2)
  })

  it('refuses when an enabled backstop fails internally', async () => {
    const broken = { peek: (): never => { throw new Error('ledger unavailable') } } as unknown as Ledger
    const down = downstream()
    // An operator who armed a last-resort deny asked for uncertainty to resolve
    // closed, and the refusal names itself so the failure is visible at once.
    const chunks = await collect(backstopStream(request(), down.next, broken, ENABLED))
    assert.equal(down.called, false)
    assertValidStream(chunks)
    assert.match(String(chunks[1]?.['text']), /provider backstop failed: ledger unavailable/)
  })
})

/** A rule as `compileRule` produces one, reduced to what this seam reads. */
function rule(
  id: string,
  when: { trust?: 'user' | 'workspace' | 'untrusted'; sensitivity?: 'public' | 'confidential' | 'secret' },
): BackstopRule {
  return {
    id,
    when,
    matches: (label) =>
      (when.trust === undefined || trustAtLeast(label, when.trust))
      && (when.sensitivity === undefined || sensitivityAtLeast(label, when.sensitivity)),
  }
}

describe('the provider backstop, deciding from the rules an operator wrote', () => {
  it('blocks on the trust axis a rule names, and not on sensitivity', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    feed(ledger, secretRead(1, 2, 'c2'), 'session-2')
    const policy: BackstopPolicy = { enabled: true, rules: [rule('r', { trust: 'untrusted' })] }

    assert.equal(shouldBlockRequest(request(), ledger, policy).blocked, true)
    assert.deepEqual(
      shouldBlockRequest(request({ sessionId: 'session-2' }), ledger, policy),
      { blocked: false },
      'a trust rule must not become a sensitivity rule',
    )
  })

  it('blocks on the sensitivity axis a rule names, and not on trust', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    feed(ledger, secretRead(1, 2, 'c2'), 'session-2')
    const policy: BackstopPolicy = { enabled: true, rules: [rule('r', { sensitivity: 'secret' })] }

    assert.deepEqual(shouldBlockRequest(request(), ledger, policy), { blocked: false })
    assert.equal(
      shouldBlockRequest(request({ sessionId: 'session-2' }), ledger, policy).blocked,
      true,
    )
  })

  it('blocks when any rule of several matches', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    feed(ledger, secretRead(1, 2, 'c2'), 'session-2')
    const policy: BackstopPolicy = {
      enabled: true,
      rules: [rule('trust', { trust: 'untrusted' }), rule('secret', { sensitivity: 'secret' })],
    }

    assert.equal(shouldBlockRequest(request(), ledger, policy).blocked, true)
    assert.equal(
      shouldBlockRequest(request({ sessionId: 'session-2' }), ledger, policy).blocked,
      true,
    )
  })

  it('cites the origin of the axis the matching rule constrained', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const decision = shouldBlockRequest(request(), ledger, {
      enabled: true,
      rules: [rule('r', { sensitivity: 'secret' })],
    })
    assert.match(decision.blocked ? decision.reason : '', /\.env/)
  })

  it('ignores the threshold pair once a rule list is present', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    // The default threshold would block a secret context; an empty rule list is
    // what the operator wrote, and it says nothing blocks.
    assert.deepEqual(
      shouldBlockRequest(request(), ledger, { enabled: true, rules: [] }),
      { blocked: false },
    )
  })

  it('reads no rule while it is disabled', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    assert.deepEqual(
      shouldBlockRequest(request(), ledger, { rules: [rule('r', { sensitivity: 'public' })] }),
      { blocked: false },
    )
  })
})
