import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type {
  Message,
  MessageSource,
  PreStepDecision,
  PreStepPayload,
  SessionEvent,
} from '../src/dsh.js'
import { Ledger } from '../src/ledger.js'
import type { PreStepPolicy } from '../src/prestep.js'
import {
  applyPreStep,
  enteringLabel,
  evaluatePreStep,
  plannedRedactions,
  producerName,
  rejectionReason,
} from '../src/prestep.js'

const SESSION = 'session-1'

/** One message as the inbox claims it, with the identity the harness assigned. */
function message(id: string, source: MessageSource, text = 'hello'): Message {
  return { id, role: 'user', content: [{ type: 'text', text }], source }
}

function payload(messages: readonly Message[], agentId = SESSION): PreStepPayload {
  return { agent: { id: agentId }, messages, turn: 1, step: 1 }
}

function feed(ledger: Ledger, events: readonly SessionEvent[]): void {
  const session = ledger.for(SESSION)
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

/** A downstream waterfall that records whether the gate reached it. */
interface Downstream {
  readonly next: () => Promise<PreStepDecision>
  called: boolean
  readonly decision: PreStepDecision
}

function downstream(messages: readonly Message[]): Downstream {
  const state: Downstream = {
    called: false,
    decision: { kind: 'enter', messages },
    next: (): Promise<PreStepDecision> => {
      state.called = true
      return Promise.resolve(state.decision)
    },
  }
  return state
}

/** The text of a message's first content block, for assertions only. */
function textOf(entered: Message | undefined): string {
  const block = entered?.content?.[0] as { text?: unknown } | undefined
  return typeof block?.text === 'string' ? block.text : ''
}

const SECRET_PLUGIN: PreStepPolicy = { secretProducers: ['vault-notes'] }

describe('labelling a message entering a step', () => {
  it('names the plugin as the producer, and the kind when there is none', () => {
    assert.equal(producerName({ kind: 'plugin', plugin: 'vault-notes' }), 'vault-notes')
    assert.equal(producerName({ kind: 'user' }), 'user')
    assert.equal(producerName(undefined), 'an unknown producer')
  })

  it('puts human input at the bottom of the lattice', () => {
    assert.deepEqual(
      enteringLabel(message('m1', { kind: 'user' })),
      { trust: 'user', sensitivity: 'public' },
    )
  })

  it('treats produced content as workspace rather than user', () => {
    assert.deepEqual(
      enteringLabel(message('m1', { kind: 'plugin', plugin: 'dsh-skills' })),
      { trust: 'workspace', sensitivity: 'public' },
    )
  })

  it('raises the axis a policy names for that producer', () => {
    assert.deepEqual(
      enteringLabel(message('m1', { kind: 'plugin', plugin: 'vault-notes' }), SECRET_PLUGIN),
      { trust: 'workspace', sensitivity: 'secret' },
    )
    assert.deepEqual(
      enteringLabel(message('m1', { kind: 'plugin', plugin: 'inbox-bridge' }), {
        untrustedProducers: ['inbox-*'],
      }),
      { trust: 'untrusted', sensitivity: 'public' },
    )
  })

  it('reads the producer and never the text', () => {
    // The content says the thing a pattern matcher would fire on. The gate does
    // not look at it, which is the property this project exists to keep.
    const typed = message('m1', { kind: 'user' }, 'AWS_SECRET_ACCESS_KEY=AKIA000')
    assert.deepEqual(enteringLabel(typed, SECRET_PLUGIN), { trust: 'user', sensitivity: 'public' })
  })
})

describe('gate B, evaluated over the payload', () => {
  it('enters the claimed batch unchanged when no policy is configured', () => {
    const ledger = new Ledger()
    const messages = [message('m1', { kind: 'user' })]
    const decision = evaluatePreStep(payload(messages), ledger)
    assert.equal(decision.kind, 'enter')
    assert.equal(decision.kind === 'enter' ? decision.messages[0] : undefined, messages[0])
  })

  it('redacts a secret-labelled message and keeps its identity', () => {
    const ledger = new Ledger()
    const source = { kind: 'plugin', plugin: 'vault-notes', form: 'notice' } as const
    const entering = message('m1', source, 'the deploy key is hunter2')
    const decision = evaluatePreStep(payload([entering]), ledger, SECRET_PLUGIN)

    assert.equal(decision.kind, 'enter')
    const entered = decision.kind === 'enter' ? decision.messages[0] : undefined
    assert.equal(entered?.id, 'm1')
    assert.equal(entered?.role, 'user')
    assert.equal(entered?.source, source)
    assert.match(textOf(entered), /^\[airlock withheld content from vault-notes/)
    assert.doesNotMatch(textOf(entered), /hunter2/)
    // The original message is untouched; the entered batch is a new object.
    assert.equal(textOf(entering), 'the deploy key is hunter2')
  })

  it('leaves every other message in the batch alone', () => {
    const ledger = new Ledger()
    const typed = message('m1', { kind: 'user' }, 'summarise the notes')
    const injected = message('m2', { kind: 'plugin', plugin: 'vault-notes' }, 'hunter2')
    const decision = evaluatePreStep(payload([typed, injected]), ledger, SECRET_PLUGIN)

    assert.equal(decision.kind, 'enter')
    const entered = decision.kind === 'enter' ? decision.messages : []
    assert.equal(entered[0], typed)
    assert.notEqual(entered[1], injected)
    assert.equal(entered.length, 2)
  })

  it('reports what it would redact without acting', () => {
    const injected = message('m2', { kind: 'plugin', plugin: 'vault-notes' })
    const planned = plannedRedactions(payload([injected]), SECRET_PLUGIN)
    assert.deepEqual(planned, [
      { id: 'm2', producer: 'vault-notes', label: { trust: 'workspace', sensitivity: 'secret' } },
    ])
    assert.deepEqual(plannedRedactions(payload([injected])), [])
  })

  it('tolerates a payload the harness shaped differently', () => {
    const ledger = new Ledger()
    const decision = evaluatePreStep({}, ledger, SECRET_PLUGIN)
    assert.deepEqual(decision, { kind: 'enter', messages: [] })
  })
})

describe('rejecting a proposed step', () => {
  it('never rejects when policy names no condition', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    assert.equal(rejectionReason(payload([]), ledger), undefined)
    assert.equal(rejectionReason(payload([]), ledger, { reject: {} }), undefined)
    assert.equal(evaluatePreStep(payload([]), ledger).kind, 'enter')
  })

  it('rejects when policy names a condition the context reaches', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const policy: PreStepPolicy = { reject: { trust: 'untrusted' } }
    const reason = rejectionReason(payload([]), ledger, policy)
    assert.match(reason ?? '', /airlock rejected this step/)
    assert.match(reason ?? '', /seq 2/)
    assert.deepEqual(evaluatePreStep(payload([]), ledger, policy), { kind: 'reject' })
  })

  it('cites the secret when the condition is written over sensitivity', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const reason = rejectionReason(payload([]), ledger, { reject: { sensitivity: 'secret' } })
    assert.match(reason ?? '', /\.env/)
  })

  it('does not reject a context below the condition', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    assert.equal(rejectionReason(payload([]), ledger, { reject: { trust: 'untrusted' } }), undefined)
  })

  it('abstains for a session it has observed no history for', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const policy: PreStepPolicy = { reject: { trust: 'untrusted' } }
    assert.equal(rejectionReason(payload([], 'session-2'), ledger, policy), undefined)
    assert.equal(rejectionReason({ messages: [] }, ledger, policy), undefined)
  })
})

describe('gate B, driving the waterfall', () => {
  it('passes the downstream decision through untouched by default', async () => {
    const ledger = new Ledger()
    const claimed = [message('m1', { kind: 'user' })]
    const down = downstream(claimed)
    const decision = await applyPreStep(payload(claimed), down.next, ledger)
    assert.equal(down.called, true)
    assert.equal(decision, down.decision)
  })

  it('redacts the batch the downstream decision entered, not the claimed one', async () => {
    // The loop's own `next()` appends the projected runtime context to the
    // claimed batch. A gate that rewrote the payload would drop it.
    const ledger = new Ledger()
    const claimed = [message('m1', { kind: 'user' })]
    const context = message('m2', { kind: 'plugin', plugin: 'vault-notes' }, 'hunter2')
    const down = downstream([...claimed, context])

    const decision = await applyPreStep(payload(claimed), down.next, ledger, SECRET_PLUGIN)
    assert.equal(decision.kind, 'enter')
    const entered = decision.kind === 'enter' ? decision.messages : []
    assert.equal(entered.length, 2)
    assert.equal(entered[0], claimed[0])
    assert.equal(entered[1]?.id, 'm2')
    assert.doesNotMatch(textOf(entered[1]), /hunter2/)
  })

  it('rejects without paying for the downstream waterfall', async () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const down = downstream([])
    const decision = await applyPreStep(
      payload([]),
      down.next,
      ledger,
      { reject: { trust: 'untrusted' } },
    )
    assert.deepEqual(decision, { kind: 'reject' })
    assert.equal(down.called, false)
  })

  it('enters the step when its own rejection check fails', async () => {
    // Gate A still stands at the tool boundary, so a bug here degrades one
    // layer rather than ending a turn the policy never asked to end.
    const broken = { peek: (): never => { throw new Error('ledger unavailable') } } as unknown as Ledger
    const claimed = [message('m1', { kind: 'user' })]
    const down = downstream(claimed)
    const decision = await applyPreStep(
      payload(claimed),
      down.next,
      broken,
      { reject: { trust: 'untrusted' } },
    )
    assert.equal(down.called, true)
    assert.equal(decision, down.decision)
  })

  it('keeps the downstream decision when redaction fails', async () => {
    const ledger = new Ledger()
    const hostile = { id: 'm1', role: 'user', source: { get kind(): string { throw new Error('bad source') } } } as unknown as Message
    const down = downstream([hostile])
    const decision = await applyPreStep(payload([]), down.next, ledger, SECRET_PLUGIN)
    assert.equal(decision, down.decision)
  })
})
