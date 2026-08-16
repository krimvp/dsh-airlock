import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { evaluateAsk, evaluateAskDetail, postureHint, resolvePosture } from '../src/ask.js'
import { Declassifier } from '../src/declassify.js'
import type { ApprovalService, SessionEvent, ToolExecution } from '../src/dsh.js'
import { Ledger } from '../src/ledger.js'
import type { Rule } from '../src/policy.js'
import { APPROVAL_SEAM, compileRules, selectRules } from '../src/policy.js'

const SESSION = 'session-1'

/** The ask rules under test: an untrusted context asks before it may mutate. */
const ASK_RULES: readonly Rule[] = selectRules(
  compileRules([
    {
      id: 'untrusted-ask-mutate',
      when: { trust: 'untrusted', capability: 'mutate' },
      then: 'ask',
      rationale: 'untrusted content in context should not change the workspace unattended',
    },
    {
      id: 'secret-ask-mutate',
      when: { sensitivity: 'secret', capability: 'mutate' },
      then: 'ask',
      rationale: 'a secret in context should not be written out unattended',
    },
  ]),
  APPROVAL_SEAM,
)

function call(name: string, callId = 'call-1'): ToolExecution {
  return { callId, name, arguments: {}, agent: { id: SESSION } }
}

function feed(ledger: Ledger, events: SessionEvent[]): void {
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

/** A ledger holding one untrusted page for {@link SESSION}. */
function taintedLedger(): Ledger {
  const ledger = new Ledger()
  feed(ledger, webFetch(1, 2, 'c1'))
  return ledger
}

describe('the ask posture', () => {
  it('asks under the ask posture', () => {
    const decision = evaluateAsk(call('write'), taintedLedger(), ASK_RULES, { posture: 'ask' })
    assert.equal(decision.kind, 'ask')
  })

  it('denies under the deny posture, because nobody is present to consent', () => {
    const decision = evaluateAsk(call('write'), taintedLedger(), ASK_RULES, { posture: 'deny' })
    assert.equal(decision.kind, 'deny')
    assert.match(
      decision.kind === 'deny' ? decision.reason : '',
      /the configured posture is deny/,
    )
  })

  it('lets a deploy-implied hint lower the configured posture', () => {
    const decision = evaluateAsk(
      call('write'),
      taintedLedger(),
      ASK_RULES,
      { posture: 'ask', hint: 'deny' },
    )
    assert.equal(decision.kind, 'deny')
  })

  it('never lets a hint raise the configured posture', () => {
    assert.equal(resolvePosture('deny', 'ask'), 'deny')
    assert.equal(resolvePosture('ask', undefined), 'ask')
    assert.equal(resolvePosture('ask', 'deny'), 'deny')
  })

  it('reads a posture hint out of the harness approval configuration', () => {
    const asking = { request: async () => 'rejected', config: { policy: 'ask' } } as
      unknown as ApprovalService
    const never = { request: async () => 'rejected', config: { policy: 'never' } } as
      unknown as ApprovalService
    assert.equal(postureHint(asking), undefined)
    assert.equal(postureHint(never), 'deny')
    // No approval service means no answerer to route an ask to at all.
    assert.equal(postureHint(undefined), 'deny')
  })

  it('abstains when it has observed no history for the session', () => {
    const decision = evaluateAskDetail(call('write'), new Ledger(), ASK_RULES, { posture: 'ask' })
    assert.equal(decision.decision.kind, 'allow')
    assert.equal(decision.abstained, true)
  })

  it('abstains on a clean session', () => {
    const ledger = new Ledger()
    feed(ledger, [
      { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    ])
    const decision = evaluateAskDetail(call('write'), ledger, ASK_RULES, { posture: 'ask' })
    assert.equal(decision.decision.kind, 'allow')
    assert.equal(decision.abstained, true)
  })

  it('abstains when the call carries no agent', () => {
    const orphan: ToolExecution = { callId: 'call-3', name: 'write', arguments: {} }
    const decision = evaluateAskDetail(orphan, taintedLedger(), ASK_RULES, { posture: 'ask' })
    assert.equal(decision.decision.kind, 'allow')
    assert.equal(decision.abstained, true)
  })

  it('leaves reading open under untrusted context', () => {
    const ledger = taintedLedger()
    for (const tool of ['read', 'glob', 'grep', 'lsp']) {
      assert.equal(
        evaluateAsk(call(tool), ledger, ASK_RULES, { posture: 'ask' }).kind,
        'allow',
        `${tool} must stay open`,
      )
    }
  })

  it('asks about every mutating path identically, whatever the tool', () => {
    const ledger = taintedLedger()
    for (const tool of ['write', 'edit', 'bash', 'run_code', 'mcp__slack__post_message']) {
      assert.equal(
        evaluateAsk(call(tool), ledger, ASK_RULES, { posture: 'ask' }).kind,
        'ask',
        `${tool} must raise the question`,
      )
    }
  })

  it('scopes the ledger to one session', () => {
    const other: ToolExecution = {
      callId: 'call-2',
      name: 'write',
      arguments: {},
      agent: { id: 'session-2' },
    }
    assert.equal(evaluateAsk(other, taintedLedger(), ASK_RULES, { posture: 'ask' }).kind, 'allow')
  })

  it('names the rule, the label, and the origin event in the reason', () => {
    const decision = evaluateAsk(call('write'), taintedLedger(), ASK_RULES, { posture: 'ask' })
    assert.equal(decision.kind, 'ask')
    const reason = decision.kind === 'ask' ? decision.reason ?? '' : ''
    assert.match(reason, /untrusted-ask-mutate/)
    assert.match(reason, /trust=untrusted sensitivity=public/)
    assert.match(reason, /seq 2/)
    assert.match(reason, /web_fetch/)
    assert.match(reason, /Approving covers this one call/)
    assert.match(reason, /another tool or another encoding reaches the same question/)
  })

  it('cites the file rather than the page when the rule is about sensitivity', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const decision = evaluateAsk(call('write'), ledger, ASK_RULES, { posture: 'ask' })
    const reason = decision.kind === 'ask' ? decision.reason ?? '' : ''
    assert.match(reason, /secret-ask-mutate/)
    assert.match(reason, /\.env/)
  })

  it('takes the first matching rule, in the authored order', () => {
    const ledger = new Ledger()
    feed(ledger, [...secretRead(1, 2, 'c1'), ...webFetch(3, 4, 'c2')])
    const decision = evaluateAskDetail(call('write'), ledger, ASK_RULES, { posture: 'ask' })
    assert.equal(decision.rule?.id, 'untrusted-ask-mutate')
  })

  it('honours an allow written above the ask rule', () => {
    const rules = selectRules(
      compileRules([
        {
          id: 'edit-is-fine',
          when: { trust: 'untrusted', capability: 'mutate' },
          then: 'allow',
        },
        {
          id: 'untrusted-ask-mutate',
          when: { trust: 'untrusted', capability: 'mutate' },
          then: 'ask',
        },
      ]),
      APPROVAL_SEAM,
    )
    assert.equal(evaluateAsk(call('write'), taintedLedger(), rules, { posture: 'ask' }).kind, 'allow')
  })
})

describe('declassification at the ask seam', () => {
  /** The context label a `write` under an untrusted page is decided on. */
  const CLEARED_LABEL = { trust: 'untrusted' as const, sensitivity: 'public' as const }

  function cleared(now: () => number = () => 1_000): Declassifier {
    const store = new Declassifier({ now })
    store.grant(SESSION, {
      capability: 'mutate',
      tool: 'write',
      label: CLEARED_LABEL,
      actor: 'operator',
      reason: 'the release notes edit was expected',
      rule: 'untrusted-ask-mutate',
    })
    return store
  }

  it('suppresses the ask while the grant is live', () => {
    const store = cleared()
    const decision = evaluateAskDetail(call('write'), taintedLedger(), ASK_RULES, {
      posture: 'ask',
      declassification: store,
    })
    assert.equal(decision.decision.kind, 'allow')
    assert.equal(decision.abstained, false)
    assert.equal(decision.rule?.id, 'untrusted-ask-mutate')
    assert.equal(decision.declassifiedBy, store.grants(SESSION)[0]?.id)
  })

  it('asks again once the grant is revoked', () => {
    const store = cleared()
    const grant = store.grants(SESSION)[0]!
    assert.equal(store.revoke(SESSION, grant.id), true)
    const decision = evaluateAsk(call('write'), taintedLedger(), ASK_RULES, {
      posture: 'ask',
      declassification: store,
    })
    assert.equal(decision.kind, 'ask')
  })

  it('asks again once the grant has expired', () => {
    let clock = 1_000
    const store = new Declassifier({ now: () => clock, ttlMs: 60_000 })
    store.grant(SESSION, {
      capability: 'mutate',
      tool: 'write',
      label: CLEARED_LABEL,
      actor: 'operator',
      reason: 'a short clearance',
    })
    const options = { posture: 'ask' as const, declassification: store }
    assert.equal(evaluateAsk(call('write'), taintedLedger(), ASK_RULES, options).kind, 'allow')
    clock = 61_001
    assert.equal(evaluateAsk(call('write'), taintedLedger(), ASK_RULES, options).kind, 'ask')
  })

  it('asks again for a tool the grant does not name', () => {
    const decision = evaluateAsk(call('bash'), taintedLedger(), ASK_RULES, {
      posture: 'ask',
      declassification: cleared(),
    })
    assert.equal(decision.kind, 'ask')
  })

  it('never clears a call when declassification is disabled', () => {
    const store = new Declassifier({ allow: false, now: () => 1_000 })
    store.grant(SESSION, {
      capability: 'mutate',
      tool: 'write',
      label: CLEARED_LABEL,
      actor: 'operator',
      reason: 'rejected by configuration',
    })
    const decision = evaluateAsk(call('write'), taintedLedger(), ASK_RULES, {
      posture: 'ask',
      declassification: store,
    })
    assert.equal(decision.kind, 'ask')
  })

  it('keeps a grant inside the session it was given in', () => {
    const other: ToolExecution = {
      callId: 'call-9',
      name: 'write',
      arguments: {},
      agent: { id: 'session-2' },
    }
    const ledger = taintedLedger()
    const session2 = ledger.for('session-2')
    for (const event of webFetch(1, 2, 'c9')) session2.apply(event)
    const decision = evaluateAsk(other, ledger, ASK_RULES, {
      posture: 'ask',
      declassification: cleared(),
    })
    assert.equal(decision.kind, 'ask')
  })
})
