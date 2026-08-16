import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { SessionEvent, ToolExecution } from '../src/dsh.js'
import { evaluate } from '../src/gate.js'
import { Ledger } from '../src/ledger.js'
import { DEFAULT_RULES } from '../src/policy.js'

const SESSION = 'session-1'

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

describe('the capability gate', () => {
  it('abstains when it has observed no history for the session', () => {
    const ledger = new Ledger()
    assert.equal(evaluate(call('bash'), ledger, DEFAULT_RULES).reason, undefined)
  })

  it('abstains on a clean session', () => {
    const ledger = new Ledger()
    feed(ledger, [
      { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
    ])
    assert.equal(evaluate(call('bash'), ledger, DEFAULT_RULES).reason, undefined)
  })

  it('denies egress once untrusted content is in context', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const decision = evaluate(call('web_fetch'), ledger, DEFAULT_RULES)
    assert.equal(decision.rule?.id, 'untrusted-no-egress')
    assert.match(decision.reason!, /airlock denied/)
  })

  it('denies every egress path identically, whatever the tool', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    // The model reformulates: curl, then a shell, then an MCP server, then a
    // Code Mode program. The rule reads the context, not the command.
    for (const tool of ['bash', 'pwsh', 'run_code', 'mcp__slack__post_message', 'terminal_send']) {
      const decision = evaluate(call(tool), ledger, DEFAULT_RULES)
      assert.equal(decision.rule?.id, 'untrusted-no-egress', `${tool} must be denied`)
    }
  })

  it('leaves reading and searching open under untrusted context', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    for (const tool of ['read', 'glob', 'grep', 'lsp']) {
      assert.equal(
        evaluate(call(tool), ledger, DEFAULT_RULES).reason,
        undefined,
        `${tool} must stay open`,
      )
    }
  })

  it('leaves writing open under untrusted context in this milestone', () => {
    // Restricting mutation is an `ask`, and a guard cannot ask. The policy file
    // adds that rule at the pre-execute seam; see the README.
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    assert.equal(evaluate(call('write'), ledger, DEFAULT_RULES).reason, undefined)
  })

  it('denies egress once a secret is in context', () => {
    const ledger = new Ledger()
    feed(ledger, secretRead(1, 2, 'c1'))
    const decision = evaluate(call('bash'), ledger, DEFAULT_RULES)
    assert.equal(decision.rule?.id, 'secret-no-egress')
  })

  it('names the rule and the origin event in the denial', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const reason = evaluate(call('bash'), ledger, DEFAULT_RULES).reason!
    assert.match(reason, /untrusted-no-egress/)
    assert.match(reason, /seq 2/)
    assert.match(reason, /web_fetch/)
    assert.match(reason, /another tool or another encoding reaches the same denial/)
  })

  it('points a secret denial at the file, not at the web page', () => {
    const ledger = new Ledger()
    feed(ledger, [...webFetch(1, 2, 'c1'), ...secretRead(3, 4, 'c2')])
    const decision = evaluate(call('bash'), ledger, DEFAULT_RULES)
    // Untrusted is checked first, so that rule fires and cites the page.
    assert.equal(decision.rule?.id, 'untrusted-no-egress')
    assert.match(decision.reason!, /web_fetch/)
  })

  it('reports the capability classes it derived', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const decision = evaluate(call('bash'), ledger, DEFAULT_RULES)
    assert.deepEqual([...decision.capabilities].sort(), ['egress', 'mutate'])
  })

  it('scopes the ledger to one session', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const other: ToolExecution = {
      callId: 'call-2',
      name: 'bash',
      arguments: {},
      agent: { id: 'session-2' },
    }
    assert.equal(evaluate(other, ledger, DEFAULT_RULES).reason, undefined)
  })

  it('abstains when the call carries no agent', () => {
    const ledger = new Ledger()
    feed(ledger, webFetch(1, 2, 'c1'))
    const orphan: ToolExecution = { callId: 'call-3', name: 'bash', arguments: {} }
    assert.equal(evaluate(orphan, ledger, DEFAULT_RULES).reason, undefined)
  })
})

describe('the kill chain the milestone exists to break', () => {
  it('stops a poisoned page from exfiltrating a key through a shell', () => {
    const ledger = new Ledger()

    // 1. The user asks for something ordinary.
    // 2. The agent reads a repository file holding credentials.
    // 3. The agent fetches a page that carries an injected instruction.
    // 4. The agent tries to POST the key out through a shell one-liner.
    feed(ledger, [
      { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
      ...secretRead(2, 3, 'c1'),
      ...webFetch(4, 5, 'c2'),
    ])

    const context = ledger.for(SESSION).contextLabel()
    assert.deepEqual(context.label, { trust: 'untrusted', sensitivity: 'secret' })

    const decision = evaluate(call('bash'), ledger, DEFAULT_RULES)
    assert.notEqual(decision.reason, undefined, 'the exfiltration must be denied')
  })

  it('still denies after the evidence is compacted away', () => {
    const ledger = new Ledger()
    feed(ledger, [
      { type: 'user/message', seq: 1, time: 1, surfaceOp: 'append', data: { source: { kind: 'user' } } },
      ...secretRead(2, 3, 'c1'),
      ...webFetch(4, 5, 'c2'),
      {
        type: 'user/message',
        seq: 6,
        time: 6,
        surfaceOp: { op: 'replace', start: 1, end: 5 },
        sourceEventSeqs: [1, 3, 5],
        data: { source: { kind: 'plugin', plugin: 'dsh-compaction-basic' } },
      },
    ])

    assert.deepEqual(ledger.for(SESSION).surfaceSeqs(), [6])
    const decision = evaluate(call('bash'), ledger, DEFAULT_RULES)
    assert.notEqual(decision.reason, undefined, 'compaction must not clear the restriction')
  })
})
