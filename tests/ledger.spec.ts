import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { SessionEvent } from '../src/dsh.js'
import { SessionLedger, resultLabelFor } from '../src/ledger.js'
import type { OpaqueReaders } from '../src/policy.js'

function userMessage(at: number, kind = 'user', plugin?: string): SessionEvent {
  return {
    type: 'user/message',
    seq: at,
    time: at,
    surfaceOp: 'append',
    data: { source: plugin === undefined ? { kind } : { kind, plugin }, content: [] },
  }
}

function toolCall(at: number, callId: string, name: string, args: unknown): SessionEvent {
  return {
    type: 'tool/call',
    seq: at,
    time: at,
    data: { callId, name, arguments: JSON.stringify(args) },
  }
}

function toolResult(at: number, callId: string): SessionEvent {
  return {
    type: 'tool/result',
    seq: at,
    time: at,
    surfaceOp: 'append',
    data: { message: { role: 'user', source: { kind: 'tool', callId }, content: [] } },
  }
}

function assistantMessage(at: number, sources: number[]): SessionEvent {
  return {
    type: 'assistant/message',
    seq: at,
    time: at,
    surfaceOp: 'append',
    sourceEventSeqs: sources,
    data: { message: { role: 'assistant', source: { kind: 'model' }, content: [] } },
  }
}

/** A compaction node replacing the surface range, citing every node it shadows. */
function compaction(at: number, start: number, end: number, shadowed: number[]): SessionEvent {
  return {
    type: 'user/message',
    seq: at,
    time: at,
    surfaceOp: { op: 'replace', start, end },
    sourceEventSeqs: shadowed,
    data: { source: { kind: 'plugin', plugin: 'dsh-compaction-basic' }, content: [] },
  }
}

describe('intrinsic labels', () => {
  it('labels a typed message as the lattice bottom', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    assert.deepEqual(ledger.contextLabel().label, { trust: 'user', sensitivity: 'public' })
  })

  it('separates injected context from human typing', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1, 'plugin', 'dsh-tool-skill'))
    const context = ledger.contextLabel()
    assert.equal(context.label.trust, 'workspace')
    assert.match(context.trustOrigin!.description, /dsh-tool-skill/)
  })

  it('labels a web fetch result untrusted', () => {
    const ledger = new SessionLedger()
    ledger.apply(toolCall(1, 'c1', 'web_fetch', { url: 'https://example.test' }))
    ledger.apply(toolResult(2, 'c1'))
    assert.equal(ledger.contextLabel().label.trust, 'untrusted')
  })

  it('labels a read of a secret path secret', () => {
    const ledger = new SessionLedger()
    ledger.apply(toolCall(1, 'c1', 'read', { file_path: '/srv/app/.env' }))
    ledger.apply(toolResult(2, 'c1'))
    const context = ledger.contextLabel()
    assert.equal(context.label.sensitivity, 'secret')
    assert.equal(context.label.trust, 'workspace')
    assert.match(context.sensitivityOrigin!.description, /\.env/)
  })

  it('leaves an ordinary file read public', () => {
    const ledger = new SessionLedger()
    ledger.apply(toolCall(1, 'c1', 'read', { file_path: '/srv/app/README.md' }))
    ledger.apply(toolResult(2, 'c1'))
    assert.deepEqual(ledger.contextLabel().label, { trust: 'workspace', sensitivity: 'public' })
  })

  it('treats a result whose call it never saw as workspace, not user', () => {
    const ledger = new SessionLedger()
    ledger.apply(toolResult(2, 'unknown-call'))
    assert.equal(ledger.contextLabel().label.trust, 'workspace')
  })

  it('ignores a malformed argument string instead of throwing', () => {
    const ledger = new SessionLedger()
    ledger.apply({
      type: 'tool/call',
      seq: 1,
      time: 1,
      data: { callId: 'c1', name: 'read', arguments: '{not json' },
    })
    ledger.apply(toolResult(2, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'public')
  })
})

describe('surface tracking', () => {
  it('joins over every live surface node', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'read', { file_path: '/app/.env' }))
    ledger.apply(toolResult(3, 'c1'))
    ledger.apply(toolCall(4, 'c2', 'web_fetch', { url: 'https://evil.test' }))
    ledger.apply(toolResult(5, 'c2'))
    assert.deepEqual(ledger.contextLabel().label, { trust: 'untrusted', sensitivity: 'secret' })
  })

  it('does not put a log-only event on the surface', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'read', { file_path: '/app/.env' }))
    assert.deepEqual(ledger.surfaceSeqs(), [1])
  })

  it('contributes nothing extra for the model\'s own output', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(assistantMessage(2, []))
    assert.deepEqual(ledger.contextLabel().label, { trust: 'user', sensitivity: 'public' })
  })
})

describe('compaction cannot launder taint', () => {
  it('carries an untrusted label into the node that shadows it', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'web_fetch', { url: 'https://evil.test' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.trust, 'untrusted')

    // Compaction replaces seqs 1..3 with a summary citing all three.
    ledger.apply(compaction(4, 1, 3, [1, 2, 3]))

    assert.deepEqual(ledger.surfaceSeqs(), [4])
    assert.equal(
      ledger.contextLabel().label.trust,
      'untrusted',
      'summarising an untrusted page must not clear its label',
    )
  })

  it('carries a secret label through a replacement too', () => {
    const ledger = new SessionLedger()
    ledger.apply(toolCall(1, 'c1', 'read', { file_path: '/app/.env' }))
    ledger.apply(toolResult(2, 'c1'))
    ledger.apply(compaction(3, 2, 2, [2]))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')
  })

  it('invents no taint when it compacts clean history', () => {
    // A summary of clean messages is still plugin-authored text, so it carries
    // the `workspace` intrinsic label rather than the `user` one. That is a
    // level no rule acts on, so summarising costs the user no capability.
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(userMessage(2))
    ledger.apply(compaction(3, 1, 2, [1, 2]))
    const label = ledger.contextLabel().label
    assert.notEqual(label.trust, 'untrusted')
    assert.equal(label.sensitivity, 'public')
  })

  it('does not re-taint the surface after the tainted node is gone', () => {
    // Compaction that shadows a tainted node inherits its label. Compaction
    // that shadows only clean nodes does not, so the label tracks the live
    // surface rather than sticking to the session for good.
    const ledger = new SessionLedger()
    ledger.apply(toolCall(1, 'c1', 'web_fetch', { url: 'https://evil.test' }))
    ledger.apply(toolResult(2, 'c1'))
    ledger.apply(userMessage(3))
    assert.equal(ledger.contextLabel().label.trust, 'untrusted')

    // A replacement covering only seq 3 leaves the tainted node on the surface.
    ledger.apply(compaction(4, 3, 3, [3]))
    assert.equal(ledger.contextLabel().label.trust, 'untrusted')
  })

  it('keeps the replacement node in surface order', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(userMessage(2))
    ledger.apply(userMessage(3))
    ledger.apply(userMessage(4))
    ledger.apply(compaction(5, 2, 3, [2, 3]))
    assert.deepEqual(ledger.surfaceSeqs(), [1, 5, 4])
  })
})

describe('provenance', () => {
  it('names the event that made the context untrusted', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'web_fetch', { url: 'https://evil.test' }))
    ledger.apply(toolResult(3, 'c1'))
    const context = ledger.contextLabel()
    assert.equal(context.trustOrigin!.seq, 3)
    assert.match(context.trustOrigin!.description, /web_fetch/)
  })

  it('reports no origin when the context is clean', () => {
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    const context = ledger.contextLabel()
    assert.equal(context.trustOrigin, undefined)
    assert.equal(context.sensitivityOrigin, undefined)
  })
})

describe('configuration', () => {
  it('honours a custom secret path list', () => {
    const ledger = new SessionLedger({ secretPaths: ['**/vault/**'] })
    ledger.apply(toolCall(1, 'c1', 'read', { file_path: '/srv/vault/token' }))
    ledger.apply(toolResult(2, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')
  })

  it('stops treating .env as secret when the list omits it', () => {
    const ledger = new SessionLedger({ secretPaths: ['**/vault/**'] })
    ledger.apply(toolCall(1, 'c1', 'read', { file_path: '/srv/.env' }))
    ledger.apply(toolResult(2, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'public')
  })
})

/** Declaring `bash` an opaque reader at the default floor. */
const BASH_OPAQUE: OpaqueReaders = { tools: ['bash'], sensitivity: 'secret' }

describe('opaque readers', () => {
  it('leaves a shell read unlabelled when nothing is declared', () => {
    // This pins the known bypass rather than hiding it. A shell takes a command
    // and not a path, so with the feature off there is nothing to derive a
    // `secret` label from and the context stays public. Anyone who believes the
    // default configuration covers this case should read this test.
    const ledger = new SessionLedger()
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'bash', { command: 'cat .env' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'public')
  })

  it('raises a declared reader\'s result to the floor', () => {
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'bash', { command: 'cat .env' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')
  })

  it('raises the floor whatever the command was, because it cannot read one', () => {
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'bash', { command: 'ls' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')
  })

  it('leaves a tool nobody declared alone', () => {
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'read', { file_path: '/app/readme.md' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'public')
  })

  it('matches a trailing star, through the one tool name matcher', () => {
    const ledger = new SessionLedger({ opaqueReaders: { tools: ['terminal_*'], sensitivity: 'secret' } })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'terminal_send', { text: 'cat .env' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')

    const other = new SessionLedger({ opaqueReaders: { tools: ['terminal_*'], sensitivity: 'secret' } })
    other.apply(toolCall(1, 'c1', 'read', { file_path: '/app/readme.md' }))
    other.apply(toolResult(2, 'c1'))
    assert.equal(other.contextLabel().label.sensitivity, 'public')
  })

  it('names the declaration in the provenance it hands the denial message', () => {
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'bash', { command: 'cat .env' }))
    ledger.apply(toolResult(3, 'c1'))
    const origin = ledger.contextLabel().sensitivityOrigin
    assert.equal(origin?.seq, 3)
    assert.match(origin!.description, /opaque reader/)
  })

  it('applies a trust floor only when the operator sets one', () => {
    const withoutTrust = resultLabelFor('bash', {}, { opaqueReaders: BASH_OPAQUE })
    assert.deepEqual(withoutTrust.label, { trust: 'workspace', sensitivity: 'secret' })

    const withTrust = resultLabelFor('bash', {}, {
      opaqueReaders: { tools: ['bash'], sensitivity: 'public', trust: 'untrusted' },
    })
    assert.deepEqual(withTrust.label, { trust: 'untrusted', sensitivity: 'public' })
  })
})

describe('the opaque reader floor only ever raises a label', () => {
  it('leaves an untrusted result untrusted', () => {
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'web_fetch', { url: 'https://evil.test' }))
    ledger.apply(toolResult(3, 'c1'))
    assert.deepEqual(ledger.contextLabel().label, { trust: 'untrusted', sensitivity: 'public' })
  })

  it('keeps an untrusted label when the untrusted tool is itself declared opaque', () => {
    const resolved = resultLabelFor('web_fetch', { url: 'https://evil.test' }, {
      opaqueReaders: { tools: ['web_fetch'], sensitivity: 'secret' },
    })
    assert.deepEqual(resolved.label, { trust: 'untrusted', sensitivity: 'secret' })
  })

  it('never lowers a sensitivity a matched glob already raised', () => {
    const resolved = resultLabelFor('bash', { file_path: '/app/.env' }, {
      opaqueReaders: { tools: ['bash'], sensitivity: 'public' },
    })
    assert.equal(resolved.label.sensitivity, 'secret')
    assert.equal(resolved.matchedGlob, '**/.env')
    assert.equal(resolved.opaque, undefined, 'a floor that moved nothing is not the reason')
  })

  it('marks the label as floored only when the floor did the raising', () => {
    assert.equal(resultLabelFor('bash', {}, { opaqueReaders: BASH_OPAQUE }).opaque, true)
    assert.equal(resultLabelFor('read', {}, { opaqueReaders: BASH_OPAQUE }).opaque, undefined)
  })

  it('survives compaction, like every other label', () => {
    // A floored label is an ordinary label. Summarising the shell output it came
    // from cannot launder it, because the replacement node cites the node it
    // shadows and inherits its label.
    const ledger = new SessionLedger({ opaqueReaders: BASH_OPAQUE })
    ledger.apply(userMessage(1))
    ledger.apply(toolCall(2, 'c1', 'bash', { command: 'cat .env' }))
    ledger.apply(toolResult(3, 'c1'))
    ledger.apply(compaction(4, 3, 3, [3]))
    assert.equal(ledger.contextLabel().label.sensitivity, 'secret')
    assert.deepEqual(ledger.surfaceSeqs(), [1, 4])
  })

  it('does nothing at all when no tool is declared', () => {
    assert.deepEqual(resultLabelFor('bash', { command: 'cat .env' }).label, {
      trust: 'workspace',
      sensitivity: 'public',
    })
  })
})
