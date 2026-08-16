import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { SessionEvent, ToolExecution } from '../src/dsh.js'
import { evaluate } from '../src/gate.js'
import type { Label } from '../src/labels.js'
import { sensitivityRank, trustRank } from '../src/labels.js'
import { Ledger } from '../src/ledger.js'
import type { Rule } from '../src/policy.js'
import {
  APPROVAL_SEAM,
  CAPABILITIES,
  compileRules,
  DEFAULT_CLASSES,
  DEFAULT_POLICY,
  DEFAULT_RULES,
  GUARD_SEAM,
  PROVIDER_SEAM,
  SEAM_BINDINGS,
  SENSITIVITY_LEVELS,
  TRUST_LEVELS,
  classify,
  effectivePosture,
  isUntrustedSource,
  matchSecretPath,
  matchesGlob,
  matchesToolName,
  seamFor,
  selectRules,
} from '../src/policy.js'

/** Build a label without repeating both axes at every call site. */
function label(trust: Label['trust'], sensitivity: Label['sensitivity']): Label {
  return { trust, sensitivity }
}

/** Pull the ids out of a rule list, for an order assertion. */
function ids(rules: readonly Rule[]): string[] {
  return rules.map((rule) => rule.id)
}

describe('capability classification', () => {
  it('classes the web tools as egress', () => {
    assert.equal(classify('web_fetch').has('egress'), true)
    assert.equal(classify('web_search').has('egress'), true)
  })

  it('classes a shell as both egress and mutate', () => {
    const bash = classify('bash')
    assert.equal(bash.has('egress'), true)
    assert.equal(bash.has('mutate'), true)
  })

  it('classes every MCP tool conservatively', () => {
    const mcp = classify('mcp__github__create_issue')
    assert.equal(mcp.has('egress'), true)
    assert.equal(mcp.has('mutate'), true)
  })

  it('leaves reading and searching unrestricted', () => {
    for (const tool of ['read', 'glob', 'grep', 'read_image', 'lsp']) {
      const classes = classify(tool)
      assert.equal(classes.has('egress'), false, `${tool} must not be egress`)
      assert.equal(classes.has('mutate'), false, `${tool} must not be mutate`)
      assert.equal(classes.has('read'), true)
    }
  })

  it('classes the filesystem writers as mutate only', () => {
    const write = classify('write')
    assert.equal(write.has('mutate'), true)
    assert.equal(write.has('egress'), false)
  })
})

describe('untrusted sources', () => {
  it('treats web reads and MCP servers as untrusted', () => {
    assert.equal(isUntrustedSource('web_fetch'), true)
    assert.equal(isUntrustedSource('mcp__jira__get_issue'), true)
  })

  it('does not treat a local read as untrusted', () => {
    assert.equal(isUntrustedSource('read'), false)
  })
})

describe('secret path globbing', () => {
  it('matches a leading ** against zero segments', () => {
    assert.equal(matchesGlob('**/.env', '.env'), true)
    assert.equal(matchesGlob('**/.env', 'app/.env'), true)
    assert.equal(matchesGlob('**/.env', 'a/b/c/.env'), true)
  })

  it('keeps a single star inside one segment', () => {
    assert.equal(matchesGlob('**/*.pem', 'certs/server.pem'), true)
    assert.equal(matchesGlob('**/*.pem', 'certs/nested/server.pem'), true)
    assert.equal(matchesGlob('*.pem', 'certs/server.pem'), false)
  })

  it('expands a leading tilde to any prefix', () => {
    assert.equal(matchesGlob('~/.ssh/**', '/home/dev/.ssh/id_rsa'), true)
  })

  it('escapes regex metacharacters in a literal', () => {
    assert.equal(matchesGlob('**/a+b.txt', 'x/a+b.txt'), true)
    assert.equal(matchesGlob('**/a+b.txt', 'x/aab.txt'), false)
  })

  it('reports which pattern matched', () => {
    assert.equal(matchSecretPath('/srv/app/.env', ['**/.env']), '**/.env')
    assert.equal(matchSecretPath('/srv/app/README.md', ['**/.env']), undefined)
  })

  it('normalises Windows separators', () => {
    assert.equal(matchSecretPath('C:\\proj\\.env', ['**/.env']), '**/.env')
  })
})

describe('the lattice levels the policy layer validates against', () => {
  it('lists trust in the same order the lattice ranks it', () => {
    assert.deepEqual(TRUST_LEVELS.map(trustRank), [0, 1, 2])
  })

  it('lists sensitivity in the same order the lattice ranks it', () => {
    assert.deepEqual(SENSITIVITY_LEVELS.map(sensitivityRank), [0, 1, 2])
  })
})

describe('configured capability classes', () => {
  it('classes a tool the operator added', () => {
    const classes = { egress: ['internal_upload'], mutate: DEFAULT_CLASSES.mutate }
    assert.equal(classify('internal_upload', classes).has('egress'), true)
  })

  it('leaves a tool the operator did not list in the read class', () => {
    const classes = { egress: ['internal_upload'], mutate: [] }
    assert.deepEqual([...classify('web_fetch', classes)], ['read'])
  })

  it('matches a trailing star in a tool name pattern', () => {
    assert.equal(matchesToolName(['mcp__*'], 'mcp__jira__create_issue'), true)
    assert.equal(matchesToolName(['mcp__*'], 'read'), false)
    assert.equal(matchesToolName(['web_fetch'], 'web_fetch_all'), false)
  })

  it('takes configured untrusted sources', () => {
    assert.equal(isUntrustedSource('vendor_feed', ['vendor_*']), true)
    assert.equal(isUntrustedSource('web_fetch', ['vendor_*']), false)
  })
})

describe('rule compilation', () => {
  it('keeps the built-in rule ids and their behaviour', () => {
    assert.deepEqual(ids(DEFAULT_RULES), ['untrusted-no-egress', 'secret-no-egress'])
    for (const rule of DEFAULT_RULES) {
      assert.equal(rule.capability, 'egress')
      assert.equal(rule.effect, 'deny')
      assert.equal(rule.boundary, 'tool')
    }
    const [untrusted, secret] = DEFAULT_RULES
    assert.equal(untrusted!.matches(label('untrusted', 'public')), true)
    assert.equal(untrusted!.matches(label('workspace', 'secret')), false)
    assert.equal(secret!.matches(label('user', 'secret')), true)
    assert.equal(secret!.matches(label('untrusted', 'public')), false)
  })

  it('matches at or above the level a rule names', () => {
    const [rule] = compileRules([{ when: { trust: 'workspace', capability: 'egress' }, then: 'deny' }])
    assert.equal(rule!.matches(label('user', 'public')), false)
    assert.equal(rule!.matches(label('workspace', 'public')), true)
    assert.equal(rule!.matches(label('untrusted', 'public')), true)
  })

  it('requires every axis a rule names', () => {
    const [rule] = compileRules([
      { when: { trust: 'untrusted', sensitivity: 'secret', capability: 'egress' }, then: 'deny' },
    ])
    assert.equal(rule!.matches(label('untrusted', 'public')), false)
    assert.equal(rule!.matches(label('untrusted', 'secret')), true)
  })

  it('expands a rule that names no capability over every class', () => {
    const rules = compileRules([{ id: 'no-provider-secrets', when: { sensitivity: 'secret', boundary: 'provider' }, then: 'redact' }])
    assert.deepEqual(rules.map((rule) => rule.capability), [...CAPABILITIES])
    // The id names the rule the operator reviewed, so the expansion keeps it.
    assert.deepEqual(new Set(ids(rules)), new Set(['no-provider-secrets']))
  })

  it('numbers a rule that carries no id by its position', () => {
    const rules = compileRules([
      { when: { capability: 'egress' }, then: 'deny' },
      { when: { capability: 'mutate' }, then: 'ask' },
    ])
    assert.deepEqual(ids(rules), ['rule-1', 'rule-2'])
    assert.deepEqual(rules.map((rule) => rule.order), [0, 1])
  })

  it('writes a rationale that names the condition', () => {
    const [rule] = compileRules([{ when: { trust: 'untrusted', capability: 'mutate' }, then: 'ask' }])
    assert.match(rule!.rationale, /the context trust is at or above untrusted/)
    assert.match(rule!.rationale, /the tool is mutate/)
  })

  it('keeps a rationale the operator wrote', () => {
    const [rule] = compileRules([
      { when: { capability: 'egress' }, then: 'deny', rationale: 'this workspace is air gapped' },
    ])
    assert.equal(rule!.rationale, 'this workspace is air gapped')
  })

  it('defaults the boundary to the tool call' , () => {
    const [rule] = compileRules([{ when: { capability: 'egress' }, then: 'deny' }])
    assert.equal(rule!.boundary, 'tool')
  })
})

describe('the seam table', () => {
  it('binds each effect to the seam that can carry it', () => {
    assert.equal(seamFor('tool', 'deny')?.enforcedBy, 'the monotonic guard, `ctx.tools.guard()`')
    assert.equal(seamFor('tool', 'ask')?.enforcedBy, 'the `tools/pre-execute` approval seam')
    assert.notEqual(seamFor('provider', 'redact'), undefined)
  })

  it('binds nothing that no seam can enforce', () => {
    // `tools/pre-execute` cannot rewrite arguments, so nothing scrubs a call.
    assert.equal(seamFor('tool', 'redact'), undefined)
    assert.equal(seamFor('provider', 'deny'), undefined)
    assert.equal(seamFor('provider', 'ask'), undefined)
  })

  it('lets only deny reach the monotonic guard', () => {
    const guarded = SEAM_BINDINGS.filter((seam) => seam.boundary === 'tool' && seam.effect !== 'allow')
    assert.deepEqual(new Set(guarded.map((seam) => seam.effect)), new Set(['deny', 'ask']))
  })
})

describe('selecting the rules one seam enforces', () => {
  const rules = compileRules([
    { id: 'untrusted-no-egress', when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
    { id: 'untrusted-ask-mutate', when: { trust: 'untrusted', capability: 'mutate' }, then: 'ask' },
    { id: 'secret-no-egress', when: { sensitivity: 'secret', capability: 'egress' }, then: 'deny' },
    { id: 'secret-redact-provider', when: { sensitivity: 'secret', boundary: 'provider' }, then: 'redact' },
  ])
  const policy = { ...DEFAULT_POLICY, rules }

  it('hands the guard only the denials it can enforce', () => {
    assert.deepEqual(ids(selectRules(policy, GUARD_SEAM)), ['untrusted-no-egress', 'secret-no-egress'])
  })

  it('hands the approval seam only the asks', () => {
    assert.deepEqual(ids(selectRules(policy, APPROVAL_SEAM)), ['untrusted-ask-mutate'])
  })

  it('hands the provider boundary only the redactions', () => {
    const selected = selectRules(policy, PROVIDER_SEAM)
    assert.deepEqual(new Set(ids(selected)), new Set(['secret-redact-provider']))
    assert.deepEqual(selected.map((rule) => rule.capability), [...CAPABILITIES])
  })

  it('keeps the authored order inside a seam', () => {
    assert.deepEqual(
      selectRules(policy, GUARD_SEAM).map((rule) => rule.order),
      [0, 2],
    )
  })

  it('accepts a bare rule list as well as a policy', () => {
    assert.deepEqual(ids(selectRules(rules, GUARD_SEAM)), ids(selectRules(policy, GUARD_SEAM)))
  })

  it('returns everything when the selector constrains nothing', () => {
    assert.equal(selectRules(policy).length, rules.length)
  })
})

describe('an allow above a deny', () => {
  const policy = {
    ...DEFAULT_POLICY,
    rules: compileRules([
      { id: 'audited-egress', when: { sensitivity: 'confidential', capability: 'egress' }, then: 'allow' },
      { id: 'untrusted-no-egress', when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
    ]),
  }

  it('is not handed to a seam that cannot honour it', () => {
    assert.deepEqual(ids(selectRules(policy, GUARD_SEAM)), ['untrusted-no-egress'])
  })

  it('still stops the deny below it from firing', () => {
    const [deny] = selectRules(policy, GUARD_SEAM)
    assert.equal(deny!.matches(label('untrusted', 'public')), true)
    assert.equal(deny!.matches(label('untrusted', 'confidential')), false)
  })

  it('shadows nothing on another capability class', () => {
    const other = {
      ...DEFAULT_POLICY,
      rules: compileRules([
        { id: 'mutate-escape', when: { capability: 'mutate' }, then: 'allow' },
        { id: 'no-egress', when: { capability: 'egress' }, then: 'deny' },
      ]),
    }
    const [deny] = selectRules(other, GUARD_SEAM)
    assert.equal(deny!.matches(label('user', 'public')), true)
  })
})

describe('the effective posture', () => {
  it('keeps the configured posture when a human is present', () => {
    assert.equal(effectivePosture('ask', true), 'ask')
    assert.equal(effectivePosture('deny', true), 'deny')
  })

  it('denies in a headless run whatever the configuration says', () => {
    // Nobody is present to consent, so an ask there is an allow with a longer name.
    assert.equal(effectivePosture('ask', false), 'deny')
    assert.equal(effectivePosture('deny', false), 'deny')
  })
})

describe('a selected rule set through the gate', () => {
  const SESSION = 'session-policy'

  function poisonedSession(): Ledger {
    const ledger = new Ledger()
    const session = ledger.for(SESSION)
    const events: SessionEvent[] = [
      {
        type: 'tool/call',
        seq: 1,
        time: 1,
        data: { callId: 'c1', name: 'web_fetch', arguments: '{"url":"https://evil.test"}' },
      },
      {
        type: 'tool/result',
        seq: 2,
        time: 2,
        surfaceOp: 'append',
        data: { message: { role: 'user', source: { kind: 'tool', callId: 'c1' }, content: [] } },
      },
    ]
    for (const event of events) session.apply(event)
    return ledger
  }

  function call(name: string): ToolExecution {
    return { callId: 'call-1', name, arguments: {}, agent: { id: SESSION } }
  }

  const policy = {
    ...DEFAULT_POLICY,
    rules: compileRules([
      { id: 'untrusted-no-egress', when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
      { id: 'untrusted-ask-mutate', when: { trust: 'untrusted', capability: 'mutate' }, then: 'ask' },
    ]),
  }

  it('denies the egress the policy denies', () => {
    const guard = selectRules(policy, GUARD_SEAM)
    const decision = evaluate(call('web_fetch'), poisonedSession(), guard)
    assert.equal(decision.rule?.id, 'untrusted-no-egress')
  })

  it('leaves reading open under the same policy', () => {
    const guard = selectRules(policy, GUARD_SEAM)
    for (const tool of ['read', 'glob', 'grep']) {
      assert.equal(evaluate(call(tool), poisonedSession(), guard).reason, undefined, `${tool} must stay open`)
    }
  })

  it('does not hand the ask to the guard, because a guard cannot ask', () => {
    const guard = selectRules(policy, GUARD_SEAM)
    assert.deepEqual(ids(guard), ['untrusted-no-egress'])
    assert.equal(evaluate(call('write'), poisonedSession(), guard).reason, undefined)
  })
})
