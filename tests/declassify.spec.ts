import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  DEFAULT_MAX_GRANTS,
  Declassifier,
  declassificationRecord,
  describeGrant,
  labelAtOrBelow,
} from '../src/declassify.js'
import type { DeclassifierOptions, GrantRequest } from '../src/declassify.js'
import type { Label } from '../src/labels.js'

const SESSION = 'session-1'

const UNTRUSTED: Label = { trust: 'untrusted', sensitivity: 'public' }
const SECRET: Label = { trust: 'workspace', sensitivity: 'secret' }
const CLEAN: Label = { trust: 'user', sensitivity: 'public' }

/** A clearance an operator would plausibly give. */
function request(overrides: Partial<GrantRequest> = {}): GrantRequest {
  return {
    capability: 'mutate',
    label: UNTRUSTED,
    actor: 'operator',
    reason: 'the release notes edit was expected',
    rule: 'untrusted-ask-mutate',
    ...overrides,
  }
}

/** A store on a clock the test controls. */
function store(
  now: () => number = () => 1_000,
  options: Omit<DeclassifierOptions, 'now'> = {},
): Declassifier {
  return new Declassifier({ ...options, now })
}

describe('the declassification store', () => {
  it('clears a call once a grant covers it', () => {
    const grants = store()
    grants.grant(SESSION, request())
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: UNTRUSTED }), true)
  })

  it('clears only the capability class the grant names', () => {
    const grants = store()
    grants.grant(SESSION, request())
    assert.equal(grants.isDeclassified(SESSION, { capability: 'egress', label: UNTRUSTED }), false)
  })

  it('covers every tool of the class when the grant names none', () => {
    const grants = store()
    grants.grant(SESSION, request())
    for (const tool of ['write', 'edit', 'bash']) {
      assert.equal(
        grants.isDeclassified(SESSION, { capability: 'mutate', tool, label: UNTRUSTED }),
        true,
        `${tool} must be covered`,
      )
    }
  })

  it('covers one tool alone when the grant names it', () => {
    const grants = store()
    grants.grant(SESSION, request({ tool: 'write' }))
    assert.equal(
      grants.isDeclassified(SESSION, { capability: 'mutate', tool: 'write', label: UNTRUSTED }),
      true,
    )
    assert.equal(
      grants.isDeclassified(SESSION, { capability: 'mutate', tool: 'bash', label: UNTRUSTED }),
      false,
    )
  })

  it('clears a label at or below the one the human saw, and nothing above it', () => {
    const grants = store()
    grants.grant(SESSION, request({ label: UNTRUSTED }))
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: CLEAN }), true)
    // A step that has since picked up a secret is a question the human never
    // answered, so it is asked again.
    assert.equal(
      grants.isDeclassified(SESSION, {
        capability: 'mutate',
        label: { trust: 'untrusted', sensitivity: 'secret' },
      }),
      false,
    )
  })

  it('orders the lattice the way the label module does', () => {
    assert.equal(labelAtOrBelow(CLEAN, UNTRUSTED), true)
    assert.equal(labelAtOrBelow(UNTRUSTED, CLEAN), false)
    assert.equal(labelAtOrBelow(SECRET, UNTRUSTED), false)
    assert.equal(labelAtOrBelow(UNTRUSTED, UNTRUSTED), true)
  })

  it('keeps grants per session', () => {
    const grants = store()
    grants.grant(SESSION, request())
    assert.equal(grants.isDeclassified('session-2', { capability: 'mutate', label: UNTRUSTED }), false)
  })

  it('withdraws one grant on revoke', () => {
    const grants = store()
    const grant = grants.grant(SESSION, request())!
    assert.equal(grants.revoke(SESSION, grant.id), true)
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: UNTRUSTED }), false)
    assert.equal(grants.revoke(SESSION, grant.id), false)
  })

  it('withdraws every grant of a session on clear', () => {
    const grants = store()
    grants.grant(SESSION, request())
    grants.grant(SESSION, request({ capability: 'egress' }))
    grants.clear(SESSION)
    assert.deepEqual(grants.grants(SESSION), [])
  })

  it('does not let a grant survive the session it was given in', () => {
    const grants = store()
    grants.grant(SESSION, request())
    grants.drop(SESSION)
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: UNTRUSTED }), false)
    assert.equal(grants.sessionCount(), 0)
  })

  it('expires a grant at its deadline', () => {
    let clock = 1_000
    const grants = store(() => clock, { ttlMs: 60_000 })
    grants.grant(SESSION, request())
    const query = { capability: 'mutate' as const, label: UNTRUSTED }

    clock = 60_999
    assert.equal(grants.isDeclassified(SESSION, query), true)
    clock = 61_000
    assert.equal(grants.isDeclassified(SESSION, query), false)
    // The expired grant is not merely hidden, it is dropped.
    assert.deepEqual(grants.grants(SESSION), [])
  })

  it('lets one grant carry its own lifetime', () => {
    let clock = 0
    const grants = store(() => clock, { ttlMs: 60_000 })
    grants.grant(SESSION, request({ ttlMs: 10 }))
    const query = { capability: 'mutate' as const, label: UNTRUSTED }
    clock = 10
    assert.equal(grants.isDeclassified(SESSION, query), false)
  })

  it('caps the grants one session may hold, evicting the oldest', () => {
    const grants = store(() => 1_000, { maxGrants: 3 })
    for (const tool of ['a', 'b', 'c', 'd']) grants.grant(SESSION, request({ tool }))

    const held = grants.grants(SESSION)
    assert.equal(held.length, 3)
    assert.deepEqual(held.map((grant) => grant.tool), ['b', 'c', 'd'])
    // Eviction can only take permission away.
    assert.equal(
      grants.isDeclassified(SESSION, { capability: 'mutate', tool: 'a', label: UNTRUSTED }),
      false,
    )
    assert.equal(
      grants.isDeclassified(SESSION, { capability: 'mutate', tool: 'd', label: UNTRUSTED }),
      true,
    )
  })

  it('caps the sessions the store remembers, forgetting the oldest', () => {
    const grants = store(() => 1_000, { maxSessions: 2 })
    for (const session of ['s1', 's2', 's3']) grants.grant(session, request())
    assert.equal(grants.sessionCount(), 2)
    assert.equal(grants.isDeclassified('s1', { capability: 'mutate', label: UNTRUSTED }), false)
    assert.equal(grants.isDeclassified('s3', { capability: 'mutate', label: UNTRUSTED }), true)
  })

  it('defaults to a bounded number of grants', () => {
    const grants = store()
    for (let index = 0; index < DEFAULT_MAX_GRANTS + 5; index += 1) {
      grants.grant(SESSION, request({ tool: `tool-${index}` }))
    }
    assert.equal(grants.grants(SESSION).length, DEFAULT_MAX_GRANTS)
  })

  it('records nothing and clears nothing when declassification is disabled', () => {
    const grants = new Declassifier({ allow: false, now: () => 1_000 })
    assert.equal(grants.grant(SESSION, request()), undefined)
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: UNTRUSTED }), false)
    assert.deepEqual(grants.grants(SESSION), [])
  })

  it('is enabled unless configuration says otherwise', () => {
    assert.equal(new Declassifier().allow, true)
    assert.equal(new Declassifier({ allow: true }).allow, true)
    assert.equal(new Declassifier({ allow: false }).allow, false)
  })

  it('answers with the newest covering grant', () => {
    const grants = store()
    grants.grant(SESSION, request({ reason: 'the first answer' }))
    const second = grants.grant(SESSION, request({ reason: 'the second answer' }))!
    const found = grants.find(SESSION, { capability: 'mutate', label: UNTRUSTED })
    assert.equal(found?.id, second.id)
  })

  it('contains a clock that throws', () => {
    const grants = new Declassifier({
      now: () => {
        throw new Error('no clock here')
      },
    })
    assert.equal(grants.grant(SESSION, request()), undefined)
    assert.equal(grants.isDeclassified(SESSION, { capability: 'mutate', label: UNTRUSTED }), false)
  })
})

describe('the declassification audit record', () => {
  it('names the actor, the label, the scope, and the reason', () => {
    const grants = store()
    const grant = grants.grant(SESSION, request({ tool: 'write' }))!
    const line = describeGrant(grant)
    assert.match(line, /operator/)
    assert.match(line, /trust=untrusted sensitivity=public/)
    assert.match(line, /`write`/)
    assert.match(line, /the release notes edit was expected/)
    assert.match(line, /1970-01-01T00:00:01\.000Z/)
  })

  it('names the whole capability class when the grant names no tool', () => {
    const grants = store()
    const grant = grants.grant(SESSION, request())!
    assert.match(describeGrant(grant), /mutate tools/)
  })

  it('builds a decision record the evidence sink accepts', () => {
    const grants = store()
    const grant = grants.grant(SESSION, request({ tool: 'write' }))!
    const record = declassificationRecord(
      grant,
      { tool: 'write', capabilities: ['mutate'], callId: 'call-1', turn: 2, step: 3 },
      new Date('2026-01-01T00:00:00.000Z'),
    )

    assert.equal(record.outcome, 'declassify')
    assert.equal(record.sessionId, SESSION)
    assert.equal(record.tool, 'write')
    assert.equal(record.callId, 'call-1')
    assert.equal(record.rule, 'untrusted-ask-mutate')
    assert.equal(record.turn, 2)
    assert.equal(record.step, 3)
    assert.deepEqual(record.capabilities, ['mutate'])
    assert.deepEqual(record.label, UNTRUSTED)
    assert.equal(record.timestamp, '2026-01-01T00:00:00.000Z')
    assert.match(record.origin!, /operator/)
  })

  it('leaves absent fields absent rather than undefined', () => {
    const grants = store()
    const grant = grants.grant(SESSION, {
      capability: 'mutate',
      label: UNTRUSTED,
      actor: 'operator',
      reason: 'no rule was cited',
    })!
    const record = declassificationRecord(grant, { tool: 'write', capabilities: ['mutate'] })
    assert.equal(Object.hasOwn(record, 'rule'), false)
    assert.equal(Object.hasOwn(record, 'callId'), false)
    assert.equal(Object.hasOwn(record, 'turn'), false)
    assert.equal(Object.hasOwn(record, 'step'), false)
  })
})
