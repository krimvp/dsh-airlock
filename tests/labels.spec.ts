import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { BOTTOM, formatLabel, join, joinAll, sensitivityAtLeast, trustAtLeast } from '../src/labels.js'

describe('the label lattice', () => {
  it('takes the upper bound on both axes independently', () => {
    const a = { trust: 'untrusted', sensitivity: 'public' } as const
    const b = { trust: 'user', sensitivity: 'secret' } as const
    assert.deepEqual(join(a, b), { trust: 'untrusted', sensitivity: 'secret' })
  })

  it('is commutative', () => {
    const a = { trust: 'workspace', sensitivity: 'secret' } as const
    const b = { trust: 'untrusted', sensitivity: 'confidential' } as const
    assert.deepEqual(join(a, b), join(b, a))
  })

  it('is idempotent', () => {
    const a = { trust: 'workspace', sensitivity: 'confidential' } as const
    assert.deepEqual(join(a, a), a)
  })

  it('is associative', () => {
    const a = { trust: 'user', sensitivity: 'secret' } as const
    const b = { trust: 'untrusted', sensitivity: 'public' } as const
    const c = { trust: 'workspace', sensitivity: 'confidential' } as const
    assert.deepEqual(join(join(a, b), c), join(a, join(b, c)))
  })

  it('treats bottom as the identity', () => {
    const a = { trust: 'untrusted', sensitivity: 'secret' } as const
    assert.deepEqual(join(a, BOTTOM), a)
    assert.deepEqual(joinAll([]), BOTTOM)
  })

  it('never lowers a label', () => {
    const a = { trust: 'untrusted', sensitivity: 'secret' } as const
    const b = { trust: 'user', sensitivity: 'public' } as const
    const joined = join(a, b)
    assert.equal(joined.trust, 'untrusted')
    assert.equal(joined.sensitivity, 'secret')
  })

  it('compares against a threshold on each axis', () => {
    const label = { trust: 'workspace', sensitivity: 'secret' } as const
    assert.equal(trustAtLeast(label, 'workspace'), true)
    assert.equal(trustAtLeast(label, 'untrusted'), false)
    assert.equal(sensitivityAtLeast(label, 'secret'), true)
  })

  it('renders both axes', () => {
    assert.equal(formatLabel(BOTTOM), 'trust=user sensitivity=public')
  })
})
