import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join as joinPath } from 'node:path'
import { describe, it } from 'node:test'

import type { ChainedRecord, DecisionRecord } from '../src/evidence.js'
import {
  canonicalize,
  chainRecord,
  DEFAULT_EVIDENCE_PATH,
  decisionRecord,
  EvidenceSink,
  expandHome,
  GENESIS_HASH,
  hashRecord,
  JsonlSink,
  OtelSink,
  RECORD_VERSION,
  SPAN_EVENT_NAME,
  spanAttributes,
  verifyChain,
} from '../src/evidence.js'

function workspace(): string {
  return mkdtempSync(joinPath(tmpdir(), 'airlock-evidence-'))
}

function record(overrides: Partial<DecisionRecord> = {}): DecisionRecord {
  return {
    version: RECORD_VERSION,
    timestamp: '2026-08-16T09:00:00.000Z',
    sessionId: 'session-1',
    turn: 3,
    step: 1,
    tool: 'bash',
    callId: 'call-1',
    capabilities: ['egress', 'mutate'],
    outcome: 'deny',
    rule: 'untrusted-no-egress',
    label: { trust: 'untrusted', sensitivity: 'secret' },
    origin: 'seq 2 (`web_fetch` result)',
    ...overrides,
  }
}

/** Write three decisions through a sink and hand back the file's lines. */
function threeLines(dir: string): { path: string; lines: string[] } {
  const path = joinPath(dir, 'decisions.jsonl')
  const sink = new JsonlSink({ path })
  for (const tool of ['web_fetch', 'bash', 'run_code']) {
    sink.append(record({ tool, callId: `call-${tool}` }))
  }
  return { path, lines: readFileSync(path, 'utf8').split('\n') }
}

/** Wait for the microtasks an unresolved OTel load is parked on. */
async function settle(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve))
}

describe('canonical serialization', () => {
  it('sorts keys, so insertion order cannot change the hash', () => {
    const first: DecisionRecord = {
      version: 1,
      timestamp: '2026-08-16T09:00:00.000Z',
      sessionId: 's',
      tool: 'bash',
      capabilities: ['egress'],
      outcome: 'deny',
      label: { trust: 'untrusted', sensitivity: 'public' },
      rule: 'untrusted-no-egress',
    }
    const second: DecisionRecord = {
      rule: 'untrusted-no-egress',
      label: { sensitivity: 'public', trust: 'untrusted' },
      outcome: 'deny',
      capabilities: ['egress'],
      tool: 'bash',
      sessionId: 's',
      timestamp: '2026-08-16T09:00:00.000Z',
      version: 1,
    }
    assert.equal(canonicalize(first), canonicalize(second))
    assert.equal(hashRecord(GENESIS_HASH, first), hashRecord(GENESIS_HASH, second))
  })

  it('emits keys in sorted order', () => {
    assert.equal(canonicalize({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}')
  })

  it('keeps array order, which is data rather than layout', () => {
    assert.notEqual(
      hashRecord(GENESIS_HASH, record({ capabilities: ['egress', 'mutate'] })),
      hashRecord(GENESIS_HASH, record({ capabilities: ['mutate', 'egress'] })),
    )
  })

  it('treats an absent optional field and an undefined one alike', () => {
    // `exactOptionalPropertyTypes` forbids writing `undefined` into an optional
    // field, so only a wider type reaches this shape. It still has to hash the
    // same as the record that simply omits the field.
    const mutable: Record<string, unknown> = { ...record() }
    delete mutable['rule']
    const absent = mutable as unknown as DecisionRecord
    const explicit = { ...mutable, rule: undefined } as unknown as DecisionRecord
    assert.equal(hashRecord(GENESIS_HASH, absent), hashRecord(GENESIS_HASH, explicit))
  })
})

describe('the hash chain', () => {
  it('chains the first record from the genesis constant', () => {
    const first = chainRecord(GENESIS_HASH, record())
    assert.equal(first.hash, hashRecord(GENESIS_HASH, record()))
    assert.match(first.hash, /^[0-9a-f]{64}$/)
  })

  it('reports no break on an intact file', () => {
    const { lines } = threeLines(workspace())
    assert.equal(verifyChain(lines), undefined)
  })

  it('reports no break on an empty file', () => {
    assert.equal(verifyChain([]), undefined)
    assert.equal(verifyChain(['']), undefined)
  })

  it('is indifferent to the key order a writer used', () => {
    const { lines } = threeLines(workspace())
    const rewritten = lines.map((line) => {
      if (line.trim().length === 0) return line
      const parsed = JSON.parse(line) as Record<string, unknown>
      const reversed: Record<string, unknown> = {}
      for (const key of Object.keys(parsed).reverse()) reversed[key] = parsed[key]
      return JSON.stringify(reversed)
    })
    assert.notEqual(rewritten[0], lines[0], 'the rewrite must actually reorder keys')
    assert.equal(verifyChain(rewritten), undefined)
  })

  it('detects a tampered middle record', () => {
    const { lines } = threeLines(workspace())
    const middle = JSON.parse(lines[1]!) as ChainedRecord
    lines[1] = JSON.stringify({ ...middle, outcome: 'allow' })
    assert.equal(verifyChain(lines), 1)
  })

  it('detects a tampered record even when its own hash is recomputed', () => {
    // The forger edits the record and re-hashes it against genesis. The link to
    // its predecessor is what fails, and every later line fails with it.
    const { lines } = threeLines(workspace())
    const middle = JSON.parse(lines[1]!) as ChainedRecord
    const { hash: _dropped, ...content } = middle
    const forged = { ...content, outcome: 'allow' } as unknown as DecisionRecord
    lines[1] = JSON.stringify(chainRecord(GENESIS_HASH, forged))
    assert.equal(verifyChain(lines), 1)
  })

  it('detects a removed record', () => {
    const { lines } = threeLines(workspace())
    const kept = [lines[0]!, lines[2]!]
    assert.equal(verifyChain(kept), 1)
  })

  it('detects a reordered pair', () => {
    const { lines } = threeLines(workspace())
    const swapped = [lines[1]!, lines[0]!, lines[2]!]
    assert.equal(verifyChain(swapped), 0)
  })

  it('detects a truncated final line', () => {
    const { lines } = threeLines(workspace())
    const truncated = [lines[0]!, lines[1]!.slice(0, 20)]
    assert.equal(verifyChain(truncated), 1)
  })

  it('detects a line that carries no hash', () => {
    assert.equal(verifyChain(['{"tool":"bash"}']), 0)
  })

  it('continues the chain across sink instances', () => {
    const dir = workspace()
    const path = joinPath(dir, 'decisions.jsonl')
    new JsonlSink({ path }).append(record({ tool: 'web_fetch' }))
    const reopened = new JsonlSink({ path })
    reopened.append(record({ tool: 'bash' }))
    const lines = readFileSync(path, 'utf8').split('\n')
    assert.equal(verifyChain(lines), undefined)
    assert.equal(lines.filter((line) => line.length > 0).length, 2)
  })

  it('does not chain a second file onto the first file head', () => {
    const dir = workspace()
    const sink = new JsonlSink({ path: joinPath(dir, 'decisions.jsonl') })
    assert.equal(sink.chainHead(), GENESIS_HASH)
    sink.append(record())
    assert.notEqual(sink.chainHead(), GENESIS_HASH)
  })
})

describe('the JSONL sink', () => {
  it('writes one line per decision, each ending in a newline', () => {
    const dir = workspace()
    const path = joinPath(dir, 'decisions.jsonl')
    const sink = new JsonlSink({ path })
    sink.append(record())
    sink.append(record({ outcome: 'allow' }))
    const text = readFileSync(path, 'utf8')
    assert.equal(text.endsWith('\n'), true)
    assert.equal(text.trimEnd().split('\n').length, 2)
  })

  it('creates the directory it was pointed at', () => {
    const dir = workspace()
    const path = joinPath(dir, 'nested', 'deeper', 'decisions.jsonl')
    assert.notEqual(new JsonlSink({ path }).append(record()), undefined)
    assert.equal(verifyChain(readFileSync(path, 'utf8').split('\n')), undefined)
  })

  it('carries every field of the record onto the line', () => {
    const dir = workspace()
    const path = joinPath(dir, 'decisions.jsonl')
    const written = new JsonlSink({ path }).append(record())!
    const line = JSON.parse(readFileSync(path, 'utf8').trimEnd()) as ChainedRecord
    assert.equal(line.hash, written.hash)
    assert.equal(line.sessionId, 'session-1')
    assert.equal(line.rule, 'untrusted-no-egress')
    assert.equal(line.turn, 3)
    assert.deepEqual(line.label, { trust: 'untrusted', sensitivity: 'secret' })
    assert.deepEqual([...line.capabilities], ['egress', 'mutate'])
  })

  it('reports rather than throws when the path cannot be written', () => {
    const dir = workspace()
    // A regular file cannot be a directory component, so the append fails with
    // ENOTDIR for any user, including root.
    const blocker = joinPath(dir, 'blocker')
    writeFileSync(blocker, 'not a directory\n')
    const errors: unknown[] = []
    const sink = new JsonlSink({
      path: joinPath(blocker, 'decisions.jsonl'),
      report: (error) => errors.push(error),
    })
    assert.equal(sink.append(record()), undefined)
    assert.equal(errors.length, 1)
    assert.equal(sink.chainHead(), GENESIS_HASH, 'a failed write must not advance the chain')
  })

  it('survives a reporter that throws', () => {
    const dir = workspace()
    const blocker = joinPath(dir, 'blocker')
    writeFileSync(blocker, 'not a directory\n')
    const sink = new JsonlSink({
      path: joinPath(blocker, 'decisions.jsonl'),
      report: () => {
        throw new Error('the logger is gone too')
      },
    })
    assert.equal(sink.append(record()), undefined)
  })
})

describe('path expansion', () => {
  it('expands a leading tilde against the home directory', () => {
    assert.equal(expandHome('~/.dsh/airlock/decisions.jsonl'), joinPath(homedir(), '.dsh/airlock/decisions.jsonl'))
    assert.equal(expandHome('~'), homedir())
  })

  it('leaves other paths alone', () => {
    assert.equal(expandHome('/var/log/airlock.jsonl'), '/var/log/airlock.jsonl')
    assert.equal(expandHome('relative/decisions.jsonl'), 'relative/decisions.jsonl')
    assert.equal(expandHome('/tmp/~/decisions.jsonl'), '/tmp/~/decisions.jsonl')
  })

  it('defaults to the documented path, without touching the filesystem', () => {
    assert.equal(new JsonlSink().path, expandHome(DEFAULT_EVIDENCE_PATH))
    assert.equal(new JsonlSink().path.includes('~'), false)
  })

  it('writes into the expanded home when the path carries a tilde', () => {
    const dir = workspace()
    const previous = process.env['HOME']
    process.env['HOME'] = dir
    try {
      if (homedir() !== dir) return
      const sink = new JsonlSink({ path: '~/.dsh/airlock/decisions.jsonl' })
      assert.equal(sink.path, joinPath(dir, '.dsh/airlock/decisions.jsonl'))
      assert.notEqual(sink.append(record()), undefined)
      assert.equal(verifyChain(readFileSync(sink.path, 'utf8').split('\n')), undefined)
    } finally {
      if (previous === undefined) delete process.env['HOME']
      else process.env['HOME'] = previous
    }
  })
})

describe('the OpenTelemetry sink', () => {
  it('adds one span event to the active span', async () => {
    const events: { name: string; attributes: Record<string, unknown> | undefined }[] = []
    const sink = new OtelSink({
      loadOtel: async () => ({
        trace: {
          getActiveSpan: () => ({
            addEvent: (name: string, attributes?: Record<string, unknown>) => {
              events.push({ name, attributes })
            },
          }),
        },
      }),
    })
    sink.emit(chainRecord(GENESIS_HASH, record()))
    await settle()
    assert.equal(events.length, 1)
    assert.equal(events[0]!.name, SPAN_EVENT_NAME)
    assert.equal(events[0]!.attributes?.['airlock.outcome'], 'deny')
    assert.equal(events[0]!.attributes?.['airlock.trust'], 'untrusted')
    assert.equal(events[0]!.attributes?.['airlock.rule'], 'untrusted-no-egress')
  })

  it('loads the api once and emits synchronously after that', async () => {
    let loads = 0
    const events: string[] = []
    const sink = new OtelSink({
      loadOtel: async () => {
        loads += 1
        return {
          trace: {
            getActiveSpan: () => ({
              addEvent: (name: string) => {
                events.push(name)
              },
            }),
          },
        }
      },
    })
    sink.emit(record())
    await settle()
    sink.emit(record())
    assert.equal(events.length, 2, 'the second emit must not wait for a second load')
    assert.equal(loads, 1)
  })

  it('no-ops when the package is absent', async () => {
    const errors: unknown[] = []
    const sink = new OtelSink({
      loadOtel: async () => undefined,
      report: (error) => errors.push(error),
    })
    sink.emit(record())
    await settle()
    sink.emit(record())
    assert.deepEqual(errors, [], 'a missing optional dependency is not an error')
  })

  it('no-ops when the real dynamic import cannot resolve the package', async () => {
    // `@opentelemetry/api` is not installed in this repository, so the default
    // loader exercises the missing-package path.
    const errors: unknown[] = []
    const sink = new OtelSink({ report: (error) => errors.push(error) })
    sink.emit(record())
    await settle()
    assert.deepEqual(errors, [])
  })

  it('contains a loader that rejects', async () => {
    const errors: unknown[] = []
    const sink = new OtelSink({
      loadOtel: () => Promise.reject(new Error('broken')),
      report: (error) => errors.push(error),
    })
    sink.emit(record())
    await settle()
    assert.equal(errors.length, 1)
    sink.emit(record())
    await settle()
    assert.equal(errors.length, 1, 'a failed load is not retried per decision')
  })

  it('contains a span whose addEvent throws', async () => {
    const errors: unknown[] = []
    const sink = new OtelSink({
      loadOtel: async () => ({
        trace: {
          getActiveSpan: () => ({
            addEvent: () => {
              throw new Error('exporter is down')
            },
          }),
        },
      }),
      report: (error) => errors.push(error),
    })
    sink.emit(record())
    await settle()
    assert.equal(errors.length, 1)
  })

  it('does nothing when there is no active span', async () => {
    const sink = new OtelSink({ loadOtel: async () => ({ trace: { getActiveSpan: () => undefined } }) })
    sink.emit(record())
    await settle()
  })

  it('renders only primitive attribute values', () => {
    const attributes = spanAttributes(chainRecord(GENESIS_HASH, record()))
    for (const [key, value] of Object.entries(attributes)) {
      const primitive = typeof value === 'string' || typeof value === 'number'
        || typeof value === 'boolean'
        || (Array.isArray(value) && value.every((entry) => typeof entry === 'string'))
      assert.equal(primitive, true, `${key} must be a primitive attribute`)
    }
    assert.match(String(attributes['airlock.hash']), /^[0-9a-f]{64}$/)
  })

  it('omits the attributes for fields the plugin does not know', () => {
    const attributes = spanAttributes(
      decisionRecord({
        sessionId: 's',
        tool: 'read',
        capabilities: ['read'],
        outcome: 'allow',
        label: { trust: 'user', sensitivity: 'public' },
      }),
    )
    assert.equal('airlock.rule' in attributes, false)
    assert.equal('airlock.turn' in attributes, false)
    assert.equal(attributes['airlock.outcome'], 'allow')
  })
})

describe('both sinks together', () => {
  it('writes the chain and hands the same hash to the span event', async () => {
    const dir = workspace()
    const path = joinPath(dir, 'decisions.jsonl')
    const events: Record<string, unknown>[] = []
    const sink = new EvidenceSink({
      path,
      loadOtel: async () => ({
        trace: {
          getActiveSpan: () => ({
            addEvent: (_name: string, attributes?: Record<string, unknown>) => {
              events.push(attributes ?? {})
            },
          }),
        },
      }),
    })
    const written = sink.emit(record())
    await settle()
    assert.notEqual(written, undefined)
    assert.equal(sink.path, path)
    assert.equal(events[0]?.['airlock.hash'], written!.hash)
    assert.equal(verifyChain(readFileSync(path, 'utf8').split('\n')), undefined)
  })

  it('still emits the span event when the file cannot be written', async () => {
    const dir = workspace()
    const blocker = joinPath(dir, 'blocker')
    writeFileSync(blocker, 'not a directory\n')
    const events: Record<string, unknown>[] = []
    const errors: unknown[] = []
    const sink = new EvidenceSink({
      path: joinPath(blocker, 'decisions.jsonl'),
      report: (error) => errors.push(error),
      loadOtel: async () => ({
        trace: {
          getActiveSpan: () => ({
            addEvent: (_name: string, attributes?: Record<string, unknown>) => {
              events.push(attributes ?? {})
            },
          }),
        },
      }),
    })
    assert.equal(sink.emit(record()), undefined)
    await settle()
    assert.equal(errors.length, 1)
    assert.equal(events.length, 1)
    assert.equal(events[0]?.['airlock.hash'], '')
  })

  it('can run with either sink switched off', () => {
    const dir = workspace()
    const path = joinPath(dir, 'decisions.jsonl')
    const quiet = new EvidenceSink({ path, otlp: false })
    assert.notEqual(quiet.emit(record()), undefined)
    const traced = new EvidenceSink({ jsonl: false, loadOtel: async () => undefined })
    assert.equal(traced.path, undefined)
    assert.equal(traced.emit(record()), undefined)
  })

  it('stamps the version and an ISO timestamp on a built record', () => {
    const built = decisionRecord(
      {
        sessionId: 'session-1',
        tool: 'bash',
        capabilities: ['egress'],
        outcome: 'deny',
        rule: 'secret-no-egress',
        label: { trust: 'workspace', sensitivity: 'secret' },
      },
      new Date('2026-08-16T09:00:00.000Z'),
    )
    assert.equal(built.version, RECORD_VERSION)
    assert.equal(built.timestamp, '2026-08-16T09:00:00.000Z')
    assert.equal(built.callId, undefined)
    assert.equal('callId' in built, false)
  })
})
