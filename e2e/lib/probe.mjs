/**
 * Ask one question of a dsh session log and answer with an exit code.
 *
 * The assertions in `verify.sh` are made against the session log rather than
 * against the model's prose. A model that says it was blocked, or says it was
 * not, is reporting; the log is the record. Every claim in the report is read
 * out of `tool/call` and `tool/result` events.
 *
 * Usage:
 *   node probe.mjs <session-dir> dump
 *   node probe.mjs <session-dir> called <tool>
 *   node probe.mjs <session-dir> succeeded <tool>
 *   node probe.mjs <session-dir> denied <tool> <substring>
 *   node probe.mjs <session-dir> no-airlock-denial
 *   node probe.mjs <session-dir> no-airlock-interference <tool>
 *
 * Exit code 0 means the assertion holds, 1 means it does not, 2 means the
 * probe could not run at all.
 */

import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { readEvents } from './decode-log.mjs'

/**
 * Find the newest `session.jsonl.zstd` under a root.
 * @param {string} root - the sessions root.
 * @returns {string|undefined} the newest log path.
 */
function newestLog(root) {
  const found = []
  const walk = (dir) => {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.name === 'session.jsonl.zstd') found.push(path)
    }
  }
  walk(root)
  if (found.length === 0) return undefined
  return found.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0]
}

/**
 * Flatten the tool traffic of one session.
 * @param {object[]} events - every event in the log.
 * @returns {{calls: object[], results: object[]}} the paired tool traffic.
 */
function toolTraffic(events) {
  const names = new Map()
  const calls = []
  const results = []
  for (const event of events) {
    if (event?.type === 'tool/call') {
      const { callId, name, arguments: args } = event.data ?? {}
      if (typeof callId === 'string') names.set(callId, name)
      calls.push({ seq: event.seq, callId, name, arguments: args })
      continue
    }
    if (event?.type !== 'tool/result') continue
    const message = event.data?.message
    const callId = message?.source?.callId
    const blocks = message?.content?.[0]?.content ?? []
    const text = blocks.map((block) => block?.text ?? '').join('\n')
    const isError = message?.content?.[0]?.isError === true
    results.push({ seq: event.seq, callId, name: names.get(callId), isError, text })
  }
  return { calls, results }
}

const [dir, query, ...rest] = process.argv.slice(2)
if (dir === undefined || query === undefined) {
  process.stderr.write('usage: probe.mjs <session-dir> <query> [args...]\n')
  process.exit(2)
}

const log = newestLog(dir)
if (log === undefined) {
  process.stderr.write(`probe: no session log under ${dir}\n`)
  process.exit(2)
}

const { calls, results } = toolTraffic(readEvents(log))
const DENIAL = 'airlock denied'
const AIRLOCK = 'airlock'

/** @returns {boolean} whether the assertion holds. */
function answer() {
  const [tool, needle] = rest
  switch (query) {
    case 'dump': {
      for (const call of calls) {
        process.stdout.write(`seq ${call.seq} CALL ${call.name} ${call.arguments ?? ''}\n`)
        const result = results.find((entry) => entry.callId === call.callId)
        if (result === undefined) continue
        const label = result.isError ? 'ERROR' : 'OK'
        process.stdout.write(`seq ${result.seq} RESULT ${label} ${result.text.trim()}\n\n`)
      }
      return true
    }
    case 'called':
      return calls.some((call) => call.name === tool)
    case 'succeeded':
      return results.some((entry) => entry.name === tool && !entry.isError)
    case 'denied':
      return results.some((entry) =>
        entry.name === tool
        && entry.isError
        && entry.text.includes(DENIAL)
        && (needle === undefined || entry.text.includes(needle)))
    case 'no-airlock-denial':
      return !results.some((entry) => entry.text.includes(DENIAL))
    case 'no-airlock-interference':
      return results.some((entry) => entry.name === tool)
        && !results.some((entry) => entry.name === tool && entry.text.includes(AIRLOCK))
    default:
      process.stderr.write(`probe: unknown query ${query}\n`)
      process.exit(2)
  }
  return false
}

process.exit(answer() ? 0 : 1)
