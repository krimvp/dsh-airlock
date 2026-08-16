/**
 * Decode a dsh session log.
 *
 * `@deepseek-ai/dsh-session-persistence-jsonl` writes `session.jsonl.zstd` as a
 * sequence of independently framed zstd blocks appended as the session grows.
 * Node's one-shot `zstdDecompressSync` and its stream both stop after the first
 * frame, so the file is split on the zstd magic number and each frame is
 * decoded on its own.
 *
 * Usage: node decode-log.mjs <session.jsonl.zstd>
 * Prints the decoded JSONL on stdout.
 */

import { readFileSync } from 'node:fs'
import { zstdDecompressSync } from 'node:zlib'

/** The zstd frame magic number, little endian. */
const MAGIC = [0x28, 0xb5, 0x2f, 0xfd]

/**
 * @param {string} file - path to a `session.jsonl.zstd`.
 * @returns {string} the decoded JSONL text.
 */
export function decodeSessionLog(file) {
  const raw = readFileSync(file)
  const offsets = []
  for (let i = 0; i <= raw.length - MAGIC.length; i += 1) {
    if (MAGIC.every((byte, k) => raw[i + k] === byte)) offsets.push(i)
  }
  if (offsets.length === 0) return raw.toString('utf8')
  let out = ''
  for (let k = 0; k < offsets.length; k += 1) {
    const end = k + 1 < offsets.length ? offsets[k + 1] : raw.length
    out += zstdDecompressSync(raw.subarray(offsets[k], end)).toString('utf8')
  }
  return out
}

/**
 * @param {string} file - path to a `session.jsonl.zstd`.
 * @returns {object[]} every parsable event in log order.
 */
export function readEvents(file) {
  const events = []
  for (const line of decodeSessionLog(file).trim().split('\n')) {
    if (line.trim() === '') continue
    try {
      events.push(JSON.parse(line))
    } catch {
      // A partially written trailing frame is not an event. Skip it.
    }
  }
  return events
}

if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const file = process.argv[2]
  if (file === undefined) {
    process.stderr.write('usage: decode-log.mjs <session.jsonl.zstd>\n')
    process.exit(2)
  }
  process.stdout.write(decodeSessionLog(file))
}
