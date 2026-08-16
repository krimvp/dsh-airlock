/**
 * Capability classes and the built-in rules.
 *
 * A rule is written over a label and a capability class. No rule reads an
 * argument string, because an argument string is exactly what a model can
 * reformulate. The tool names below come from the harness tool catalogue
 * (`docs/tool-catalog.md` at 0.1.0-rc.5), not from a guess.
 */

import type { Label } from './labels.js'
import { sensitivityAtLeast, trustAtLeast } from './labels.js'

/**
 * What a tool can do with the context it is given.
 *
 * - `egress` — the call can carry context out of the machine.
 * - `mutate` — the call can change the workspace or the host.
 * - `read` — the call brings information in and sends nothing out.
 */
export type Capability = 'egress' | 'mutate' | 'read'

/**
 * Tools that can carry bytes off the machine.
 *
 * `bash`, `pwsh`, and `terminal_send` appear here as well as in the mutating
 * set, because a shell is a general-purpose network client. That double
 * classification is the point of the design: `curl`, `wget`, and a base64
 * Python one-liner are all the same capability, so all three are stopped by
 * the same rule.
 *
 * `run_code` is egress because a Code Mode program executes in-process and can
 * open its own sockets. Its bridged sub-calls re-enter the full guarded
 * pipeline, so the leaf tools it invokes are gated on their own account too.
 */
const EGRESS_TOOLS: readonly string[] = [
  'web_fetch',
  'web_search',
  'bash',
  'pwsh',
  'terminal_send',
  'terminal_open',
  'run_code',
]

/** Tools that can change the workspace or the host. */
const MUTATE_TOOLS: readonly string[] = [
  'write',
  'edit',
  'str_replace_editor',
  'bash',
  'pwsh',
  'terminal_send',
  'terminal_open',
  'terminal_close',
  'terminal_signal',
  'run_code',
]

/**
 * Tools whose results arrive from outside the workspace and are therefore
 * labelled `untrusted` on arrival.
 */
const UNTRUSTED_SOURCE_TOOLS: readonly string[] = ['web_fetch', 'web_search']

/** The MCP bridge registers every server tool under this prefix. */
const MCP_PREFIX = 'mcp__'

/**
 * Classify a tool name.
 *
 * A tool carries every class that applies to it. An MCP tool is both `egress`
 * and `mutate`: the bridge speaks to a process this plugin cannot inspect, so
 * the conservative classification is the only sound one.
 *
 * @param name - the registered tool name, as the model calls it.
 * @returns every capability class the tool belongs to.
 */
export function classify(name: string): ReadonlySet<Capability> {
  const classes = new Set<Capability>()
  if (name.startsWith(MCP_PREFIX)) {
    classes.add('egress')
    classes.add('mutate')
    return classes
  }
  if (EGRESS_TOOLS.includes(name)) classes.add('egress')
  if (MUTATE_TOOLS.includes(name)) classes.add('mutate')
  if (classes.size === 0) classes.add('read')
  return classes
}

/** A rule that Gate A can enforce. A guard may only deny, so every rule here denies. */
export interface Rule {
  /** Stable identifier, quoted in the denial message and in evidence. */
  readonly id: string
  /** The capability class the rule governs. */
  readonly capability: Capability
  /** Whether the step's context label triggers the rule. */
  readonly matches: (label: Label) => boolean
  /** Why this rule exists, in one line, for the denial message. */
  readonly rationale: string
}

/**
 * The two rules the first milestone ships.
 *
 * They are the two halves of the demo: untrusted content cannot reach a tool
 * that talks to the network, and secret content cannot leave through one.
 * Nothing here restricts reading or searching, which is most of what an agent
 * does — see the over-blocking discussion in the README.
 */
export const DEFAULT_RULES: readonly Rule[] = Object.freeze([
  Object.freeze({
    id: 'untrusted-no-egress',
    capability: 'egress',
    matches: (label: Label) => trustAtLeast(label, 'untrusted'),
    rationale: 'untrusted content in context cannot direct a tool that reaches the network',
  }),
  Object.freeze({
    id: 'secret-no-egress',
    capability: 'egress',
    matches: (label: Label) => sensitivityAtLeast(label, 'secret'),
    rationale: 'secret content in context cannot leave through a tool that reaches the network',
  }),
]) as readonly Rule[]

/** Paths whose contents are labelled `secret` when a tool reads them. */
export const DEFAULT_SECRET_PATHS: readonly string[] = Object.freeze([
  '**/.env',
  '**/.env.*',
  '**/credentials',
  '**/.aws/**',
  '**/.ssh/**',
  '**/*.pem',
  '**/*.key',
  '**/.netrc',
  '**/.npmrc',
  '**/id_rsa*',
  '**/id_ed25519*',
])

/**
 * Test whether a tool's results are untrusted by origin.
 * @param name - the registered tool name.
 * @returns `true` when the tool reads from outside the workspace.
 */
export function isUntrustedSource(name: string): boolean {
  return UNTRUSTED_SOURCE_TOOLS.includes(name) || name.startsWith(MCP_PREFIX)
}

/**
 * Match a path against one glob.
 *
 * Supports `**` across separators, `*` within one segment, and `?`. This is
 * deliberately small: the pattern set is operator-authored configuration, not
 * model-controlled input, so it needs no defence against a crafted pattern.
 *
 * @param pattern - the glob.
 * @param path - the path to test, with `\` normalised to `/`.
 * @returns `true` when the glob matches the whole path.
 */
export function matchesGlob(pattern: string, path: string): boolean {
  const expanded = pattern.startsWith('~/') ? `**/${pattern.slice(2)}` : pattern
  let regex = '^'
  for (let index = 0; index < expanded.length; index += 1) {
    const char = expanded[index]
    if (char === '*') {
      if (expanded[index + 1] === '*') {
        // `**/` also matches zero segments, so `**/.env` matches a bare `.env`.
        if (expanded[index + 2] === '/') {
          regex += '(?:.*/)?'
          index += 2
        } else {
          regex += '.*'
          index += 1
        }
      } else {
        regex += '[^/]*'
      }
      continue
    }
    if (char === '?') {
      regex += '[^/]'
      continue
    }
    regex += char!.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  regex += '$'
  return new RegExp(regex).test(path)
}

/**
 * Test a path against every configured secret glob.
 * @param path - the path a tool call named.
 * @param patterns - the globs to test.
 * @returns the glob that matched, or `undefined`.
 */
export function matchSecretPath(
  path: string,
  patterns: readonly string[],
): string | undefined {
  const normalised = path.replace(/\\/g, '/')
  return patterns.find((pattern) => matchesGlob(pattern, normalised))
}
