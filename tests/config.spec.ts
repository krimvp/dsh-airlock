import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'

import type { PolicyConfig } from '../src/config.js'
import {
  PolicyConfigError,
  loadPolicy,
  loadPolicyFile,
  mergeConfigs,
  policyFromConfig,
  resolvePolicy,
  unwrapPolicyDocument,
  validateConfig,
} from '../src/config.js'
import {
  DEFAULT_CLASSES,
  DEFAULT_OPAQUE_READERS,
  DEFAULT_POLICY,
  DEFAULT_SECRET_PATHS,
  GUARD_SEAM,
  classify,
  selectRules,
} from '../src/policy.js'

/** A scratch directory for the tests that exercise the real filesystem. */
const workspace = mkdtempSync(join(tmpdir(), 'airlock-config-'))

after(() => {
  rmSync(workspace, { recursive: true, force: true })
})

/**
 * Write a policy file into the scratch directory.
 * @param name - the file name, whose extension selects the parser.
 * @param text - the file's contents.
 * @returns the absolute path.
 */
function writePolicy(name: string, text: string): string {
  const path = join(workspace, name)
  writeFileSync(path, text, 'utf8')
  return path
}

/**
 * Assert that a configuration is refused, and return the error.
 * @param value - the configuration to validate.
 * @returns the error that was thrown.
 */
function refusal(value: unknown): PolicyConfigError {
  try {
    validateConfig(value)
  } catch (error) {
    assert.ok(error instanceof PolicyConfigError, 'a refusal must be a PolicyConfigError')
    return error
  }
  assert.fail('the configuration was accepted')
}

describe('validating a configuration', () => {
  it('accepts an empty configuration', () => {
    assert.deepEqual(validateConfig({}), {})
  })

  it('accepts the documented policy in full', () => {
    const config = validateConfig({
      posture: 'ask',
      dryRun: false,
      classes: { egress: ['web_fetch', 'bash', 'mcp__*'], mutate: ['write', 'edit'] },
      secretPaths: ['**/.env', '~/.ssh/**'],
      untrustedSources: ['web_fetch', 'web_search', 'mcp__*'],
      rules: [
        { when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
        { when: { trust: 'untrusted', capability: 'mutate' }, then: 'ask' },
        { when: { sensitivity: 'secret', capability: 'egress' }, then: 'deny' },
        { when: { sensitivity: 'secret', boundary: 'provider' }, then: 'redact' },
      ],
      declassify: { allow: true },
      evidence: { otlp: true, jsonl: '~/.dsh/airlock/decisions.jsonl' },
    })
    assert.equal(config.rules?.length, 4)
    assert.equal(config.posture, 'ask')
  })

  it('holds only the keys the layer actually set', () => {
    assert.deepEqual(Object.keys(validateConfig({ dryRun: true })), ['dryRun'])
  })

  it('treats an undefined value as an unset key', () => {
    // A caller that forwards `{ secretPaths: config.secretPaths }` has set nothing.
    assert.deepEqual(validateConfig({ secretPaths: undefined }), {})
  })

  it('refuses a configuration that is not a mapping', () => {
    assert.match(refusal(['deny']).message, /must be a mapping, but it is a list/)
    assert.match(refusal(null).message, /must be a mapping, but it is null/)
    assert.match(refusal('deny').message, /must be a mapping/)
  })
})

describe('refusing a typo', () => {
  it('refuses an unknown top-level key', () => {
    const error = refusal({ secretPath: ['**/.env'] })
    assert.equal(error.at, 'airlock.secretPath')
    assert.match(error.message, /is not a key airlock knows/)
    assert.match(error.message, /`secretPaths`/)
  })

  it('refuses an unknown key inside a rule', () => {
    const error = refusal({ rules: [{ when: {}, then: 'deny', becuase: 'typo' }] })
    assert.equal(error.at, 'airlock.rules[0].becuase')
  })

  it('refuses an unknown key inside a when, and says why there is no argument key', () => {
    const error = refusal({ rules: [{ when: { sensitivty: 'secret' }, then: 'deny' }] })
    assert.equal(error.at, 'airlock.rules[0].when.sensitivty')
    assert.match(error.message, /`trust`, `sensitivity`, `capability`, `boundary`/)
    assert.match(error.message, /no key for an argument value or for tool output/)
  })

  it('refuses an argument predicate outright', () => {
    // The one invariant: the gate decides over labels, never over an argument.
    const error = refusal({ rules: [{ when: { argumentMatches: 'curl .*' }, then: 'deny' }] })
    assert.match(error.message, /is not a key airlock knows/)
  })

  it('refuses an unknown effect', () => {
    const error = refusal({ rules: [{ when: { capability: 'egress' }, then: 'dney' }] })
    assert.equal(error.at, 'airlock.rules[0].then')
    assert.match(error.message, /is not an effect airlock knows/)
    assert.match(error.message, /`deny`, `ask`, `redact`, `allow`/)
  })

  it('refuses an unknown posture', () => {
    const error = refusal({ posture: 'prompt' })
    assert.equal(error.at, 'airlock.posture')
    assert.match(error.message, /is not a posture airlock knows/)
    assert.match(error.message, /`ask`, `deny`/)
  })

  it('refuses an unknown trust or sensitivity level', () => {
    assert.match(
      refusal({ rules: [{ when: { trust: 'untrused' }, then: 'deny' }] }).message,
      /is not a trust level airlock knows/,
    )
    assert.match(
      refusal({ rules: [{ when: { sensitivity: 'private' }, then: 'deny' }] }).message,
      /is not a sensitivity level airlock knows/,
    )
  })

  it('refuses an unknown capability class in a rule', () => {
    const error = refusal({ rules: [{ when: { capability: 'network' }, then: 'deny' }] })
    assert.equal(error.at, 'airlock.rules[0].when.capability')
    assert.match(error.message, /`egress`, `mutate`, `read`/)
  })

  it('refuses an unknown capability class in the class table', () => {
    const error = refusal({ classes: { egres: ['web_fetch'] } })
    assert.equal(error.at, 'airlock.classes.egres')
    assert.match(error.message, /is not a capability class airlock knows/)
  })

  it('refuses listing the read class, and says how a tool joins it', () => {
    const error = refusal({ classes: { read: ['read'] } })
    assert.equal(error.at, 'airlock.classes.read')
    assert.match(error.message, /matches no other class/)
  })

  it('refuses an unknown boundary', () => {
    assert.match(
      refusal({ rules: [{ when: { boundary: 'model' }, then: 'deny' }] }).message,
      /is not a boundary airlock knows/,
    )
  })

  it('refuses an unknown evidence or declassify key', () => {
    assert.equal(refusal({ evidence: { jsonlPath: '/tmp/x' } }).at, 'airlock.evidence.jsonlPath')
    assert.equal(refusal({ declassify: { allowed: true } }).at, 'airlock.declassify.allowed')
  })
})

describe('refusing a shape', () => {
  it('refuses a string where a list is required', () => {
    const error = refusal({ secretPaths: '**/.env' })
    assert.equal(error.at, 'airlock.secretPaths')
    assert.match(error.message, /must be a list of strings, but it is a string/)
  })

  it('refuses a non-string inside a list', () => {
    const error = refusal({ untrustedSources: ['web_fetch', 7] })
    assert.equal(error.at, 'airlock.untrustedSources[1]')
    assert.match(error.message, /must be a non-empty string/)
  })

  it('refuses an empty string inside a list', () => {
    assert.equal(refusal({ secretPaths: [''] }).at, 'airlock.secretPaths[0]')
  })

  it('refuses a mapping where the rule list is required', () => {
    const error = refusal({ rules: { when: {}, then: 'deny' } })
    assert.equal(error.at, 'airlock.rules')
    assert.match(error.message, /must be a list of rules/)
  })

  it('refuses a rule that is not a mapping', () => {
    assert.equal(refusal({ rules: ['deny'] }).at, 'airlock.rules[0]')
  })

  it('refuses a non-boolean switch', () => {
    assert.match(refusal({ dryRun: 'yes' }).message, /must be true or false, but it is a string/)
    assert.match(refusal({ declassify: { allow: 1 } }).message, /must be true or false/)
    assert.match(refusal({ evidence: { otlp: 'on' } }).message, /must be true or false/)
  })

  it('refuses an evidence path that is neither a path nor false', () => {
    const error = refusal({ evidence: { jsonl: 3 } })
    assert.equal(error.at, 'airlock.evidence.jsonl')
    assert.match(error.message, /must be a file path or false/)
  })

  it('refuses a rule with no when', () => {
    const error = refusal({ rules: [{ then: 'deny' }] })
    assert.equal(error.at, 'airlock.rules[0]')
    assert.match(error.message, /needs a `when`/)
  })

  it('refuses a rule with no then', () => {
    assert.match(refusal({ rules: [{ when: {} }] }).message, /needs a `then`/)
  })

  it('refuses a repeated rule id', () => {
    const error = refusal({
      rules: [
        { id: 'no-egress', when: { capability: 'egress' }, then: 'deny' },
        { id: 'no-egress', when: { capability: 'mutate' }, then: 'deny' },
      ],
    })
    assert.equal(error.at, 'airlock.rules[1].id')
    assert.match(error.message, /Rule ids must be unique/)
  })
})

describe('refusing an effect no seam can enforce', () => {
  it('refuses a redaction at the tool boundary', () => {
    // `tools/pre-execute` cannot rewrite arguments, so nothing scrubs a call.
    const error = refusal({ rules: [{ when: { capability: 'egress' }, then: 'redact' }] })
    assert.equal(error.at, 'airlock.rules[0]')
    assert.match(error.message, /no seam enforces that/)
    assert.match(error.message, /`redact` is enforced at the provider boundary/)
  })

  it('refuses a denial at the provider boundary', () => {
    const error = refusal({ rules: [{ when: { boundary: 'provider' }, then: 'deny' }] })
    assert.match(error.message, /The provider boundary carries `redact`, `allow`/)
  })

  it('refuses an ask at the provider boundary', () => {
    assert.match(
      refusal({ rules: [{ when: { boundary: 'provider' }, then: 'ask' }] }).message,
      /no seam enforces that/,
    )
  })

  it('accepts every pair a seam does carry', () => {
    const config = validateConfig({
      rules: [
        { when: { capability: 'egress' }, then: 'deny' },
        { when: { capability: 'mutate' }, then: 'ask' },
        { when: { capability: 'egress' }, then: 'allow' },
        { when: { boundary: 'provider' }, then: 'redact' },
        { when: { boundary: 'provider' }, then: 'allow' },
      ],
    })
    assert.equal(config.rules?.length, 5)
  })
})

describe('merging layers', () => {
  const lower: PolicyConfig = {
    posture: 'ask',
    dryRun: true,
    secretPaths: ['**/.env'],
    classes: { egress: ['web_fetch'] },
    evidence: { otlp: true, jsonl: '/var/log/airlock.jsonl' },
  }

  it('lets the higher layer win one key at a time', () => {
    const merged = mergeConfigs(lower, { posture: 'deny' })
    assert.equal(merged.posture, 'deny')
    assert.equal(merged.dryRun, true)
  })

  it('leaves the lower layer alone where the higher one is silent', () => {
    assert.deepEqual(mergeConfigs(lower, {}).secretPaths, ['**/.env'])
  })

  it('replaces a list rather than concatenating it', () => {
    const merged = mergeConfigs(lower, { secretPaths: ['**/*.pem'] })
    assert.deepEqual(merged.secretPaths, ['**/*.pem'])
  })

  it('merges the class table one class at a time', () => {
    const merged = mergeConfigs(lower, { classes: { mutate: ['write'] } })
    assert.deepEqual(merged.classes, { egress: ['web_fetch'], mutate: ['write'] })
  })

  it('merges the evidence switches one at a time', () => {
    const merged = mergeConfigs(lower, { evidence: { otlp: false } })
    assert.deepEqual(merged.evidence, { otlp: false, jsonl: '/var/log/airlock.jsonl' })
  })
})

describe('resolving a policy', () => {
  it('fills every built-in default', () => {
    const policy = resolvePolicy({})
    assert.equal(policy.posture, 'ask')
    assert.equal(policy.dryRun, false)
    assert.deepEqual(policy.classes, DEFAULT_CLASSES)
    assert.deepEqual(policy.secretPaths, DEFAULT_SECRET_PATHS)
    assert.deepEqual(policy.rules, DEFAULT_POLICY.rules)
    assert.equal(policy.declassify.allow, true)
    assert.equal(policy.evidence.otlp, true)
    assert.equal(policy.evidence.jsonl, true)
  })

  it('keeps the built-in class a configuration does not mention', () => {
    const policy = resolvePolicy({ classes: { egress: ['internal_upload'] } })
    assert.deepEqual(policy.classes.egress, ['internal_upload'])
    assert.deepEqual(policy.classes.mutate, DEFAULT_CLASSES.mutate)
    assert.equal(classify('write', policy.classes).has('mutate'), true)
  })

  it('replaces the built-in rules when a policy lists its own', () => {
    const policy = resolvePolicy(
      validateConfig({ rules: [{ id: 'only-rule', when: { capability: 'mutate' }, then: 'deny' }] }),
    )
    assert.deepEqual(policy.rules.map((rule) => rule.id), ['only-rule'])
  })

  it('leaves a policy with no rules enforcing nothing, visibly', () => {
    assert.equal(resolvePolicy(validateConfig({ rules: [] })).rules.length, 0)
  })

  it('expands a leading tilde in the evidence path', () => {
    const policy = resolvePolicy(validateConfig({ evidence: { jsonl: '~/audit/airlock.jsonl' } }))
    assert.equal(policy.evidence.path, join(homedir(), 'audit/airlock.jsonl'))
    assert.equal(policy.evidence.jsonl, true)
  })

  it('reads a false evidence path as a disabled sink', () => {
    const policy = resolvePolicy(validateConfig({ evidence: { jsonl: false } }))
    assert.equal(policy.evidence.jsonl, false)
    assert.equal(policy.evidence.path, DEFAULT_POLICY.evidence.path)
  })

  it('compiles the rules into something a seam can select', () => {
    const policy = resolvePolicy(
      validateConfig({
        rules: [
          { id: 'untrusted-no-egress', when: { trust: 'untrusted', capability: 'egress' }, then: 'deny' },
          { id: 'untrusted-ask-mutate', when: { trust: 'untrusted', capability: 'mutate' }, then: 'ask' },
        ],
      }),
    )
    assert.deepEqual(
      selectRules(policy, GUARD_SEAM).map((rule) => rule.id),
      ['untrusted-no-egress'],
    )
  })
})

describe('the mount config on its own', () => {
  it('resolves without touching the filesystem', () => {
    assert.equal(policyFromConfig({ posture: 'deny' }).posture, 'deny')
    assert.equal(policyFromConfig().posture, 'ask')
  })

  it('refuses to resolve synchronously when a policy file is named', () => {
    // Ignoring the file would enforce a policy the operator did not write.
    assert.throws(
      () => policyFromConfig({ policyFile: 'airlock.policy.yml' }),
      /needs `loadPolicy\(\)`/,
    )
  })
})

describe('loading a workspace policy file', () => {
  it('reads a JSON policy with no dependency at all', async () => {
    const path = writePolicy(
      'policy.json',
      JSON.stringify({ posture: 'deny', rules: [{ id: 'json-rule', when: {}, then: 'deny' }] }),
    )
    const policy = await loadPolicy({}, { policyFile: path })
    assert.equal(policy.posture, 'deny')
    assert.deepEqual(new Set(policy.rules.map((rule) => rule.id)), new Set(['json-rule']))
  })

  it('reads a YAML policy through js-yaml', async () => {
    const path = writePolicy(
      'policy.yml',
      [
        'posture: deny',
        'secretPaths:',
        '  - "**/.env"',
        'rules:',
        '  - when: { trust: untrusted, capability: egress }',
        '    then: deny',
      ].join('\n'),
    )
    const policy = await loadPolicy({}, { policyFile: path, loadYaml: () => import('js-yaml') })
    assert.equal(policy.posture, 'deny')
    assert.deepEqual(policy.secretPaths, ['**/.env'])
    assert.equal(policy.rules.length, 1)
  })

  it('unwraps a document written under a top-level airlock key', async () => {
    const path = writePolicy('wrapped.yml', ['airlock:', '  posture: deny'].join('\n'))
    const policy = await loadPolicy({}, { policyFile: path, loadYaml: () => import('js-yaml') })
    assert.equal(policy.posture, 'deny')
  })

  it('passes an unwrapped document through untouched', () => {
    assert.deepEqual(unwrapPolicyDocument({ posture: 'deny' }), { posture: 'deny' })
    assert.deepEqual(unwrapPolicyDocument({ airlock: {}, other: 1 }), { airlock: {}, other: 1 })
  })

  it('resolves a relative path against the configured directory', async () => {
    writePolicy('relative.json', JSON.stringify({ dryRun: true }))
    const policy = await loadPolicy({ policyFile: 'relative.json' }, { cwd: workspace })
    assert.equal(policy.dryRun, true)
  })

  it('validates a policy file as strictly as the mount config', async () => {
    const path = writePolicy('broken.json', JSON.stringify({ rules: [{ when: {}, then: 'dney' }] }))
    await assert.rejects(
      loadPolicy({}, { policyFile: path }),
      (error: unknown) => {
        assert.ok(error instanceof PolicyConfigError)
        assert.match(error.message, /is not an effect airlock knows/)
        assert.match(error.message, /the policy file/)
        return true
      },
    )
  })

  it('refuses a policy file that names another policy file', async () => {
    const path = writePolicy('chained.json', JSON.stringify({ policyFile: 'other.json' }))
    await assert.rejects(loadPolicy({}, { policyFile: path }), /Only the mount config may name one/)
  })
})

describe('failing loudly at load', () => {
  it('refuses a policy file it cannot read', async () => {
    await assert.rejects(
      loadPolicy({}, { policyFile: join(workspace, 'absent.json') }),
      (error: unknown) => {
        assert.ok(error instanceof PolicyConfigError)
        assert.match(error.message, /cannot be read/)
        assert.match(error.message, /a policy that does not load is a policy that is not enforced/)
        return true
      },
    )
  })

  it('refuses a policy file that is not valid JSON', async () => {
    const path = writePolicy('invalid.json', '{ posture: deny')
    await assert.rejects(loadPolicy({}, { policyFile: path }), /is not valid JSON/)
  })

  it('refuses a policy file that is not valid YAML', async () => {
    const path = writePolicy('invalid.yaml', 'rules:\n  - when: {\n')
    await assert.rejects(
      loadPolicy({}, { policyFile: path, loadYaml: () => import('js-yaml') }),
      /is not valid YAML/,
    )
  })

  it('refuses an extension it does not read', async () => {
    const path = writePolicy('policy.toml', 'posture = "deny"')
    await assert.rejects(loadPolicy({}, { policyFile: path }), /which airlock does not read/)
  })

  it('names the missing package when js-yaml is unavailable', async () => {
    // The policy file is never silently ignored. A policy that does not load is
    // a policy that is not enforced.
    const path = writePolicy('needs-yaml.yaml', 'posture: deny')
    await assert.rejects(
      loadPolicyFile(path, { loadYaml: () => Promise.reject(new Error('Cannot find module')) }),
      (error: unknown) => {
        assert.ok(error instanceof PolicyConfigError)
        assert.match(error.message, /needs the optional peer dependency `js-yaml`/)
        assert.match(error.message, /npm install js-yaml/)
        assert.match(error.message, /not ignored/)
        return true
      },
    )
  })

  it('refuses a js-yaml that exposes no load function', async () => {
    const path = writePolicy('odd-yaml.yaml', 'posture: deny')
    await assert.rejects(
      loadPolicyFile(path, { loadYaml: async () => ({}) }),
      /exposes no `load` function/,
    )
  })

  it('refuses a policy file whose document is not a mapping', async () => {
    const path = writePolicy('list.json', JSON.stringify(['deny']))
    await assert.rejects(loadPolicy({}, { policyFile: path }), /must be a mapping/)
  })
})

describe('the merge order end to end', () => {
  it('puts the mount config above the policy file above the defaults', async () => {
    const path = writePolicy(
      'precedence.json',
      JSON.stringify({ posture: 'ask', dryRun: true, secretPaths: ['**/from-file'] }),
    )
    const policy = await loadPolicy({ policyFile: path, posture: 'deny' })

    // The mount config wins where it speaks.
    assert.equal(policy.posture, 'deny')
    // The file wins over the defaults where the mount config is silent.
    assert.equal(policy.dryRun, true)
    assert.deepEqual(policy.secretPaths, ['**/from-file'])
    // The defaults fill what neither layer set.
    assert.deepEqual(policy.classes, DEFAULT_CLASSES)
    assert.deepEqual(policy.untrustedSources, DEFAULT_POLICY.untrustedSources)
  })

  it('lets the load options override the file the mount config names', async () => {
    const named = writePolicy('named.json', JSON.stringify({ posture: 'ask' }))
    const override = writePolicy('override.json', JSON.stringify({ posture: 'deny' }))
    const policy = await loadPolicy({ policyFile: named }, { policyFile: override })
    assert.equal(policy.posture, 'deny')
  })

  it('needs no file when the mount config names none', async () => {
    assert.equal((await loadPolicy({ dryRun: true })).dryRun, true)
    assert.deepEqual((await loadPolicy()).rules, DEFAULT_POLICY.rules)
  })
})

describe('the preStep section', () => {
  it('accepts the documented shape in full', () => {
    const config = validateConfig({
      preStep: {
        secretProducers: ['vault', 'secrets-*'],
        untrustedProducers: ['inbox'],
        redactAtOrAbove: 'confidential',
        reject: { trust: 'untrusted', sensitivity: 'secret' },
      },
    })
    assert.deepEqual(config.preStep, {
      secretProducers: ['vault', 'secrets-*'],
      untrustedProducers: ['inbox'],
      redactAtOrAbove: 'confidential',
      reject: { trust: 'untrusted', sensitivity: 'secret' },
    })
  })

  it('refuses a typo, and names the path it is at', () => {
    const error = refusal({ preStep: { secretProducer: ['vault'] } })
    assert.equal(error.at, 'airlock.preStep.secretProducer')
    assert.match(error.message, /is not a key airlock knows/)
    assert.match(
      error.message,
      /`secretProducers`, `untrustedProducers`, `redactAtOrAbove`, `reject`/,
    )
  })

  it('refuses a typo inside the rejection, and says there is no key for a message', () => {
    const error = refusal({ preStep: { reject: { sensitivty: 'secret' } } })
    assert.equal(error.at, 'airlock.preStep.reject.sensitivty')
    assert.match(error.message, /`trust`, `sensitivity`/)
    assert.match(error.message, /no key for a message body/)
  })

  it('refuses an unknown sensitivity level', () => {
    const error = refusal({ preStep: { redactAtOrAbove: 'very-secret' } })
    assert.equal(error.at, 'airlock.preStep.redactAtOrAbove')
    assert.match(error.message, /`public`, `confidential`, `secret`/)
  })

  it('refuses an unknown trust level in the rejection', () => {
    const error = refusal({ preStep: { reject: { trust: 'unstrusted' } } })
    assert.equal(error.at, 'airlock.preStep.reject.trust')
    assert.match(error.message, /is not a trust level airlock knows/)
  })

  it('refuses a producer list that is not a list of strings', () => {
    assert.equal(refusal({ preStep: { secretProducers: 'vault' } }).at, 'airlock.preStep.secretProducers')
    assert.equal(refusal({ preStep: { untrustedProducers: [1] } }).at, 'airlock.preStep.untrustedProducers[0]')
  })

  it('refuses a rejection that would never fire', () => {
    const error = refusal({ preStep: { reject: {} } })
    assert.equal(error.at, 'airlock.preStep.reject')
    assert.match(error.message, /would never reject a step/)
  })

  it('resolves onto the policy, and stays inert when it is absent', () => {
    assert.deepEqual(resolvePolicy({}).preStep, {})
    assert.deepEqual(resolvePolicy({ preStep: { secretProducers: ['vault'] } }).preStep, {
      secretProducers: ['vault'],
    })
  })

  it('leaves a key the layer did not set absent rather than undefined', () => {
    const preStep = resolvePolicy({ preStep: { redactAtOrAbove: 'secret' } }).preStep
    assert.equal(Object.hasOwn(preStep, 'secretProducers'), false)
    assert.equal(Object.hasOwn(preStep, 'reject'), false)
  })

  it('merges one key at a time across layers', () => {
    const merged = mergeConfigs(
      { preStep: { secretProducers: ['vault'] } },
      { preStep: { redactAtOrAbove: 'confidential' } },
    )
    assert.deepEqual(merged.preStep, {
      secretProducers: ['vault'],
      redactAtOrAbove: 'confidential',
    })
  })
})

describe('the backstop section', () => {
  it('accepts and resolves the auxiliary switch', () => {
    assert.deepEqual(validateConfig({ backstop: { auxiliary: true } }).backstop, { auxiliary: true })
    assert.equal(resolvePolicy({ backstop: { auxiliary: true } }).backstop.auxiliary, true)
    assert.equal(resolvePolicy({}).backstop.auxiliary, false)
    assert.equal(resolvePolicy({}).backstop.auxiliary, DEFAULT_POLICY.backstop.auxiliary)
  })

  it('refuses a typo, and points at the rule that actually arms the backstop', () => {
    const error = refusal({ backstop: { enabled: true } })
    assert.equal(error.at, 'airlock.backstop.enabled')
    assert.match(error.message, /`boundary: provider`/)
  })

  it('refuses a non-boolean auxiliary', () => {
    assert.equal(refusal({ backstop: { auxiliary: 'yes' } }).at, 'airlock.backstop.auxiliary')
  })
})

describe('the opaqueReaders section', () => {
  it('accepts the documented shape in full', () => {
    const config = validateConfig({
      opaqueReaders: {
        tools: ['bash', 'pwsh', 'run_code', 'terminal_*'],
        sensitivity: 'secret',
        trust: 'workspace',
      },
    })
    assert.deepEqual(config.opaqueReaders, {
      tools: ['bash', 'pwsh', 'run_code', 'terminal_*'],
      sensitivity: 'secret',
      trust: 'workspace',
    })
  })

  it('is off until an operator names a tool', () => {
    const policy = resolvePolicy({})
    assert.deepEqual(policy.opaqueReaders.tools, [])
    assert.equal(policy.opaqueReaders.sensitivity, 'secret')
    assert.deepEqual(policy.opaqueReaders, DEFAULT_OPAQUE_READERS)
  })

  it('resolves a named tool onto the policy, keeping the default floor', () => {
    const readers = resolvePolicy({ opaqueReaders: { tools: ['bash'] } }).opaqueReaders
    assert.deepEqual(readers.tools, ['bash'])
    assert.equal(readers.sensitivity, 'secret')
  })

  it('leaves the trust floor absent rather than undefined when nobody set one', () => {
    const readers = resolvePolicy({ opaqueReaders: { tools: ['bash'] } }).opaqueReaders
    assert.equal(Object.hasOwn(readers, 'trust'), false)
    assert.equal(resolvePolicy({ opaqueReaders: { trust: 'untrusted' } }).opaqueReaders.trust, 'untrusted')
  })

  it('refuses a typo, and names the path it is at', () => {
    const error = refusal({ opaqueReaders: { tool: ['bash'] } })
    assert.equal(error.at, 'airlock.opaqueReaders.tool')
    assert.match(error.message, /is not a key airlock knows/)
    assert.match(error.message, /`tools`, `sensitivity`, `trust`/)
  })

  it('says there is no key for a command string', () => {
    const error = refusal({ opaqueReaders: { commandPattern: 'cat *' } })
    assert.equal(error.at, 'airlock.opaqueReaders.commandPattern')
    assert.match(error.message, /no key for a command string/)
  })

  it('refuses an unknown sensitivity level', () => {
    const error = refusal({ opaqueReaders: { tools: ['bash'], sensitivity: 'very-secret' } })
    assert.equal(error.at, 'airlock.opaqueReaders.sensitivity')
    assert.match(error.message, /`public`, `confidential`, `secret`/)
  })

  it('refuses an unknown trust level', () => {
    const error = refusal({ opaqueReaders: { tools: ['bash'], trust: 'unstrusted' } })
    assert.equal(error.at, 'airlock.opaqueReaders.trust')
    assert.match(error.message, /is not a trust level airlock knows/)
  })

  it('refuses a tool list that is not a list of strings', () => {
    assert.equal(refusal({ opaqueReaders: { tools: 'bash' } }).at, 'airlock.opaqueReaders.tools')
    assert.equal(refusal({ opaqueReaders: { tools: [1] } }).at, 'airlock.opaqueReaders.tools[0]')
  })

  it('merges one key at a time across layers', () => {
    const merged = mergeConfigs(
      { opaqueReaders: { tools: ['bash'] } },
      { opaqueReaders: { sensitivity: 'confidential' } },
    )
    assert.deepEqual(merged.opaqueReaders, { tools: ['bash'], sensitivity: 'confidential' })
  })
})
