import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { classify, isUntrustedSource, matchSecretPath, matchesGlob } from '../src/policy.js'

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
