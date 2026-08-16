# Publishing 0.1.0

The runbook for finishing publication from a local checkout with npm and GitHub
push rights. The steps are ordered, and the order matters: step 4 before step 3
gets the project rejected by the registry for three weeks.

Everything below was checked against the live registry and npm on 2026-08-16.

```sh
git clone https://github.com/krimvp/dsh-airlock.git
cd dsh-airlock
npm install
npm run build && npm test     # expect 390 tests, 65 suites, 0 failures
```

## 1. Make `main` the default branch

GitHub set the default branch to the first branch that was pushed, which was
`claude/work-in-progress-7ilpg1`. Both branches hold the identical commit, so
nothing is missing, but a visitor currently lands on a branch named after a
work in progress.

Settings, then Branches, then switch the default to `main`. Delete the other
branch afterwards if you want.

This is a web-UI step. The API needs a token with `repo` scope, which this
session did not have.

## 2. Confirm the package before publishing

```sh
npm pack --dry-run
```

Expect `dsh-airlock-0.1.0.tgz`, about 128 kB, 55 files, `dist/` and the
documentation only. The name is unregistered, so the first publish claims it.

## 3. Publish to npm

```sh
npm login
npm publish --access public
```

The registry defines a plugin's install path as a published package a profile
can depend on. Nothing after this point works until the package exists.

Confirm it resolves:

```sh
npm view dsh-airlock version
```

## 4. Add the discovery topics

Add the `dsh-plugin` topic to the repository, and `dsh` alongside it.

**Do this after step 3, never before.** The registry runs a scheduled workflow
that sweeps the `dsh-plugin` topic, applies its spam gate, and records what
fails. A repository carrying the topic with no published package fails gate one
and is written into `data/rejected.json` with `recheckAfter` 21 days away. That
is not a hypothetical: 788 of the 849 rows in the rejection ledger read "no dsh
install path".

## 5. Submit the registry entry

The registry is the JSON, not the README. The README is regenerated from it.

```sh
gh repo fork dshworks/awesome-dsh-plugins --clone
cd awesome-dsh-plugins
git checkout -b add-dsh-airlock
```

Append the object in [registry-entry.json](./registry-entry.json) to the
`plugins` array in `data/plugins.json`, dropping its `_comment` field, and set
the top-level `updated` to today.

```sh
node scripts/validate.mjs     # expect: validate: ok
node scripts/render.mjs       # regenerates README.md and lists/
git add data/plugins.json README.md lists/
git commit -m "Add dsh-airlock"
git push -u origin add-dsh-airlock
gh pr create --repo dshworks/awesome-dsh-plugins
```

CI runs the same two scripts.

### On the `status` field

The prepared entry says `verified`, which is only honest once step 3 has
happened. If you submit before publishing, change `status` to `unverified` and
drop the `npm` field. The registry's contributing guide is direct about this:
lying in `verified` gets the entry pulled.

`verifiedAgainst` is `0.1.0-rc.6` because that is the version `e2e/verify.sh`
actually ran against, with a control arm. It is not the version the source was
read at, and it is not a guess.

### The tags

`safety` and `observability`, which is the maximum of two the schema allows.
`safety` is the primary function. `observability` covers the evidence sinks.

## 6. Optional, and worth an afternoon

`dsh-otel` is not in the registry and carries no `dsh-plugin` topic, so no
discovery tool in this ecosystem can see it. Its three nearest competitors are
listed at two to four stars. The same two steps apply to it.

## What is deliberately not automated

Publishing is irreversible in practice: an npm name cannot be re-used, and a
registry PR is public. Every step above is one a human should run knowingly
rather than one an agent should perform on a schedule.
