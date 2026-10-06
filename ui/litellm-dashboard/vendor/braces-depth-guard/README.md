# Vendored braces depth guard

This is a private, unpublished downstream derivation of `braces@3.0.3`, named `@captify-io/braces-depth-guard@3.0.3-captify.1`. It applies the six library changes from [upstream PR 78](https://github.com/micromatch/braces/pull/78) at commit `97308a01d091b211cf015314a2d0696da28a5392` to the exact published npm archive. It is not an upstream release or a claim that upstream has merged the repair

[GHSA-vfj7-8cjw-p6xm / CVE-2026-93687](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) describes call-stack exhaustion from deeply nested patterns. The parser now limits brace and parenthesis nesting, and compile, expand and stringify bound recursive `nodes` traversal. Normal nested patterns remain supported. Exceeding the fixed bound raises `SyntaxError`, including caller-supplied deeply nested or cyclic `nodes` ASTs

The source is based on npm 3.0.3, git commit `74b2db2938fad48a2ea54a9c8bf27a37a62c350d`. The original archive, exact patch, MIT license and before/after source hashes are retained here. `provenance.json` records the original identity, source URLs, advisory and downstream identity, and is also included inside the derived package. Unrelated changes on upstream master are excluded

## Rebuild and verify

Use the dashboard's supported Node 24/npm 11 toolchain and installed `tar` and `patch` commands. From `ui/litellm-dashboard`, run:

```sh
npm run vendor:braces
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
npm ci
npm run check:braces
npm run build
npm audit
```

`vendor:braces` verifies the original archive and patch hashes, applies the patch without fuzz, checks all six before/after hashes, preserves the MIT license and repacks deterministically. It needs no network request or package publication. `check:braces` reconstructs the archive in a temporary directory and requires byte equality, checks lockfile integrity and installed source, exercises the depth limit and compares normal patterns with the original source. It also verifies that unchanged source with only the downstream name/version substituted still fails the security regression, and that both Next's ESLint plugin and knip resolve the patched package through their real fast-glob dependencies

The local archive is a direct development dependency aliased as `braces`; the `$braces` override makes every transitive consumer use that same artifact. npm 11 resolves a standalone relative `file:` override against the transitive package in some existing lockfiles, so the direct dependency reference is intentional. The lockfile includes the actual downstream name, version, local path and SHA512 integrity. A clean install requires the checked-in archive, with registry dependencies available online or in npm's cache

The normal build and local dashboard checks explicitly run `check:braces`. This does not rely on an install lifecycle hook, which the project's `ignore-scripts=true` would disable. All four Docker UI builders copy the vendor directory before `npm ci` and provide `patch`; the resulting production image still serves the static UI export

## Scanner interpretation and maintenance

The OSV lockfile scan and full npm audit remain enabled with no added ignores or advisory suppression. Both tools identify the installed package by its downstream scoped name. They do not map that new identity back to the original braces advisory or certify that the patch fixes it. An unchanged archive with only its name changed also produces no matching advisory in these tools. Scanner exit codes alone therefore cannot establish closure; the retained source ancestry, reviewed six-file repair, deterministic artifact verification and required negative-control regressions provide the source evidence

Review the [upstream advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm), [issue 70](https://github.com/micromatch/braces/issues/70), [PR 78](https://github.com/micromatch/braces/pull/78) and new braces advisories whenever dependencies or this artifact change. The original package name/version in provenance must remain part of the dependency inventory and security review. New advisories against upstream braces require reviewing the inherited source even if the scoped package is not listed in scanner results

When upstream publishes a qualified fix, test it against these regressions and both consumers, remove the direct downstream dependency and use the exact upstream version in the override. Regenerate the lockfile, run the unchanged scanners and complete the clean install/build checks before removing this vendored repair. Do not replace the archive at the same version: a source change requires a new downstream version, provenance, integrity and review

## Scope and evidence

The independent source qualification used the original published suite (764 passing), then the same suite plus 14 upstream depth regressions (778 passing). On unchanged source those added regressions failed in 12 cases. An additional bounded probe checked 24 deep-string/direct-AST/`nodes`-cycle refusals and 3,150 ordinary-pattern comparisons against the original code. The required repository check retains the security cases, boundary/normal-pattern comparisons, rename-only negative control and actual-consumer resolution

This repair does not make arbitrary hostile JavaScript objects safe. A manually constructed cyclic `.parent` pointer can still loop in expand's queue lookup; ordinary parsed patterns cannot create that cycle because parent links point to the previously active container. Getters, unusual text values, output cardinality and regex behavior are also outside this patch. The advisory's ordinary deeply nested string path and the recursive public AST traversal are bounded

The affected dependency is used by build tooling through fast-glob/micromatch. Static-only production delivery reduces runtime reachability, but that fact is not counted as closing a source vulnerability. Installing this source candidate does not prove any managed gateway image has been rebuilt, scanned or deployed
