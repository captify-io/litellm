import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dashboard = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(join(dashboard, "package.json"));
const vendor = join(dashboard, "vendor/braces-depth-guard");
const provenance = JSON.parse(readFileSync(join(vendor, "provenance.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(dashboard, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(dashboard, "package-lock.json"), "utf8"));
const installed = dirname(require.resolve("braces/package.json"));
const artifactSpec = manifest.devDependencies.braces;
const integrity =
  "sha512-" +
  createHash("sha512")
    .update(readFileSync(join(dashboard, artifactSpec.slice(5))))
    .digest("base64");
assert.equal(manifest.overrides.braces, "$braces");
const locked = Object.entries(lock.packages).filter(([path]) => /(^|\/)node_modules\/braces$/.test(path));
assert.ok(locked.length > 0);
for (const [, entry] of locked) {
  assert.equal(entry.name, provenance.downstream.name);
  assert.equal(entry.version, provenance.downstream.version);
  assert.equal(entry.resolved, artifactSpec);
  assert.equal(entry.integrity, integrity);
}
for (const file of provenance.files) {
  const actual = createHash("sha256")
    .update(readFileSync(join(installed, file.path)))
    .digest("hex");
  assert.equal(actual, file.afterSha256, `installed source drift: ${file.path}`);
}

const cases = [
  ...["default", "parse", "compile", "expand", "stringify"].flatMap((operation) =>
    ["'{'.repeat(4000)+'a,b'+'}'.repeat(4000)", "'('.repeat(4000)+'a'+')'.repeat(4000)", "'{'.repeat(4000)+'a,b'"].map(
      (expression) => ({ operation, expression }),
    ),
  ),
  ...["compile", "expand", "stringify"].flatMap((operation) =>
    [
      "(()=>{let n={type:'root',nodes:[]};for(let i=0;i<4000;i++)n={type:'root',nodes:[n]};return n})()",
      "(()=>{const n={type:'root',nodes:[]};n.nodes=[n];return n})()",
      "(()=>{const a={type:'root',nodes:[]},b={type:'root',nodes:[a]};a.nodes=[b];return a})()",
    ].map((expression) => ({ operation, expression })),
  ),
];

function probe(modulePath, testCase) {
  const call = testCase.operation === "default" ? "braces" : `braces.${testCase.operation}`;
  const code = `const braces=require(${JSON.stringify(modulePath)});try{${call}(${testCase.expression});process.stdout.write(JSON.stringify({name:'accepted'}));}catch(e){process.stdout.write(JSON.stringify({name:e.name,message:e.message}));}`;
  const child = spawnSync(process.execPath, ["--stack_size=512", "-e", code], {
    encoding: "utf8",
    timeout: 3000,
    env: { ...process.env, NODE_PATH: join(dashboard, "node_modules") },
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout);
}

function assertGuard(result) {
  assert.equal(result.name, "SyntaxError");
  assert.match(result.message, /nesting depth exceeds/);
}

for (const testCase of cases) assertGuard(probe(installed, testCase));

const temporary = mkdtempSync(join(tmpdir(), "braces-regression-"));
try {
  execFileSync("tar", ["-xzf", join(vendor, "upstream-3.0.3.tgz"), "-C", temporary]);
  symlinkSync(join(dashboard, "node_modules"), join(temporary, "node_modules"), "dir");
  const baseline = join(temporary, "package");
  const original = JSON.parse(readFileSync(join(baseline, "package.json"), "utf8"));
  writeFileSync(join(baseline, "package.json"), JSON.stringify({ ...original, ...provenance.downstream }));
  const unchanged = probe(baseline, cases[0]);
  assert.equal(unchanged.name, "RangeError", "negative control must reproduce the original stack exhaustion");
  assert.throws(() => assertGuard(unchanged), assert.AssertionError, "renaming unchanged source must fail");
  const base = require(baseline);
  const fixed = require(installed);
  const patterns = ["src/**/*.{ts,tsx}", "a/{b,{c,d}}", "page-{1..3}.js", "a\\{b,c\\}", "${a,b}", '"{a,b}"'];
  for (const pattern of patterns) {
    for (const operation of ["compile", "expand", "stringify"]) {
      assert.deepEqual(fixed[operation](pattern), base[operation](pattern), `${operation}: ${pattern}`);
    }
  }
  const boundary = "{".repeat(99) + "x" + "}".repeat(99);
  assert.equal(fixed.stringify(boundary), boundary);
  for (const operation of ["compile", "expand", "stringify"]) {
    const ast = (depth) =>
      Array.from({ length: depth }).reduce((node) => ({ type: "root", nodes: [node] }), { type: "root", nodes: [] });
    assert.deepEqual(fixed[operation](ast(100)), operation === "expand" ? [] : "");
    assert.throws(() => fixed[operation](ast(101)), /nesting depth exceeds/);
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

for (const consumer of ["@next/eslint-plugin-next", "knip"]) {
  const consumerRequire = createRequire(require.resolve(consumer));
  const globRequire = createRequire(consumerRequire.resolve("fast-glob"));
  const matchRequire = createRequire(globRequire.resolve("micromatch"));
  assert.equal(dirname(matchRequire.resolve("braces/package.json")), installed, consumer);
  const glob = consumerRequire("fast-glob");
  const matches = glob.sync("src/**/*.{ts,tsx}", { cwd: dashboard });
  assert.ok(matches.length > 0, `${consumer} must glob actual dashboard source`);
  assert.ok(matches.includes("src/app/layout.tsx"));
}
process.stdout.write(
  `braces security check passed: ${cases.length} depth probes, compatibility, rename-only rejection, both consumers\n`,
);
