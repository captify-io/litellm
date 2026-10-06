import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dashboard = dirname(dirname(fileURLToPath(import.meta.url)));
const vendor = join(dashboard, "vendor/braces-depth-guard");
const provenanceText = readFileSync(join(vendor, "provenance.json"), "utf8");
const provenance = JSON.parse(provenanceText);
const artifact = "captify-io-braces-depth-guard-3.0.3-captify.1.tgz";
const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const upstream = join(vendor, "upstream-3.0.3.tgz");
const patch = join(vendor, "depth-guard.patch");
const temporary = mkdtempSync(join(tmpdir(), "braces-derive-"));

try {
  assert.ok(["--write", "--check"].includes(process.argv[2]), "Use --check or --write");
  assert.equal(sha256(upstream), provenance.upstream.sha256, "upstream archive changed");
  assert.equal(sha256(patch), provenance.patch.sha256, "reviewed patch changed");
  execFileSync("tar", ["-xzf", upstream, "-C", temporary]);
  const source = join(temporary, "package");
  for (const file of provenance.files) {
    assert.equal(sha256(join(source, file.path)), file.beforeSha256, file.path);
  }
  execFileSync("patch", ["--batch", "--fuzz=0", "-p1", "-i", patch], { cwd: source });
  for (const file of provenance.files) {
    assert.equal(sha256(join(source, file.path)), file.afterSha256, file.path);
  }
  const original = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  const derived = {
    ...original,
    ...provenance.downstream,
    private: true,
    description: "Downstream braces 3.0.3 with mandatory parser and AST depth guards",
    files: [...original.files, "CAPTIFY-PROVENANCE.json", "patches"],
  };
  writeFileSync(join(source, "package.json"), JSON.stringify(derived, null, 2) + "\n");
  writeFileSync(join(source, "CAPTIFY-PROVENANCE.json"), provenanceText);
  mkdirSync(join(source, "patches"));
  cpSync(patch, join(source, "patches/depth-guard.patch"));
  assert.deepEqual(readFileSync(join(source, "LICENSE")), readFileSync(join(vendor, "LICENSE")));
  const pack = execFileSync("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary], {
    cwd: source,
    encoding: "utf8",
  });
  assert.equal(JSON.parse(pack)[0].filename, artifact);
  if (process.argv[2] === "--write") {
    cpSync(join(temporary, artifact), join(vendor, artifact));
  } else {
    assert.deepEqual(
      readFileSync(join(temporary, artifact)),
      readFileSync(join(vendor, artifact)),
      "derived archive drift",
    );
  }
  process.stdout.write(`braces derivation verified: ${sha256(join(vendor, artifact))}\n`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
