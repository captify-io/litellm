#!/usr/bin/env ruby
# The normal gtcs analyzer is Ruby. Verify predecessor artifacts without Docker.
require 'json'
require 'digest'
require 'open3'
require 'time'

def check(value, message)
  raise message unless value
end

def canonical(value)
  case value
  when Hash then value.keys.sort.to_h { |key| [key, canonical(value[key])] }
  when Array then value.map { |item| canonical(item) }
  else value
  end
end

def digest(path)
  Digest::SHA256.file(path).hexdigest
end

# Preserve actual suppressed rows, and fail if VEX removes anything beyond the
# single repaired package/CVE. Neither scanner report is edited.
if ARGV.first == '--reports'
  check(ARGV.length == 4, 'expected raw report, filtered report, summary output')
  reports = ARGV[1, 2].map { |path| JSON.parse(File.read(path)) }
  maps = reports.map do |report|
    check(report.dig('scan', 'status') == 'success', 'unsuccessful scanner report')
    rows = report.fetch('vulnerabilities')
    check(rows.is_a?(Array), 'vulnerability array')
    pairs = rows.map do |row|
      check(row.is_a?(Hash) && row['id'].is_a?(String) && !row['id'].empty?, 'vulnerability identity')
      [row['id'], row]
    end
    check(pairs.map(&:first).uniq.length == pairs.length, 'duplicate vulnerability identity')
    pairs.to_h
  end
  raw, filtered = maps
  check((filtered.keys - raw.keys).empty?, 'scan inventory changed between passes')
  filtered.each { |id, row| check(row == raw[id], 'retained finding changed') }
  suppressed = (raw.keys - filtered.keys).map { |id| raw[id] }
  suppressed.each do |row|
    identifiers = row.fetch('identifiers')
    check(identifiers.any? { |id| id['type'] == 'cve' && id['value'] == 'CVE-2026-89032' }, 'unexpected suppressed CVE')
    check(row.dig('location', 'dependency', 'package', 'name') == 'litellm' &&
      row.dig('location', 'dependency', 'version') == '1.100.0', 'unexpected suppressed package')
  end
  File.write(ARGV[3], JSON.pretty_generate({ 'status' => 'PASS', 'rawSha256' => digest(ARGV[1]),
    'filteredSha256' => digest(ARGV[2]), 'suppressedCount' => suppressed.length,
    'suppressedFindings' => suppressed, 'retainedFindingCount' => filtered.length }) + "\n")
  puts "VEX report comparison PASS: #{suppressed.length} exact repaired findings suppressed; all others retained."
  exit
end

check(ARGV.length == 3, 'expected image, source revision, artifact directory')
image, revision, output = ARGV
check(revision.match?(/\A[a-f0-9]{40}\z/), 'source revision')
check(image.match?(/\A[a-z0-9][a-z0-9.\/:_-]*@sha256:[a-f0-9]{64}\z/), 'immutable registry image')
root = File.expand_path('..', __dir__)
head, status = Open3.capture2('git', '-C', root, 'rev-parse', 'HEAD')
check(status.success? && head.strip == revision, 'checkout revision')
changes, status = Open3.capture2('git', '-C', root, 'status', '--porcelain', '--untracked-files=no')
check(status.success? && changes.strip.empty?, 'tracked checkout changed')
files = %w[litellm/caching/caching.py litellm/proxy/litellm_pre_call_utils.py]
package = { 'name' => 'litellm', 'version' => '1.100.0' }
upstream = '16db51e2cfc28e02bd460481e634a8403ea9265e'
manifest_path = File.join(root, 'security/backports/CVE-2026-89032.json')
manifest = JSON.parse(File.read(manifest_path))
expected_manifest = { 'schemaVersion' => 1, 'cve' => 'CVE-2026-89032', 'package' => package,
  'upstreamCommit' => upstream, 'sourceSha256' => files.to_h { |name| [name, digest(File.join(root, name))] } }
check(manifest == expected_manifest, 'source/manifest drift')
proof = JSON.parse(File.read(File.join(output, 'proof.json')))
identity = proof.fetch('identity')
check(identity.fetch('imageId').match?(/\Asha256:[a-f0-9]{64}\z/), 'Docker config identity')
repository, manifest_digest = image.split('@', 2)
expected_identity = { 'image' => image, 'imageId' => identity['imageId'], 'sourceRevision' => revision,
  'product' => "pkg:oci/#{repository.split('/').last}@#{manifest_digest}", 'identityKind' => 'registry-manifest-digest' }
check(identity == expected_identity, 'artifact image/source binding')
expected_proof = { 'identity' => expected_identity, 'manifest' => manifest,
  'probe' => { 'status' => 'PASS', 'package' => package, 'sourceSha256' => manifest['sourceSha256'],
    'scopeCases' => 36, 'proxyCases' => 12 },
  'manifestSha256' => digest(manifest_path),
  'guardSha256' => digest(File.join(root, 'scripts/semantic_cache_backport.py')),
  'verifierSha256' => digest(__FILE__) }
check(proof == expected_proof, 'installed-image proof/guard binding')
binding = Digest::SHA256.hexdigest(JSON.generate(canonical(proof)))
doc = JSON.parse(File.read(File.join(output, 'fixed.vex.json')))
timestamp = doc.fetch('timestamp')
Time.iso8601(timestamp)
notes = "Verified upstream metadata-lookup backport #{upstream} plus HTTP bare user_api_key, root cache_key and nested litellm_params.preset_cache_key stripping; " \
  "package version unchanged. Source #{revision}; Docker config #{identity['imageId']}; exact installed source and 48 network-blocked behavior cases verified. Proof SHA256 #{binding}"
expected_vex = { '@context' => 'https://openvex.dev/ns/v0.2.0',
  '@id' => "https://github.com/captify-io/litellm/backports/#{binding}", 'author' => 'Captify',
  'role' => 'Document Creator', 'timestamp' => timestamp, 'version' => 1,
  'statements' => [{ 'vulnerability' => { 'name' => 'CVE-2026-89032' },
    'products' => [{ '@id' => identity['product'], 'subcomponents' => [{ '@id' => 'pkg:pypi/litellm@1.100.0' }] }],
    'status' => 'fixed', 'timestamp' => timestamp, 'status_notes' => notes }] }
check(doc == expected_vex, 'fixed VEX recomputation differs')
puts 'Immutable registry image/source/probe/VEX artifact binding PASS (in-image probe ran in predecessor job).'
