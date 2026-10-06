# Semantic cache tenant isolation backport

[CVE-2026-89032](https://github.com/advisories/GHSA-237m-2qxv-ww7c) affects semantic cache identity partitioning on routes that carry authenticated identity in `litellm_metadata`, including Responses, Messages and Bedrock. The old scope reader only inspected `metadata`, so different virtual keys could select the same semantic bucket when their remaining request parameters matched

This change backports the metadata lookup from [upstream commit 16db51e2](https://github.com/BerriAI/litellm/commit/16db51e2cfc28e02bd460481e634a8403ea9265e). It reads both metadata containers at the top level and within `litellm_params`, retaining upstream precedence and the existing key, team and organization fields

The proxy also removes caller-supplied `user_api_key` before stamping authenticated identity. Its existing prefix check covered `user_api_key_*` but omitted this bare field. With the upstream lookup alone, a forged bare key in provider metadata could still win over the authenticated key in `litellm_metadata`. The added reserved field closes that path for dictionary and JSON-encoded metadata, including the requester metadata snapshot

At that same HTTP boundary, the proxy removes root `cache_key` and nested `litellm_params.preset_cache_key` values. Either client-supplied override could otherwise bypass the authenticated tenant scope. Trusted SDK and server-side cache-key overrides remain available after this boundary

The upstream commit also introduces an optional `semantic_cache_scope: end_user` setting and dashboard controls. That separate feature is not included here. Users sharing one key retain the existing key-scoped behavior; this backport does not claim isolation between those end users

The mapped cache tests check all three semantic backend scope paths, both metadata names and both nesting positions. They also pass requests through the real proxy identity stamping for Chat, Responses, Messages and Bedrock, including forged identity fields in both caller metadata containers and both HTTP cache-key override channels. Trusted direct overrides, exact-cache behavior and the existing shared-key behavior remain covered

The package still reports its actual upstream baseline, 1.100.0. A version-based image scanner can therefore continue reporting the advisory after this source repair. Source regression results alone are not a passed image scan or a deployed fix. The active GitHub and GitLab image checks use the reviewed exact-image OpenVEX process described in [image backport evidence](image-backport-evidence.md), retaining raw reports and normal release thresholds. No package-version substitution or general advisory ignore is used
