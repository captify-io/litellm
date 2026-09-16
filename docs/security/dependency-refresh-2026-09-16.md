# Dependency security refresh, September 16, 2026

The lockfiles now select GitPython 3.1.62, MLflow 3.16.0, Next.js and eslint-config-next 16.3.3, patched js-yaml, sharp, smol-toml, browserslist, ws, form-data and protobufjs versions, and Go gRPC 1.83.2, x/crypto 0.55.0 and x/mod 0.40.0. The provider requires patched Go 1.26.8, which was used for its tests. JavaScript overrides preserve the existing major line where multiple major lines occur. The cookbook installs this fork's current 1.100.0 release

The optional Rust Bedrock client selects the AWS SDK default HTTPS client rather than its legacy TLS feature. This removes rustls 0.21 and rustls-webpki 0.101 from the dependency graph while retaining certificate verification with rustls 0.23 and webpki 0.103.13

The production Next.js build uses tsconfig.build.json with the same strict compiler options and includes every production source and generated route type. Test files have their own Vitest unit, component, integration and type suites. Existing test fixture TypeScript errors prevented the production build when the broad root tsconfig included them; production source had no reported errors. Type checking remains enabled. No test is removed from the test suites

## Verification

The dashboard production build passed. All 772 Vitest files and 9,217 tests passed, including the separate type-test project. Four npm lockfiles each report zero critical/high audit findings, with four moderate dashboard findings and one low finding in each other lockfile still open. Core Rust tests with Bedrock authentication passed 201 tests with one ignored test. Go provider tests and all three existing MLflow integration tests passed

A direct parser regression uses 100 empty-mapping merges and a maxTotalMergeKeys limit of five. js-yaml 4.3.1 accepts the payload, while 4.3.2 rejects it with `merge keys exceeded maxTotalMergeKeys (5)`

## Remaining evidence

The MLflow advisory GHSA-h7x2-h6g9-p789 lists versions through 3.15.2, but its unvalidated gateway destination still requires assessment in 3.16.0. Upgrading beyond an advisory's listed range is not proof of closure. MLflow is an optional integration and is absent from the production gateway image. Keep this source risk open until the destination validation and authorization behavior are verified

Final GitHub checks, immutable GitLab image scans, deployment, real gateway readiness and target application acceptance are required before runtime closure. Preserve the prior image and environment for rollback
