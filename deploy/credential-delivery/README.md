# Private runtime credential delivery

The deployment job publishes an encrypted, versioned runtime envelope in Secrets Manager and sends only its coordinates and this reviewed operator to SSM. Database passwords, environment values, registry tokens, and their base64 encodings do not enter Run Command parameters or job output

Configure each environment through its protected `DEV_DEPLOYMENT_CONFIG`, `STAGING_DEPLOYMENT_CONFIG`, or `PRODUCTION_DEPLOYMENT_CONFIG` file variable. Each contains `accountId`, `partition`, `region`, `deployRoleArn`, `secretArn`, `instanceId`, `expectedImageId`, `network`, `bindAddress`, `hostPort`, `containerPort`, and `healthPath`. All are strings. No account is built into the operator

The role and secret must match the selected account and partition, and the secret must match the region and `litellm/deployment-` purpose. Use the current Docker image ID for `expectedImageId`, the existing Docker network and ports, the existing loopback or RFC 1918 IPv4 address for the bind address, and `/health/readiness` for the health path. A different runtime layout requires a separately reviewed migration

Install `secret-delivery.yaml` with the selected host role, instance, publisher role, environment name, and a customer managed KMS key before enabling that environment's deployment job. Review the change set and verify its four secret/IAM resources. It creates no network resources. Key policy must permit the scoped IAM grants; an access denial requires the resource owner to correct the grant

Protect the release branch and the runtime file and password variables. Restrict each variable to its intended environment and disable expansion. Verify that the mirror can still update the protected release branch. Both CI debug tracing and the old password debugging option are refused

`ENV_FILE` contains literal, unique `KEY=value` entries without shell evaluation. The protected `LITELLM_DATABASE_PASSWORD` variable takes precedence over a stale file value. An unset `LITELLM_DATABASE_PASSWORD_READ_REPLICA` clears a stale replica override so LiteLLM uses its writer-password fallback. Use an explicit replica password when the reader has a different database identity

Remove the selected environment's legacy `DATABASE_PASSWORD` CI variable after encrypted recovery is prepared. Older deployment scripts then stop at their required-password check instead of deploying a stale password or sending the replacement through command history

The target reads only the pinned `AWSCURRENT` version and verifies its account, instance, deployment, image, and expiry. The reader policy denies historical or unspecified stages and another instance using the same role. The publisher expires the current envelope after the command completes, using an ownership check so it cannot expire a concurrent publisher's version. Encrypted historical versions remain under the account's retention and access policies

The operator stages the candidate before stopping the running container, preserves launch settings and resource limits, and requires HTTP readiness with a connected database. It retains the previous container stopped with restart disabled, along with root-only recovery files. Failed readiness restores the prior container and runtime file. Database password rotation is a separate coordinated operation: restoring a container does not restore the database password. A qualified maintenance operator can supply a dependency transition after staging and a dependency rollback before service recovery; ordinary CI supplies neither and never alters the database

The optional `runtimeMigration` field accepts `preserve` (the default) or `root-to-nonroot-v1`. The latter explicitly permits a release from the existing root image with `docker/prod_entrypoint.sh` to the qualified image with user `65534` and `/app/docker/prod_entrypoint.sh`. Both images must keep `/app` and the same default command. Host settings, ports, network attachment, application configuration and rollback remain preserved. Changed image environment defaults are adopted; conflicting application overrides stop the operation before interruption. The receipt separately records the changed startup contract and preserved host settings. After successful acceptance, update `expectedImageId` and remove `runtimeMigration` from the protected configuration. Another user, command, working directory or startup path requires a separately reviewed migration

`DEPLOY_MODE=credentials` permits a same-image credential transition when `LITELLM_IMAGE` equals the reviewed image ID. Normal releases require the exact immutable digest from the image build and the existing security release gate. A changed image startup contract is refused before stopping the service

Qualify reader permissions, wrong-instance and historical-version denial, current image/port checks, and database readiness before a live credential transition. Keep deployment secrets under review for the account's rotation controls; expiring a delivery envelope does not establish automatic-rotation compliance

Focused regression checks:

```sh
python3 -m unittest discover -s tests/credential_delivery -v
```

## Temporary AWS credentials for database authentication

The RDS token path carries the complete temporary credential: access key, secret key and session token. `AWS_SESSION_TOKEN` is preferred, with the SDK-compatible legacy `AWS_SECURITY_TOKEN` fallback. Explicit client credentials can supply `aws_session_token`, including an `os.environ/` reference, without inheriting an unrelated ambient token

Role and web-identity exchanges use the configured database region and client timeouts. This is required for partition-specific regional STS endpoints. Session tokens and signed database tokens must remain private

Use `DATABASE_AWS_ROLE_ARN` for a database-specific role, with an optional `DATABASE_AWS_ROLE_SESSION_NAME`. The existing `AWS_ROLE_NAME` setting is shared with other AWS integrations. See [database authentication](../../docs/runtime/database-authentication.md) for precedence and credential requirements. This source correction does not enable IAM database authentication, provision a database user or change existing runtime credentials. Native database access, renewal and application acceptance remain separate qualification steps

## Permanent IAM deployment binding

Set the optional `databaseAuthentication` object in the selected environment's protected configuration to `mode: rds-iam`, `username`, `roleArn`, `caPem` and `caSha256`. The role must belong to that selected account and partition. Platform provisions and authorizes the connection; this deployment consumes its reviewed coordinates. Account enrollment remains an application record, never a source-code list

Provide exactly one PEM CA certificate selected from current database certificate metadata and its SHA-256. Every candidate receives this public certificate as a root-owned, read-only regular file before the serving container is stopped. The operator reads it back and verifies the digest. Certificate staging failure removes the candidate and leaves the running service intact. Requalify certificate compatibility when the database CA changes

IAM mode does not require either database password CI variable. It removes discrete database passwords and password-bearing writer/reader URL authorities, keeps the selected endpoints and database names, normalizes both username aliases, and sets `DATABASE_AWS_ROLE_ARN` plus `DATABASE_AWS_REGION_NAME`. Provider role and region settings remain unchanged. Writer and reader URL options survive, with strict CA verification required. A configured `DIRECT_URL` is refused because independent migration-token renewal has not been qualified. Conflicting Azure authentication, endpoint changes and credential overrides require separate review

After IAM activation, password-mode deployment is refused even if a new environment file attempts to disable the IAM flag. An older publisher refuses the unknown configuration field. Keep this binding in future releases and retire stale protected password settings only after coordinated acceptance and recovery checks. A source test or deployment receipt does not prove actual automatic token renewal or close a rotation finding
