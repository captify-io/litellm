# Private runtime credential delivery

The deployment job publishes an encrypted, versioned runtime envelope in Secrets Manager and sends only its coordinates and this reviewed operator to SSM. Database passwords, environment values, registry tokens, and their base64 encodings do not enter Run Command parameters or job output

Configure each environment through its protected `DEV_DEPLOYMENT_CONFIG`, `STAGING_DEPLOYMENT_CONFIG`, or `PRODUCTION_DEPLOYMENT_CONFIG` file variable. Each contains `accountId`, `partition`, `region`, `deployRoleArn`, `secretArn`, `instanceId`, `expectedImageId`, `network`, `bindAddress`, `hostPort`, `containerPort`, and `healthPath`. All are strings. No account is built into the operator

The role and secret must match the selected account and partition, and the secret must match the region and `litellm/deployment-` purpose. Use the current Docker image ID for `expectedImageId`, the existing Docker network and ports, the existing loopback or RFC 1918 IPv4 address for the bind address, and `/health/readiness` for the health path. A different runtime layout requires a separately reviewed migration

Install `secret-delivery.yaml` with the selected host role, instance, publisher role, environment name, and a customer managed KMS key before enabling that environment's deployment job. Review the change set and verify its four secret/IAM resources. It creates no network resources. Key policy must permit the scoped IAM grants; an access denial requires the resource owner to correct the grant

Protect the release branch and the runtime file and password variables. Restrict each variable to its intended environment and disable expansion. Verify that the mirror can still update the protected release branch. Both CI debug tracing and the old password debugging option are refused

`ENV_FILE` contains literal, unique `KEY=value` entries without shell evaluation. The job's `DATABASE_PASSWORD` takes precedence over a stale file value. An unset `DATABASE_PASSWORD_READ_REPLICA` clears a stale replica override so LiteLLM uses its writer-password fallback. Use an explicit replica password when the reader has a different database identity

The target reads only the pinned `AWSCURRENT` version and verifies its account, instance, deployment, image, and expiry. The reader policy denies historical or unspecified stages and another instance using the same role. The publisher expires the current envelope after the command completes, using an ownership check so it cannot expire a concurrent publisher's version. Encrypted historical versions remain under the account's retention and access policies

The operator stages the candidate before stopping the running container, preserves launch settings and resource limits, and requires HTTP readiness with a connected database. It retains the previous container stopped with restart disabled, along with root-only recovery files. Failed readiness restores the prior container and runtime file. Database password rotation is a separate coordinated operation: restoring a container does not restore the database password

`DEPLOY_MODE=credentials` permits a same-image credential transition when `LITELLM_IMAGE` equals the reviewed image ID. Normal releases require the exact immutable digest from the image build and the existing security release gate. A changed image startup contract is refused before stopping the service

Qualify reader permissions, wrong-instance and historical-version denial, current image/port checks, and database readiness before a live credential transition. Keep deployment secrets under review for the account's rotation controls; expiring a delivery envelope does not establish automatic-rotation compliance

Focused regression checks:

```sh
python3 -m unittest discover -s tests/credential_delivery -v
```
