# Database authentication

This fork runs stock upstream LiteLLM (v1.108.8 LTS); only the GitLab CI and the
`deploy/credential-delivery` tooling are our own, plus one code change:

- `litellm/proxy/proxy_server.py`, `ensure_spend_counter_initialized`: when the DB
  reseed returns nothing, the counter is raised to the cached base spend
  (`_repair_stale_spend_counter`) instead of incremented by it. Upstream's increment
  lets concurrent cold-cache requests each add the base spend, doubling a key's spend
  (seen on dev's docling key, fixed there by hand on 2026-11-04). Drop this once
  upstream fixes it.

## Current state (2026-11-14)

Every environment (dev, staging, tertiary, commercial) authenticates LiteLLM to
Postgres with a **password**: `LITELLM_DATABASE_PASSWORD` (CI variable, per
environment) is delivered as `DATABASE_PASSWORD`, and upstream assembles
`DATABASE_URL` from the discrete `DATABASE_*` settings, with TLS from
`DATABASE_SSLMODE`.

Password authentication is checked by Postgres alone: IAM policy does not gate the
login. Access rests on who can read the password (Secrets Manager / CI variable
permissions) and on the database security group.

## Open decision: RDS IAM for dev

Until 2026-11-14 dev logged in as `litellm_app_iam` with RDS IAM tokens minted
through a dedicated role (`DATABASE_AWS_ROLE_ARN`), so only principals allowed to
assume that role could connect, every token expired in 15 minutes, and logins were
attributable in CloudTrail. Upstream LiteLLM cannot assume a database-only role: it
reads `AWS_ROLE_NAME` / `AWS_ROLE_ARN`, which Bedrock also uses, and dev's host
role is the shared `EC2-Default-SSM-AD-Role`.

To return dev to IAM-only access, either carry the small `DATABASE_AWS_ROLE_ARN`
patch to `litellm/proxy/auth/rds_iam_token.py` on top of upstream, or give the
LiteLLM host a dedicated instance role allowed `rds-db:connect` as the database
user. `deploy/credential-delivery` still supports `databaseAuthentication`
`{"mode": "rds-iam", ...}` for that case.

## Switching a host from IAM to password

`target.py` refuses to drop IAM implicitly. A deploy switches only when the
environment file sets `IAM_TOKEN_DB_AUTH=False` and a password is delivered; it
then removes `DATABASE_AWS_ROLE_ARN`, `DATABASE_AWS_REGION_NAME`, `DATABASE_URL`
and `DATABASE_URL_READ_REPLICA` from the container so upstream rebuilds the URLs.
