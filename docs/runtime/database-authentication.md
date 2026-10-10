# Database authentication

With `IAM_TOKEN_DB_AUTH=true`, the database connection signs RDS authentication tokens using the configured AWS credential source. Temporary credentials require `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. The SDK-compatible legacy `AWS_SECURITY_TOKEN` is a fallback when `AWS_SESSION_TOKEN` is absent or empty. Credentials and signed tokens must remain private

Set `DATABASE_AWS_ROLE_ARN` to use a role specifically for database connections. `DATABASE_AWS_ROLE_SESSION_NAME` sets its session name and defaults to `litellm-database`. This leaves the process environment and service role settings used by Bedrock and other integrations unchanged. Each token renewal obtains fresh role credentials

Without `DATABASE_AWS_ROLE_ARN`, the existing `AWS_ROLE_NAME` or `AWS_ROLE_ARN` and `AWS_SESSION_NAME` behavior remains. A database session name alone does not enable role assumption. Explicit client credentials can supply `aws_session_token`, including an `os.environ/` reference, without inheriting an unrelated ambient token

Role and web-identity exchanges use the selected database region and client timeouts. For web identity, the selected database role must trust the configured identity provider. These settings do not provision IAM permissions or database users. Verify access, certificate and hostname validation, token renewal, application behavior and rollback before changing a running workload

Writer startup, reader initialization and token renewal preserve each connection URL's TLS, certificate, pool and timeout settings when replacing its token. Configure the reader's own trust settings explicitly; a reader must not inherit the writer's certificate or identity merely because they share a proxy. This preserves configured verification and does not enable strict certificate validation for an unconfigured URL

`DATABASE_AWS_REGION_NAME` selects the database token region without changing `AWS_REGION_NAME` or other provider settings. When absent, existing AWS region resolution is preserved
