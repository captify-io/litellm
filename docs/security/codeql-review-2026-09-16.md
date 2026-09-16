# Credential and browser-boundary review

The final dependency image scan passes with zero critical/high findings. A separate CodeQL inventory exposed source-level findings, so that image remains undeployed while this source batch is verified

Adaptive-router demo pages keep API keys only in memory and clear the previous session-storage entry on page load. Chat session IDs use browser cryptographic random bytes, including on local HTTP demo origins. Actual browser connect/reload checks use a synthetic key and show persistence before this change and no persisted or restored key afterwards

Upload previews accept browser blob URLs. Stored plugin URLs remain visible as text, but only HTTP or HTTPS URLs without embedded credentials become links or pass form validation. Regression tests cover active-content URL schemes, embedded credentials and valid blob previews. The onboarding component requires a server-supplied ID for password invitations. Its SSO invitation caller now uses the existing uuid library, whose fallback uses crypto.getRandomValues on HTTP origins without crypto.randomUUID. No invitation path uses Math.random

Rust provider calls require HTTPS beyond literal IP loopback. Local adapters and existing local transport tests remain supported. Provider redirects are disabled, so an upstream response cannot forward authentication headers to another origin or downgrade the transport. TLS client construction fails closed. Tests reject remote HTTP, scheme confusion and embedded credentials, and an actual local socket test returns the redirect response without following its credential-sink destination. Existing provider transformation, streaming and Bedrock tests remain required

Credential-bearing diagnostic values were removed from Rust test assertion messages. This does not change provider request or response payloads. The dependency locks and model database are unchanged

Target preflight found seven configured model entries with no explicit custom api_base and no Rust rollout overrides. Public provider endpoint defaults use HTTPS. Actual provider completion and target readiness remain deployment acceptance requirements. Browser storage checks and local socket tests are scoped regression evidence, not a claim that a human completed target sign-in

This downstream fork releases from its existing main branch. The upstream staging-branch convention does not define this fork's GitLab deployment branch. Existing user authorization covers the maintenance and review; no independent reviewer or upstream maintainer action is asserted
