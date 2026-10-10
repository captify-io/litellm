use std::sync::OnceLock;
use std::time::Duration;

use crate::constants::{CHAT_COMPLETIONS_CONNECT_TIMEOUT_SECS, CHAT_COMPLETIONS_TIMEOUT_SECS};

use crate::error::{CoreError, CoreResult};

pub(super) fn http_client(url: &reqwest::Url) -> CoreResult<&'static reqwest::Client> {
    static CLIENT: OnceLock<Result<reqwest::Client, reqwest::Error>> = OnceLock::new();
    static LOOPBACK_CLIENT: OnceLock<Result<reqwest::Client, reqwest::Error>> = OnceLock::new();
    let https_only = url.scheme() == "https";
    let client = if https_only {
        &CLIENT
    } else {
        &LOOPBACK_CLIENT
    };
    client
        .get_or_init(|| {
            reqwest::Client::builder()
                .https_only(https_only)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(CHAT_COMPLETIONS_TIMEOUT_SECS))
                .connect_timeout(Duration::from_secs(CHAT_COMPLETIONS_CONNECT_TIMEOUT_SECS))
                .build()
        })
        .as_ref()
        .map_err(|_| CoreError::Network("provider HTTP client initialization failed".to_string()))
}
