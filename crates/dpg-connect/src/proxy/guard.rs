//! HTTP guards for proxy request authentication, DNS rebinding, and CSRF protection.
//!
//! Defined per `docs/components/CONNECT.md` §11 and `docs/testing/SECURITY_TEST_CASES.md` (PX-01..PX-07).

use axum::http::{HeaderMap, StatusCode};
use subtle::ConstantTimeEq;

/// Validates security headers (Host, Origin, Sec-Fetch-Site).
/// Rejects potential DNS rebinding and cross-site browser requests.
pub fn validate_request_headers(headers: &HeaderMap, listen_port: u16) -> Result<(), StatusCode> {
    // 1. Host header validation (PX-03: DNS rebinding protection)
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let port_str = listen_port.to_string();
    let is_valid_host = host == "127.0.0.1"
        || host == "localhost"
        || host == format!("127.0.0.1:{port_str}")
        || host == format!("localhost:{port_str}");

    if !is_valid_host {
        return Err(StatusCode::FORBIDDEN);
    }

    // 2. Origin header validation (PX-04: Reject browser cross-origin requests)
    if headers.contains_key(axum::http::header::ORIGIN) {
        return Err(StatusCode::FORBIDDEN);
    }

    // 3. Sec-Fetch-Site validation (PX-05: Reject cross-site requests)
    if let Some(sec_fetch_site) = headers.get("sec-fetch-site") {
        if let Ok(site) = sec_fetch_site.to_str() {
            if site != "none" {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(())
}

/// Constant-time validation of the token URL path segment.
pub fn validate_token(candidate: &str, expected_token: &str) -> bool {
    let candidate_bytes = candidate.as_bytes();
    let expected_bytes = expected_token.as_bytes();

    if candidate_bytes.len() != expected_bytes.len() {
        return false;
    }

    candidate_bytes.ct_eq(expected_bytes).into()
}

/// Allowed upstream provider routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRoute {
    /// Anthropic `/v1/messages`
    AnthropicMessages,
    /// Anthropic `/v1/messages/count_tokens`
    AnthropicCountTokens,
    /// OpenAI `/v1/chat/completions`
    OpenAiChatCompletions,
}

impl ProxyRoute {
    /// Returns the target upstream path.
    pub fn upstream_path(&self) -> &'static str {
        match self {
            Self::AnthropicMessages => "/v1/messages",
            Self::AnthropicCountTokens => "/v1/messages/count_tokens",
            Self::OpenAiChatCompletions => "/v1/chat/completions",
        }
    }
}

/// Matches the remaining path after the token segment to an allowed proxy route.
pub fn match_proxy_route(remainder: &str) -> Option<ProxyRoute> {
    let normalized = remainder.trim_start_matches('/');
    match normalized {
        "anthropic/v1/messages" => Some(ProxyRoute::AnthropicMessages),
        "anthropic/v1/messages/count_tokens" => Some(ProxyRoute::AnthropicCountTokens),
        "openai/v1/chat/completions" => Some(ProxyRoute::OpenAiChatCompletions),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_sr_px_03_host_header_validation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("127.0.0.1:8787"),
        );
        assert!(validate_request_headers(&headers, 8787).is_ok());

        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("localhost:8787"),
        );
        assert!(validate_request_headers(&headers, 8787).is_ok());

        // DNS rebinding attack
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("evil.example:8787"),
        );
        assert_eq!(
            validate_request_headers(&headers, 8787),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn test_sr_px_04_and_px_05_origin_and_sec_fetch_site() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("127.0.0.1:8787"),
        );

        // Origin present -> 403
        headers.insert(
            axum::http::header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            validate_request_headers(&headers, 8787),
            Err(StatusCode::FORBIDDEN)
        );

        headers.remove(axum::http::header::ORIGIN);

        // Sec-Fetch-Site cross-site -> 403
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert_eq!(
            validate_request_headers(&headers, 8787),
            Err(StatusCode::FORBIDDEN)
        );

        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        assert!(validate_request_headers(&headers, 8787).is_ok());
    }

    #[test]
    fn test_sr_px_02_constant_time_token_validation() {
        let expected = "DPG_PROXY_SECRET_TOKEN_ABC12345";
        assert!(validate_token(expected, expected));
        assert!(!validate_token("wrong_token", expected));
        assert!(!validate_token("DPG_PROXY_SECRET_TOKEN_ABC12344", expected));
    }

    #[test]
    fn test_sr_px_06_route_matching() {
        assert_eq!(
            match_proxy_route("/anthropic/v1/messages"),
            Some(ProxyRoute::AnthropicMessages)
        );
        assert_eq!(
            match_proxy_route("/openai/v1/chat/completions"),
            Some(ProxyRoute::OpenAiChatCompletions)
        );
        assert_eq!(match_proxy_route("/anthropic/../../evil"), None);
        assert_eq!(match_proxy_route("/unknown/route"), None);
    }
}
