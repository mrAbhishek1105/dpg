//! Axum loopback proxy server, upstream client, and request lifecycle management.
//!
//! Defined per `docs/components/CONNECT.md` §11 and `docs/testing/SECURITY_TEST_CASES.md` (PX-01..PX-13).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use dpg_core::context::{ProjectContext, RequestContext, SessionId};
use dpg_core::engine::Engine;
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::Route;
use dpg_protect::store::MappingStore;
use rand::RngCore;
use serde_json::Value;
use tower_http::limit::RequestBodyLimitLayer;

use crate::proxy::guard::{match_proxy_route, validate_request_headers, validate_token};
use crate::proxy::mask::mask_request_body;
use crate::proxy::restore::restore_response_body;
use crate::proxy::sse::SseStreamRestorer;

/// 32 MiB maximum request body limit (PX-07).
pub const MAX_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// Generates a new 32-byte Crockford base32 proxy authentication token.
pub fn generate_proxy_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        let idx = (b as usize) % dpg_protect::CROCKFORD_BASE32.len();
        s.push(dpg_protect::CROCKFORD_BASE32[idx] as char);
    }
    s
}

/// Runtime configuration for the local proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Bind address (MUST be 127.0.0.1; 0.0.0.0 is strictly refused per PX-01).
    pub bind_addr: SocketAddr,
    /// Upstream Anthropic API base URL (e.g. `https://api.anthropic.com`).
    pub upstream_anthropic: String,
    /// Upstream OpenAI API base URL (e.g. `https://api.openai.com`).
    pub upstream_openai: String,
    /// 32-byte secret token expected in the path segment `/t/<token>/...`.
    pub token: String,
    /// Whether to restore placeholders in model responses (default true).
    pub restore_in_responses: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8787)),
            upstream_anthropic: "https://api.anthropic.com".to_string(),
            upstream_openai: "https://api.openai.com".to_string(),
            token: generate_proxy_token(),
            restore_in_responses: true,
        }
    }
}

/// Shared proxy server state.
#[derive(Clone)]
pub struct ProxyState {
    /// Core DPG engine orchestrator.
    pub engine: Arc<Engine>,
    /// Backing mapping store for response restoration.
    pub store: Option<Arc<MappingStore>>,
    /// Active proxy configuration.
    pub config: Arc<ProxyConfig>,
    /// Upstream HTTP client.
    pub client: reqwest::Client,
    /// Project whose mappings this proxy uses (resolved from the launch directory).
    pub project: ProjectContext,
}

/// Builds the upstream HTTP client: bounded connect time and a per-read idle timeout
/// (no total timeout, so long streaming responses are not cut off).
pub fn build_upstream_client(
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<reqwest::Client, DpgError> {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .https_only(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Failed to build upstream HTTP client"),
        })
}

/// Validates that the bind address is strictly loopback (PX-01).
pub fn validate_bind_address(addr: &SocketAddr) -> Result<(), DpgError> {
    let ip = addr.ip();
    if !ip.is_loopback() {
        return Err(DpgError::Configuration {
            code: ErrorCode::C003,
            detail: SafeDetail::from_static(
                "Proxy must bind to 127.0.0.1 only; non-loopback addresses are refused",
            ),
        });
    }
    Ok(())
}

/// Builds the Axum application router with guards and body limits configured.
pub fn build_proxy_router(state: ProxyState) -> Router {
    Router::new()
        .route("/t/{token}/{*rest}", any(handle_proxy_request))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_LIMIT_BYTES))
        .with_state(state)
}

/// Main proxy request handler.
async fn handle_proxy_request(
    State(state): State<ProxyState>,
    Path((token, rest)): Path<(String, String)>,
    req: Request<Body>,
) -> Response<Body> {
    let listen_port = state.config.bind_addr.port();

    // 1. Validate security headers (Host, Origin, Sec-Fetch-Site)
    if let Err(status) = validate_request_headers(req.headers(), listen_port) {
        return status.into_response();
    }

    // 2. Constant-time token validation (PX-02)
    if !validate_token(&token, &state.config.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // 3. Match route allowlist (PX-06)
    let proxy_route = match match_proxy_route(&rest) {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // 4. Construct request context for masking
    let ctx = RequestContext {
        project: state.project.clone(),
        session: SessionId::new("proxy-session".to_string()),
        route: Route::Proxy,
        deadline: std::time::Instant::now() + Duration::from_secs(60),
    };

    // 5. Read and mask request body (PX-08, FC-08, FC-09)
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_BODY_LIMIT_BYTES).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(), // PX-07
    };

    let mut body_val: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(), // FC-09
    };

    if let Err(status) = mask_request_body(&state.engine, &ctx, &mut body_val) {
        return status.into_response(); // FC-08 (502 Bad Gateway)
    }

    let masked_bytes = match serde_json::to_vec(&body_val) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // 6. Forward to upstream provider
    let upstream_base = match proxy_route {
        crate::proxy::guard::ProxyRoute::AnthropicMessages
        | crate::proxy::guard::ProxyRoute::AnthropicCountTokens => &state.config.upstream_anthropic,
        crate::proxy::guard::ProxyRoute::OpenAiChatCompletions => &state.config.upstream_openai,
    };

    let upstream_url = format!(
        "{}{}",
        upstream_base.trim_end_matches('/'),
        proxy_route.upstream_path()
    );

    let upstream_req = state
        .client
        .request(parts.method, &upstream_url)
        .body(masked_bytes);

    // Forward allowed headers
    let upstream_req = copy_forward_headers(&parts.headers, upstream_req);

    // Upstream forwarding with timeout parity (PX-12, PX-13, H-07)
    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            if e.is_timeout() {
                return StatusCode::GATEWAY_TIMEOUT.into_response(); // PX-12
            }
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let resp_status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    // Pass through non-2xx responses verbatim (H-07)
    if !resp_status.is_success() {
        let err_bytes = upstream_resp.bytes().await.unwrap_or_default();
        return (
            resp_status,
            [(axum::http::header::CONTENT_TYPE, content_type)],
            err_bytes,
        )
            .into_response();
    }

    // 7a. Streaming (SSE): restore text deltas incrementally (PX-09, PX-10)
    if content_type.starts_with("text/event-stream") {
        let restorer = match (state.config.restore_in_responses, state.store.clone()) {
            (true, Some(store)) => Some(SseStreamRestorer::new(store, ctx.project.id.clone())),
            _ => None,
        };
        let stream = sse_body_stream(upstream_resp, restorer);
        return Response::builder()
            .status(resp_status)
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .header(axum::http::header::CACHE_CONTROL, "no-cache")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    // 7b. Non-streaming response placeholder restoration
    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    if state.config.restore_in_responses {
        if let Some(ref store) = state.store {
            if let Ok(mut resp_val) = serde_json::from_slice::<Value>(&resp_bytes) {
                restore_response_body(store, &ctx.project.id, &mut resp_val);
                if let Ok(restored_bytes) = serde_json::to_vec(&resp_val) {
                    return (
                        resp_status,
                        [(axum::http::header::CONTENT_TYPE, content_type)],
                        restored_bytes,
                    )
                        .into_response();
                }
            }
        }
    }

    (
        resp_status,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        resp_bytes,
    )
        .into_response()
}

/// Adapts the upstream byte stream through the SSE restorer (or verbatim without one).
fn sse_body_stream(
    upstream: reqwest::Response,
    restorer: Option<SseStreamRestorer>,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send {
    use futures_util::StreamExt;
    let bytes = upstream.bytes_stream();
    futures_util::stream::unfold(
        (bytes, restorer, false),
        |(mut bytes, mut restorer, done)| async move {
            if done {
                return None;
            }
            loop {
                match bytes.next().await {
                    Some(Ok(chunk)) => {
                        let out = match restorer.as_mut() {
                            Some(r) => r.push(&chunk),
                            None => chunk.to_vec(),
                        };
                        if !out.is_empty() {
                            return Some((Ok(bytes::Bytes::from(out)), (bytes, restorer, false)));
                        }
                    }
                    Some(Err(_)) => {
                        // Upstream broke mid-stream: end the response with an error.
                        return Some((
                            Err(std::io::Error::other("upstream stream error")),
                            (bytes, restorer, true),
                        ));
                    }
                    None => {
                        let tail = restorer.as_mut().map(|r| r.finish()).unwrap_or_default();
                        return Some((Ok(bytes::Bytes::from(tail)), (bytes, restorer, true)));
                    }
                }
            }
        },
    )
}

fn copy_forward_headers(src: &HeaderMap, dst: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let mut builder = dst;
    for (k, v) in src {
        let name = k.as_str();
        if name.starts_with("x-api-key")
            || name.starts_with("authorization")
            || name.starts_with("anthropic-")
            || name.starts_with("openai-")
            || name == "content-type"
        {
            if let Ok(val) = v.to_str() {
                builder = builder.header(name, val);
            }
        }
    }
    builder
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_core::context::ProjectId;

    #[test]
    fn test_sr_px_01_refuse_non_loopback_bind() {
        let non_loopback = "0.0.0.0:8787".parse().unwrap();
        let err = validate_bind_address(&non_loopback).expect_err("PX-01: Must refuse 0.0.0.0");
        assert_eq!(err.code(), ErrorCode::C003);

        let public_ip = "192.168.1.100:8787".parse().unwrap();
        assert!(validate_bind_address(&public_ip).is_err());

        let loopback = "127.0.0.1:8787".parse().unwrap();
        assert!(validate_bind_address(&loopback).is_ok());
    }

    #[test]
    fn test_token_generation_format() {
        let tok = generate_proxy_token();
        assert_eq!(tok.len(), 32);
        for c in tok.chars() {
            assert!(
                dpg_protect::CROCKFORD_BASE32.contains(&(c as u8)),
                "Token must use Crockford base32"
            );
        }
    }

    #[tokio::test]
    async fn test_h_08_mock_upstream_forwarding_and_masking() {
        use axum::routing::post;
        use axum::Json;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut rng = dpg_testgen::create_rng(999);
        let secret = dpg_testgen::gen_openai_token(&mut rng);

        let received_masked = Arc::new(AtomicBool::new(false));
        let received_masked_clone = received_masked.clone();

        // 1. Mock upstream server
        let mock_upstream = axum::Router::new().route(
            "/v1/messages",
            post(move |Json(body): Json<serde_json::Value>| {
                let rec = received_masked_clone.clone();
                async move {
                    let text = body["messages"][0]["content"].as_str().unwrap_or_default();
                    if text.starts_with("DPG_") && !text.contains("sk-") {
                        rec.store(true, Ordering::SeqCst);
                    }
                    Json(serde_json::json!({
                        "id": "msg_mock",
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Echo: {}", text)
                            }
                        ]
                    }))
                }
            }),
        );

        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let _ = axum::serve(upstream_listener, mock_upstream).await;
        });

        // 2. Set up DPG engine with ephemeral store
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("master.key");
        let key_prov = dpg_protect::key::FileKeyProvider::new(key_path);
        let store = Arc::new(
            dpg_protect::store::MappingStore::open(&tmp.path().join("map.db"), &key_prov).unwrap(),
        );

        let detector = Arc::new(dpg_detect::DpgDetector::new().unwrap());
        let policy = Arc::new(dpg_policy::DpgPolicy::default_policy());
        let protector = Arc::new(dpg_protect::DpgProtector::with_store(store.clone()));
        let restorer = Arc::new(dpg_restore::DpgRestorer::with_store(store.clone()));
        let config = Arc::new(dpg_core::config::Config::default());
        let engine = Arc::new(dpg_core::engine::Engine::new(
            detector, policy, protector, restorer, config, None,
        ));

        let token = "TOKEN123456789012345678901234567".to_string();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let proxy_config = Arc::new(ProxyConfig {
            bind_addr: proxy_addr,
            upstream_anthropic: format!("http://{}", upstream_addr),
            upstream_openai: format!("http://{}", upstream_addr),
            token: token.clone(),
            restore_in_responses: true,
        });

        let http_client = reqwest::Client::builder().build().unwrap();
        let state = ProxyState {
            engine,
            store: Some(store),
            config: proxy_config,
            client: http_client.clone(),
            project: ProjectContext {
                root: tmp.path().to_path_buf(),
                id: ProjectId::new("proxy-test".to_string()),
            },
        };

        let proxy_app = build_proxy_router(state);
        let proxy_server = tokio::spawn(async move {
            let _ = axum::serve(proxy_listener, proxy_app).await;
        });

        // 3. Client sends request to proxy with secret
        let proxy_url = format!("http://{}/t/{}/anthropic/v1/messages", proxy_addr, token);
        let req_payload = serde_json::json!({
            "model": "claude-3-opus-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": secret.clone()
                }
            ]
        });

        let resp = http_client
            .post(&proxy_url)
            .header("host", format!("{}", proxy_addr))
            .json(&req_payload)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            received_masked.load(Ordering::SeqCst),
            "Upstream must receive masked token, not secret"
        );

        let resp_json: serde_json::Value = resp.json().await.unwrap();
        let restored_text = resp_json["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            restored_text,
            format!("Echo: {}", secret),
            "Proxy response must restore original secret"
        );

        upstream_server.abort();
        proxy_server.abort();
    }

    #[tokio::test]
    async fn test_px_09_streaming_sse_masked_upstream_restored_downstream() {
        use axum::routing::post;
        use axum::Json;

        let mut rng = dpg_testgen::create_rng(4242);
        let secret = dpg_testgen::gen_openai_token(&mut rng);

        // Mock upstream: streams the (masked) user content back in 3-byte text deltas.
        let mock_upstream = axum::Router::new().route(
            "/v1/messages",
            post(move |Json(body): Json<serde_json::Value>| async move {
                let text = body["messages"][0]["content"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                assert!(!text.contains("sk-"), "upstream must never see the secret");
                let mut sse = String::from(
                    "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                );
                let chars: Vec<char> = text.chars().collect();
                for piece in chars.chunks(3) {
                    let piece: String = piece.iter().collect();
                    sse.push_str(&format!(
                        "event: content_block_delta\ndata: {}\n\n",
                        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":piece}})
                    ));
                }
                sse.push_str("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
                sse.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    sse,
                )
            }),
        );
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let _ = axum::serve(upstream_listener, mock_upstream).await;
        });

        let tmp = tempfile::tempdir().unwrap();
        let key_prov = dpg_protect::key::FixedKeyProvider::new([5u8; 32]);
        let store = Arc::new(
            dpg_protect::store::MappingStore::open(&tmp.path().join("map.db"), &key_prov).unwrap(),
        );
        let engine = Arc::new(dpg_core::engine::Engine::new(
            Arc::new(dpg_detect::DpgDetector::new().unwrap()),
            Arc::new(dpg_policy::DpgPolicy::default_policy()),
            Arc::new(dpg_protect::DpgProtector::with_store(store.clone())),
            Arc::new(dpg_restore::DpgRestorer::with_store(store.clone())),
            Arc::new(dpg_core::config::Config::default()),
            None,
        ));
        let token = "TOKEN765432109876543210987654321".to_string();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let state = ProxyState {
            engine,
            store: Some(store),
            config: Arc::new(ProxyConfig {
                bind_addr: proxy_addr,
                upstream_anthropic: format!("http://{}", upstream_addr),
                upstream_openai: format!("http://{}", upstream_addr),
                token: token.clone(),
                restore_in_responses: true,
            }),
            client: build_upstream_client(Duration::from_secs(5), Duration::from_secs(30)).unwrap(),
            project: ProjectContext {
                root: tmp.path().to_path_buf(),
                id: ProjectId::new("proxy-stream".to_string()),
            },
        };
        let proxy_server = tokio::spawn(async move {
            let _ = axum::serve(proxy_listener, build_proxy_router(state)).await;
        });

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{}/t/{}/anthropic/v1/messages",
                proxy_addr, token
            ))
            .json(&serde_json::json!({
                "model": "m", "stream": true,
                "messages": [{"role": "user", "content": secret.clone()}]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[reqwest::header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        let body = resp.text().await.unwrap();
        let mut text = String::new();
        let mut saw_stop_after_text = false;
        for block in body.split("\n\n").filter(|b| !b.trim().is_empty()) {
            let data = block
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .unwrap();
            let v: serde_json::Value = serde_json::from_str(data).unwrap();
            if let Some(t) = v["delta"]["text"].as_str() {
                assert!(!saw_stop_after_text, "no text after block stop");
                text.push_str(t);
            }
            if v["type"] == "content_block_stop" {
                saw_stop_after_text = true;
            }
        }
        assert_eq!(text, secret, "streamed text restored exactly");

        upstream_server.abort();
        proxy_server.abort();
    }
}
