//! Local loopback proxy server, request masking, and streaming restoration.
//!
//! Defined per `docs/integrations/LOCAL_PROXY.md` and `docs/components/CONNECT.md`.

pub mod guard;
pub mod mask;
pub mod restore;
pub mod server;
pub mod sse;

pub use guard::{match_proxy_route, validate_request_headers, validate_token, ProxyRoute};
pub use mask::mask_request_body;
pub use restore::restore_response_body;
pub use server::{
    build_proxy_router, generate_proxy_token, validate_bind_address, ProxyConfig, ProxyState,
    MAX_BODY_LIMIT_BYTES,
};
pub use sse::{SseEvent, SseParser, StreamingRestorer};
