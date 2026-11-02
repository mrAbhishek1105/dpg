//! Server-Sent Events (SSE) parser and streaming placeholder restorer.
//!
//! Defined per `docs/components/CONNECT.md` §11 and `docs/testing/SECURITY_TEST_CASES.md` (PX-09, PX-10).

use dpg_core::context::ProjectId;
use dpg_protect::store::MappingStore;
use serde_json::Value;

use crate::proxy::restore::restore_text_placeholders;

/// A parsed Server-Sent Event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SseEvent {
    /// Optional event type name (from `event: <name>`).
    pub event: Option<String>,
    /// Accumulated event payload (from `data: <content>`).
    pub data: String,
    /// Optional event ID (from `id: <id>`).
    pub id: Option<String>,
}

/// Incremental SSE frame parser accumulating bytes and yielding completed events.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
}

impl SseParser {
    /// Constructs a new empty `SseParser`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a new chunk of raw SSE bytes and returns all complete events.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let chunk_str = String::from_utf8_lossy(chunk);
        self.buffer.push_str(&chunk_str);

        let mut events = Vec::new();

        // Events in SSE are delimited by double newlines (\n\n or \r\n\r\n)
        while let Some(pos) = find_event_boundary(&self.buffer) {
            let event_block = self.buffer[..pos].to_string();
            // Advance buffer past the delimiter
            let delimiter_len = if self.buffer[pos..].starts_with("\r\n\r\n") {
                4
            } else if self.buffer[pos..].starts_with("\n\n") {
                2
            } else {
                1
            };
            self.buffer.drain(..pos + delimiter_len);

            if let Some(event) = parse_sse_block(&event_block) {
                events.push(event);
            }
        }

        events
    }
}

fn find_event_boundary(s: &str) -> Option<usize> {
    if let Some(pos) = s.find("\r\n\r\n") {
        Some(pos)
    } else {
        s.find("\n\n")
    }
}

fn parse_sse_block(block: &str) -> Option<SseEvent> {
    let mut event_type = None;
    let mut data_lines = Vec::new();
    let mut event_id = None;

    for line in block.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            // Ignore empty lines and SSE comments
            continue;
        }

        if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.trim_start());
        } else if let Some(ev) = line.strip_prefix("event:") {
            event_type = Some(ev.trim().to_string());
        } else if let Some(id) = line.strip_prefix("id:") {
            event_id = Some(id.trim().to_string());
        }
    }

    if data_lines.is_empty() && event_type.is_none() {
        return None;
    }

    Some(SseEvent {
        event: event_type,
        data: data_lines.join("\n"),
        id: event_id,
    })
}

/// Streaming restorer that buffers potential trailing partial placeholder tokens
/// across chunk boundaries, ensuring complete restoration (PX-09).
pub struct StreamingRestorer<'a> {
    store: &'a MappingStore,
    project_id: &'a ProjectId,
    trailing_buffer: String,
}

impl<'a> StreamingRestorer<'a> {
    /// Constructs a new streaming restorer for the given store and project.
    pub fn new(store: &'a MappingStore, project_id: &'a ProjectId) -> Self {
        Self {
            store,
            project_id,
            trailing_buffer: String::new(),
        }
    }

    /// Processes an incoming event's JSON data, restoring text deltas while preserving
    /// partial placeholder tokens across chunks.
    pub fn process_event_data(&mut self, data: &str) -> String {
        let mut parsed: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return data.to_string(), // not JSON (e.g. [DONE]), return verbatim
        };

        // 1. Anthropic text delta: delta.text
        if let Some(delta) = parsed.get_mut("delta") {
            if let Some(text_val) = delta.get_mut("text") {
                if let Some(s) = text_val.as_str() {
                    let restored = self.process_streaming_text(s);
                    *text_val = Value::String(restored);
                }
            }
        }

        // 2. OpenAI text delta: choices[].delta.content
        if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                if let Some(delta) = choice.get_mut("delta") {
                    if let Some(content_val) = delta.get_mut("content") {
                        if let Some(s) = content_val.as_str() {
                            let restored = self.process_streaming_text(s);
                            *content_val = Value::String(restored);
                        }
                    }
                }
            }
        }

        serde_json::to_string(&parsed).unwrap_or_else(|_| data.to_string())
    }

    /// Restores text chunks while buffering trailing partial placeholder prefixes.
    pub fn process_streaming_text(&mut self, text: &str) -> String {
        let mut combined = std::mem::take(&mut self.trailing_buffer);
        combined.push_str(text);

        // Check if combined ends with a partial prefix of DPG_ (up to 19 bytes)
        let trailing_len = find_potential_placeholder_suffix_len(&combined);
        let (to_restore, trailing) = combined.split_at(combined.len() - trailing_len);

        self.trailing_buffer = trailing.to_string();
        let (restored, _) = restore_text_placeholders(self.store, self.project_id, to_restore);
        restored
    }

    /// Flushes any remaining bytes in the trailing buffer at stream completion.
    pub fn finish(mut self) -> String {
        if self.trailing_buffer.is_empty() {
            String::new()
        } else {
            let buffer = std::mem::take(&mut self.trailing_buffer);
            let (restored, _) = restore_text_placeholders(self.store, self.project_id, &buffer);
            restored
        }
    }
}

/// Identifies the length of a suffix that could be the start of a DPG placeholder.
/// Placeholders are up to 19 bytes matching `DPG_<CAT>_<BODY>`.
fn find_potential_placeholder_suffix_len(s: &str) -> usize {
    const MAX_PLACEHOLDER_LEN: usize = 19;
    const PREFIX: &str = "DPG_";

    let search_len = s.len().min(MAX_PLACEHOLDER_LEN);
    let suffix = &s[s.len() - search_len..];

    for idx in 0..suffix.len() {
        let candidate_suffix = &suffix[idx..];
        if PREFIX.starts_with(candidate_suffix) || candidate_suffix.starts_with(PREFIX) {
            // Potential placeholder prefix found at suffix[idx..]
            return candidate_suffix.len();
        }
    }

    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use dpg_protect::key::FixedKeyProvider;
    use dpg_protect::PlaceholderCat;

    #[test]
    fn test_sse_parser_split_chunks_and_crlf() {
        let mut parser = SseParser::new();

        // Push partial chunk 1
        let chunk1 = b"event: message\r\ndata: {\"text\": \"hello";
        let evs1 = parser.push_chunk(chunk1);
        assert!(evs1.is_empty());

        // Push partial chunk 2 completing the event
        let chunk2 = b" world\"}\r\n\r\n";
        let evs2 = parser.push_chunk(chunk2);
        assert_eq!(evs2.len(), 1);
        assert_eq!(evs2[0].event, Some("message".to_string()));
        assert_eq!(evs2[0].data, "{\"text\": \"hello world\"}");
    }

    #[test]
    fn test_sr_px_09_streaming_restore_split_at_every_byte_boundary() {
        let keys = FixedKeyProvider::new([77u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let project_id = ProjectId::new("proj-stream".to_string());

        let secret = "STREAMING_SECRET_DATA_XYZ";
        let ph = store
            .get_or_create(&project_id, secret, PlaceholderCat::Secret)
            .expect("insert mapping");

        let full_text = format!("Prefix text before [{ph}] and suffix text after.");

        // Split the full text at EVERY single byte index into two chunks
        for split_idx in 1..full_text.len() {
            let chunk1 = &full_text[..split_idx];
            let chunk2 = &full_text[split_idx..];

            let mut restorer = StreamingRestorer::new(&store, &project_id);
            let mut assembled = String::new();

            assembled.push_str(&restorer.process_streaming_text(chunk1));
            assembled.push_str(&restorer.process_streaming_text(chunk2));
            assembled.push_str(&restorer.finish());

            assert_eq!(
                assembled,
                format!("Prefix text before [{secret}] and suffix text after."),
                "PX-09: Must restore perfectly when split at byte index {split_idx}"
            );
        }
    }
}
