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
    buffer: Vec<u8>,
}

impl SseParser {
    /// Constructs a new empty `SseParser`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a new chunk of raw SSE bytes and returns all complete events.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        // Buffer raw bytes and decode only complete events, so a multi-byte UTF-8
        // character split across chunks is never corrupted.
        self.buffer.extend_from_slice(chunk);

        let mut events = Vec::new();
        while let Some((pos, delimiter_len)) = find_block_end(&self.buffer) {
            let block: Vec<u8> = self.buffer.drain(..pos + delimiter_len).collect();
            let event_block = String::from_utf8_lossy(&block[..pos]);
            if let Some(event) = parse_sse_block(&event_block) {
                events.push(event);
            }
        }

        events
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
            data_lines.push(data.strip_prefix(' ').unwrap_or(data));
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
        holdback_restore(self.store, self.project_id, &mut self.trailing_buffer, text)
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
    const PREFIX: &str = "DPG_";

    let mut start = s.len().saturating_sub(MAX_PLACEHOLDER_LEN);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    let suffix = &s[start..];

    for (idx, _) in suffix.char_indices() {
        let candidate_suffix = &suffix[idx..];
        if PREFIX.starts_with(candidate_suffix) || candidate_suffix.starts_with(PREFIX) {
            // Potential placeholder prefix found at suffix[idx..]
            return candidate_suffix.len();
        }
    }

    0
}

/// Byte length of the longest placeholder (`DPG_SECRET_XXXXXXXX`).
const MAX_PLACEHOLDER_LEN: usize = 19;

/// Restores placeholders in `held + text`, keeping back any trailing bytes that could
/// be the start of a placeholder split across chunks. Returns the text to emit now.
fn holdback_restore(
    store: &MappingStore,
    project_id: &ProjectId,
    held: &mut String,
    text: &str,
) -> String {
    let mut combined = std::mem::take(held);
    combined.push_str(text);
    let trailing_len = find_potential_placeholder_suffix_len(&combined);
    let split = combined.len() - trailing_len;
    *held = combined[split..].to_string();
    let (restored, _) = restore_text_placeholders(store, project_id, &combined[..split]);
    restored
}

/// Where the text of a streamed delta lives.
#[derive(Debug, Clone)]
enum DeltaShape {
    /// Anthropic `content_block_delta` with `delta.type == "text_delta"`.
    Anthropic,
    /// OpenAI chat chunk `choices[i].delta.content`.
    OpenAi { choice: usize },
}

/// Per-stream hold-back state for one text block / choice.
struct HeldText {
    held: String,
    /// Event name and JSON of the last delta, reused to emit a flush delta.
    event: Option<String>,
    template: Value,
    shape: DeltaShape,
}

/// Owned SSE response transformer for the proxy: parses events on byte boundaries
/// (never splitting UTF-8), restores placeholders in **text** deltas only (PX-10:
/// tool-call arguments such as `input_json_delta` / `tool_calls` are never touched),
/// and holds back at most 19 bytes (the maximum placeholder length) per text stream (PX-09).
/// Held text is flushed as a synthetic text delta before any non-text event (e.g.
/// `content_block_stop`, `[DONE]`) so no text is lost or reordered across blocks.
pub struct SseStreamRestorer {
    store: std::sync::Arc<MappingStore>,
    project_id: ProjectId,
    raw: Vec<u8>,
    held: std::collections::BTreeMap<String, HeldText>,
}

impl SseStreamRestorer {
    /// Creates a restorer for one upstream response.
    pub fn new(store: std::sync::Arc<MappingStore>, project_id: ProjectId) -> Self {
        Self {
            store,
            project_id,
            raw: Vec::new(),
            held: std::collections::BTreeMap::new(),
        }
    }

    /// Feeds upstream bytes; returns the bytes to send downstream now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.raw.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((end, delim)) = find_block_end(&self.raw) {
            let block: Vec<u8> = self.raw.drain(..end + delim).collect();
            self.process_block(&block[..end], &block[end..], &mut out);
        }
        out
    }

    /// Flushes everything at end of stream (held text, then any incomplete event verbatim).
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush_all(&mut out);
        out.append(&mut self.raw);
        out
    }

    fn process_block(&mut self, block: &[u8], delim: &[u8], out: &mut Vec<u8>) {
        let text = String::from_utf8_lossy(block);
        let mut event_name: Option<String> = None;
        let mut data_lines: Vec<&str> = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(d) = line.strip_prefix("data:") {
                data_lines.push(d.strip_prefix(' ').unwrap_or(d));
            } else if let Some(e) = line.strip_prefix("event:") {
                event_name = Some(e.trim().to_string());
            }
        }

        let parsed: Option<Value> = if data_lines.is_empty() {
            None
        } else {
            serde_json::from_str(&data_lines.join("\n")).ok()
        };

        if let Some(mut json) = parsed {
            let texts = text_slots(&json);
            if !texts.is_empty() {
                for (key, shape) in texts {
                    let original = get_text(&json, &shape).unwrap_or_default();
                    let entry = self.held.entry(key).or_insert_with(|| HeldText {
                        held: String::new(),
                        event: None,
                        template: Value::Null,
                        shape: shape.clone(),
                    });
                    let emitted =
                        holdback_restore(&self.store, &self.project_id, &mut entry.held, &original);
                    entry.event = event_name.clone();
                    entry.template = json.clone();
                    entry.shape = shape.clone();
                    set_text(&mut json, &shape, emitted);
                }
                emit_event(out, event_name.as_deref(), &json);
                return;
            }
        }

        // Non-text event: flush held text first so ordering is preserved.
        self.flush_all(out);
        out.extend_from_slice(block);
        out.extend_from_slice(delim);
    }

    fn flush_all(&mut self, out: &mut Vec<u8>) {
        let held = std::mem::take(&mut self.held);
        for (_, h) in held {
            if h.held.is_empty() {
                continue;
            }
            let (restored, _) = restore_text_placeholders(&self.store, &self.project_id, &h.held);
            let mut json = flush_template(h.template, &h.shape);
            set_text(&mut json, &h.shape, restored);
            emit_event(out, h.event.as_deref(), &json);
        }
    }
}

fn find_block_end(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = buf.windows(2).position(|w| w == b"\n\n");
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(a), Some(b)) if b < a => Some((b, 4)),
        (Some(a), _) => Some((a, 2)),
        (None, Some(b)) => Some((b, 4)),
        (None, None) => None,
    }
}

fn text_slots(json: &Value) -> Vec<(String, DeltaShape)> {
    let mut slots = Vec::new();
    if json.get("type").and_then(Value::as_str) == Some("content_block_delta")
        && json.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta")
        && json.pointer("/delta/text").map(Value::is_string) == Some(true)
    {
        let idx = json.get("index").and_then(Value::as_u64).unwrap_or(0);
        slots.push((format!("a:{idx}"), DeltaShape::Anthropic));
    }
    if let Some(choices) = json.get("choices").and_then(Value::as_array) {
        for (i, c) in choices.iter().enumerate() {
            if c.pointer("/delta/content").map(Value::is_string) == Some(true) {
                let idx = c.get("index").and_then(Value::as_u64).unwrap_or(i as u64);
                slots.push((format!("o:{idx}"), DeltaShape::OpenAi { choice: i }));
            }
        }
    }
    slots
}

fn get_text(json: &Value, shape: &DeltaShape) -> Option<String> {
    match shape {
        DeltaShape::Anthropic => json.pointer("/delta/text"),
        DeltaShape::OpenAi { choice } => json
            .get("choices")
            .and_then(|c| c.get(*choice))
            .and_then(|c| c.pointer("/delta/content")),
    }
    .and_then(Value::as_str)
    .map(str::to_string)
}

fn set_text(json: &mut Value, shape: &DeltaShape, text: String) {
    let slot = match shape {
        DeltaShape::Anthropic => json.pointer_mut("/delta/text"),
        DeltaShape::OpenAi { choice } => json
            .get_mut("choices")
            .and_then(|c| c.get_mut(*choice))
            .and_then(|c| c.pointer_mut("/delta/content")),
    };
    if let Some(v) = slot {
        *v = Value::String(text);
    }
}

/// Builds a minimal delta event from the last text delta of the same stream.
fn flush_template(mut template: Value, shape: &DeltaShape) -> Value {
    if let DeltaShape::OpenAi { choice } = shape {
        if let Some(choices) = template.get_mut("choices").and_then(Value::as_array_mut) {
            let mut c = choices.get(*choice).cloned().unwrap_or(Value::Null);
            if let Some(obj) = c.as_object_mut() {
                obj.insert("finish_reason".to_string(), Value::Null);
            }
            if let Some(d) = c.get_mut("delta").and_then(Value::as_object_mut) {
                d.retain(|k, _| k == "content");
            }
            *choices = vec![c];
        }
    }
    template
}

fn emit_event(out: &mut Vec<u8>, event: Option<&str>, json: &Value) {
    if let Some(e) = event {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(e.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(json.to_string().as_bytes());
    out.extend_from_slice(b"\n\n");
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

    fn anthropic_stream(ph: &str) -> String {
        let ev = |name: &str, data: serde_json::Value| format!("event: {name}\ndata: {data}\n\n");
        let mut s = String::new();
        s += &ev("message_start", serde_json::json!({"type":"message_start"}));
        s += &ev(
            "content_block_start",
            serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        );
        s += &ev(
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":format!("Key is {}", &ph[..7])}}),
        );
        s += &ev(
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":format!("{} — ok ✓", &ph[7..])}}),
        );
        s += &ev(
            "content_block_stop",
            serde_json::json!({"type":"content_block_stop","index":0}),
        );
        s += &ev(
            "content_block_start",
            serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"Write","input":{}}}),
        );
        s += &ev(
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":format!("{{\"content\":\"{ph}\"}}")}}),
        );
        s += &ev(
            "content_block_stop",
            serde_json::json!({"type":"content_block_stop","index":1}),
        );
        s += &ev("message_stop", serde_json::json!({"type":"message_stop"}));
        s
    }

    /// Reassembles the text of block 0 and the tool JSON of block 1 from SSE output.
    fn collect(out: &str) -> (String, String, Vec<String>) {
        let mut text = String::new();
        let mut tool = String::new();
        let mut order = Vec::new();
        for block in out.split("\n\n").filter(|b| !b.trim().is_empty()) {
            let data = block
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .expect("data line");
            let v: Value = serde_json::from_str(data).expect("json");
            let ty = v["type"].as_str().unwrap_or_default().to_string();
            if ty == "content_block_delta" {
                if let Some(t) = v["delta"]["text"].as_str() {
                    text.push_str(t);
                }
                if let Some(t) = v["delta"]["partial_json"].as_str() {
                    tool.push_str(t);
                }
            }
            order.push(ty);
        }
        (text, tool, order)
    }

    #[test]
    fn test_sse_stream_restorer_every_split_text_restored_tool_args_untouched() {
        let keys = FixedKeyProvider::new([78u8; 32]);
        let store = std::sync::Arc::new(MappingStore::in_memory(&keys).expect("store"));
        let pid = ProjectId::new("proj-sse".to_string());
        let secret = "sk_live_stream_secret_42";
        let ph = store
            .get_or_create(&pid, secret, PlaceholderCat::Secret)
            .expect("insert");
        let input = anthropic_stream(&ph);
        let bytes = input.as_bytes();

        // Split the byte stream at every position (including inside multi-byte chars).
        for split in 1..bytes.len() {
            let mut r = SseStreamRestorer::new(store.clone(), pid.clone());
            let mut out = r.push(&bytes[..split]);
            out.extend(r.push(&bytes[split..]));
            out.extend(r.finish());
            let out = String::from_utf8(out).expect("valid utf-8 at split {split}");
            let (text, tool, order) = collect(&out);
            assert_eq!(text, format!("Key is {secret} — ok ✓"), "split {split}");
            assert_eq!(
                tool,
                format!("{{\"content\":\"{ph}\"}}"),
                "PX-10 at {split}"
            );
            let stop = order
                .iter()
                .position(|t| t == "content_block_stop")
                .expect("stop");
            let last_text = order
                .iter()
                .rposition(|t| t == "content_block_delta")
                .expect("delta");
            assert!(
                order[..stop]
                    .iter()
                    .filter(|t| *t == "content_block_delta")
                    .count()
                    >= 1
            );
            assert!(last_text > stop, "tool delta follows block 0 stop");
        }
    }

    #[test]
    fn test_sse_stream_restorer_openai_and_done() {
        let keys = FixedKeyProvider::new([79u8; 32]);
        let store = std::sync::Arc::new(MappingStore::in_memory(&keys).expect("store"));
        let pid = ProjectId::new("proj-oai".to_string());
        let secret = "oai_secret_value_777";
        let ph = store
            .get_or_create(&pid, secret, PlaceholderCat::Secret)
            .expect("insert");
        let chunk = |c: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":c},"finish_reason":null}]})
            )
        };
        let input = format!("{}{}data: [DONE]\n\n", chunk("value: "), chunk(&ph));
        let mut r = SseStreamRestorer::new(store.clone(), pid.clone());
        let mut out = r.push(input.as_bytes());
        out.extend(r.finish());
        let out = String::from_utf8(out).expect("utf8");
        assert!(out.contains(secret), "restored: {out}");
        assert!(!out.contains(&ph));
        assert!(
            out.trim_end().ends_with("data: [DONE]"),
            "DONE stays last: {out}"
        );
    }

    #[test]
    fn test_suffix_len_never_splits_utf8() {
        // Must not panic when the 19-byte window starts inside a multi-byte char.
        let s = "ééééééééééééééééééééDPG_SE";
        assert_eq!(find_potential_placeholder_suffix_len(s), 6);
        let s = "€€€€€€€€€€";
        assert_eq!(find_potential_placeholder_suffix_len(s), 0);
    }
}
