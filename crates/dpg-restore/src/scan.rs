//! Placeholder token scanner for incoming tool requests.

use std::sync::OnceLock;
use dpg_core::types::Span;
use dpg_protect::placeholder::PATTERN;
use regex::Regex;

static TOKEN_RE: OnceLock<Regex> = OnceLock::new();

fn get_token_re() -> &'static Regex {
    TOKEN_RE.get_or_init(|| {
        Regex::new(PATTERN).unwrap_or_else(|_| {
            let fallback = Regex::new(r"\bDPG_SECRET_[0-9A-Z]{8}\b");
            match fallback {
                Ok(r) => r,
                Err(_) => unreachable!(),
            }
        })
    })
}

/// A scanned placeholder occurrence in text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedToken<'a> {
    /// Byte span of the token in the scanned text.
    pub span: Span,
    /// The exact placeholder token string slice.
    pub token: &'a str,
}

/// Scans text and returns all exact-match placeholder tokens with their byte spans.
pub fn scan_tokens<'a>(text: &'a str) -> Vec<ScannedToken<'a>> {
    let re = get_token_re();
    let mut tokens = Vec::new();

    for mat in re.find_iter(text) {
        if let Ok(span) = Span::new(text, mat.start(), mat.end()) {
            tokens.push(ScannedToken {
                span,
                token: mat.as_str(),
            });
        }
    }

    tokens
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_scan_all_valid_categories() {
        let text = "Tokens: DPG_SECRET_ABCDEFGH DPG_PASS_23456789 DPG_USER_ABCDEF23 \
                    DPG_HOST_456789AB DPG_CONN_CDEF2345 DPG_TERM_6789ABCD \
                    DPG_ID_EF234567 DPG_PII_89ABCDEF";

        let tokens = scan_tokens(text);
        assert_eq!(tokens.len(), 8);
        assert_eq!(tokens[0].token, "DPG_SECRET_ABCDEFGH");
        assert_eq!(tokens[1].token, "DPG_PASS_23456789");
        assert_eq!(tokens[2].token, "DPG_USER_ABCDEF23");
        assert_eq!(tokens[3].token, "DPG_HOST_456789AB");
        assert_eq!(tokens[4].token, "DPG_CONN_CDEF2345");
        assert_eq!(tokens[5].token, "DPG_TERM_6789ABCD");
        assert_eq!(tokens[6].token, "DPG_ID_EF234567");
        assert_eq!(tokens[7].token, "DPG_PII_89ABCDEF");
    }

    #[test]
    fn test_sr_rg_06_altered_tokens_rejected() {
        // Test altered tokens:
        // 1. One character too long (9 chars)
        // 2. One character too short (7 chars)
        // 3. Ambiguous letters excluded by Crockford (I, L, O, U)
        // 4. Unknown category prefix
        // 5. Embedded in another identifier without word boundaries
        let text = "Invalid: DPG_SECRET_ABCDEFGHI \
                    DPG_SECRET_ABCDEFG \
                    DPG_SECRET_ABCDEFI1 \
                    DPG_SECRET_ABCDL123 \
                    DPG_SECRET_ABCDO123 \
                    DPG_SECRET_ABCDU123 \
                    DPG_UNKNOWN_ABCDEFGH \
                    PREFIX_DPG_SECRET_ABCDEFGH \
                    DPG_SECRET_ABCDEFGH_SUFFIX";

        let tokens = scan_tokens(text);
        assert!(
            tokens.is_empty(),
            "RG-06: Altered or invalid tokens must not match! Matched: {:?}",
            tokens.iter().map(|t| t.token).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_sr_rg_07_well_formed_tokens_detected() {
        // Well-formed tokens should be detected by the scanner, even if they are not yet looked up
        let text = "Content containing DPG_SECRET_89ABCDEF and DPG_PASS_ABCDEF23 in text.";
        let tokens = scan_tokens(text);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].token, "DPG_SECRET_89ABCDEF");
        assert_eq!(tokens[1].token, "DPG_PASS_ABCDEF23");
    }
}
