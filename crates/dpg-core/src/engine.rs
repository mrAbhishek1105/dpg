//! Core Engine orchestrator and component traits.
//!
//! Orchestrates `Detector` -> `PolicyEngine` -> `Protector`, and `Restorer` with deadline checks.
//! Defined per `docs/components/CORE.md` §7.

use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::context::RequestContext;
use crate::error::DpgError;
use crate::event::{Event, EventLog};
use crate::types::{Action, BlockItem, Decision, Finding, ProtectOutcome, Report, Span, WarnItem};

/// Restorer input describing a tool call with potential placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRequest {
    /// Name of the invoked tool (e.g. "Write", "Edit", "Bash").
    pub tool_name: String,
    /// Destination file path if tool targets a file.
    pub target_path: Option<PathBuf>,
    /// Tool input fields to restore (e.g. `[("content", "DPG_SECRET_...")]`).
    pub fields: Vec<(String, String)>,
}

/// Restorer output with restored real values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Whether the tool operation was permitted by restore guards.
    pub allowed: bool,
    /// Updated fields with real values restored where permitted.
    pub updated_fields: Vec<(String, String)>,
    /// Audit report of restored items.
    pub report: Report,
}

/// Abstract secret and confidential pattern detection trait.
pub trait Detector: Send + Sync {
    /// Scans text for sensitive patterns and returns findings.
    fn scan(&self, text: &str, ctx: &RequestContext) -> Result<Vec<Finding>, DpgError>;
}

/// Abstract policy decision engine trait.
pub trait PolicyEngine: Send + Sync {
    /// Resolves findings to security actions (`Allow`, `Warn`, `Mask`, `Block`).
    fn decide(
        &self,
        ctx: &RequestContext,
        text: &str,
        findings: &[Finding],
    ) -> Result<Vec<Decision>, DpgError>;
}

/// Abstract placeholder masking and mapping store persistence trait.
pub trait Protector: Send + Sync {
    /// Replaces masked findings with placeholders and persists mappings.
    fn apply(
        &self,
        ctx: &RequestContext,
        text: &str,
        findings: &[Finding],
        decisions: &[Decision],
    ) -> Result<(String, Report), DpgError>;
}

/// Abstract placeholder restoration trait.
pub trait Restorer: Send + Sync {
    /// Restores placeholders to real values according to tool allowlists and path guards.
    fn restore(
        &self,
        ctx: &RequestContext,
        req: RestoreRequest,
    ) -> Result<RestoreOutcome, DpgError>;
}

/// Central DPG engine orchestrator.
pub struct Engine {
    detector: Arc<dyn Detector>,
    policy: Arc<dyn PolicyEngine>,
    protector: Arc<dyn Protector>,
    restorer: Arc<dyn Restorer>,
    config: Arc<Config>,
    event_log: Option<Arc<EventLog>>,
}

impl Engine {
    /// Constructs a new Engine instance with concrete components injected.
    pub fn new(
        detector: Arc<dyn Detector>,
        policy: Arc<dyn PolicyEngine>,
        protector: Arc<dyn Protector>,
        restorer: Arc<dyn Restorer>,
        config: Arc<Config>,
        event_log: Option<Arc<EventLog>>,
    ) -> Self {
        Self {
            detector,
            policy,
            protector,
            restorer,
            config,
            event_log,
        }
    }

    /// Returns a reference to the active engine configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Orchestrates detection, policy evaluation, and protection with deadline enforcement.
    pub fn protect(&self, ctx: &RequestContext, text: &str) -> Result<ProtectOutcome, DpgError> {
        let start_time = std::time::Instant::now();

        // 1. Check deadline before detection
        ctx.check_deadline()?;

        // 2. Scan input
        let findings = self.detector.scan(text, ctx)?;

        // 3. Check deadline after detection
        ctx.check_deadline()?;

        // 4. Policy evaluation
        let decisions = self.policy.decide(ctx, text, &findings)?;

        // 5. If any decision is Block, short-circuit Protector
        let mut blocked_items = Vec::new();
        let mut warned_items = Vec::new();

        for decision in &decisions {
            if decision.finding < findings.len() {
                let finding = &findings[decision.finding];
                match decision.action {
                    Action::Block => {
                        blocked_items.push(BlockItem {
                            rule_id: finding.rule_id.clone(),
                            category: finding.category,
                            line_number: 1,
                            reason: decision.reason.clone(),
                        });
                    }
                    Action::Warn => {
                        warned_items.push(WarnItem {
                            rule_id: finding.rule_id.clone(),
                            category: finding.category,
                            line_number: 1,
                        });
                    }
                    _ => {}
                }
            }
        }

        if !blocked_items.is_empty() {
            let report = Report {
                masked: 0,
                warned: warned_items,
                blocked: blocked_items,
                degraded: false,
            };

            if let Some(ref log) = self.event_log {
                let ev = Event::new(
                    format!("{:?}", ctx.route),
                    ctx.project.id.as_str(),
                    ctx.session.as_str(),
                    "blocked",
                    report.blocked.len() as u32,
                    start_time.elapsed().as_millis() as u64,
                );
                let _ = log.record(&ev);
            }

            return Ok(ProtectOutcome::Blocked { report });
        }

        // 6. Check deadline before protector application
        ctx.check_deadline()?;

        // 7. Apply protector
        let (masked_text, mut report) = self.protector.apply(ctx, text, &findings, &decisions)?;
        report.warned.extend(warned_items);

        // 8. Event logging
        if let Some(ref log) = self.event_log {
            let ev = Event::new(
                format!("{:?}", ctx.route),
                ctx.project.id.as_str(),
                ctx.session.as_str(),
                "allowed",
                report.masked,
                start_time.elapsed().as_millis() as u64,
            );
            let _ = log.record(&ev);
        }

        Ok(ProtectOutcome::Allowed {
            text: masked_text,
            report,
        })
    }

    /// Orchestrates restore operations with deadline enforcement.
    pub fn restore(
        &self,
        ctx: &RequestContext,
        req: RestoreRequest,
    ) -> Result<RestoreOutcome, DpgError> {
        ctx.check_deadline()?;
        self.restorer.restore(ctx, req)
    }

    /// Scans text for DPG placeholder tokens (`DPG_SECRET_<BODY>`).
    pub fn find_placeholders<'a>(&self, text: &'a str) -> Vec<(Span, &'a str)> {
        const PREFIX: &str = "DPG_SECRET_";
        let mut results = Vec::new();
        let bytes = text.as_bytes();
        let prefix_len = PREFIX.len();

        let mut i = 0;
        while i + prefix_len <= bytes.len() {
            if &text[i..i + prefix_len] == PREFIX {
                let start = i;
                let mut end = i + prefix_len;

                while end < bytes.len() {
                    let b = bytes[end];
                    if b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' {
                        end += 1;
                    } else {
                        break;
                    }
                }

                // Placeholder bodies must have non-empty alphanumeric body
                if end - start >= prefix_len + 4 {
                    let token = &text[start..end];
                    results.push((Span::new_raw(start, end), token));
                    i = end;
                    continue;
                }
            }
            i += 1;
        }

        results
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::context::{ProjectId, SessionId};
    use crate::error::ErrorCode;
    use crate::types::{Category, Confidence, Route, RuleId};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    // Fake detector for testing
    struct FakeDetector {
        fail_with: Option<ErrorCode>,
        findings: Vec<Finding>,
    }

    impl Detector for FakeDetector {
        fn scan(&self, _text: &str, _ctx: &RequestContext) -> Result<Vec<Finding>, DpgError> {
            if let Some(code) = self.fail_with {
                Err(DpgError::Detection {
                    code,
                    detail: crate::error::SafeDetail::from_static("forced test failure"),
                })
            } else {
                Ok(self.findings.clone())
            }
        }
    }

    // Fake policy engine for testing
    struct FakePolicyEngine {
        fail_with: Option<ErrorCode>,
        decisions: Vec<Decision>,
    }

    impl PolicyEngine for FakePolicyEngine {
        fn decide(
            &self,
            _ctx: &RequestContext,
            _text: &str,
            _findings: &[Finding],
        ) -> Result<Vec<Decision>, DpgError> {
            if let Some(code) = self.fail_with {
                Err(DpgError::Policy {
                    code,
                    detail: crate::error::SafeDetail::from_static("forced test failure"),
                })
            } else {
                Ok(self.decisions.clone())
            }
        }
    }

    // Fake protector for testing
    struct FakeProtector {
        called: AtomicBool,
        masked_output: String,
    }

    impl Protector for FakeProtector {
        fn apply(
            &self,
            _ctx: &RequestContext,
            _text: &str,
            _findings: &[Finding],
            _decisions: &[Decision],
        ) -> Result<(String, Report), DpgError> {
            self.called.store(true, Ordering::SeqCst);
            Ok((
                self.masked_output.clone(),
                Report {
                    masked: 1,
                    ..Default::default()
                },
            ))
        }
    }

    // Fake restorer for testing
    struct FakeRestorer;

    impl Restorer for FakeRestorer {
        fn restore(
            &self,
            _ctx: &RequestContext,
            req: RestoreRequest,
        ) -> Result<RestoreOutcome, DpgError> {
            Ok(RestoreOutcome {
                allowed: true,
                updated_fields: req.fields,
                report: Report::default(),
            })
        }
    }

    fn test_ctx(deadline_duration: Duration) -> RequestContext {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = dunce::canonicalize(temp.path()).expect("canonical");
        RequestContext {
            project: crate::context::ProjectContext {
                root,
                id: ProjectId::new("proj123".to_string()),
            },
            session: SessionId::new("sess123".to_string()),
            route: Route::HookPostToolUse,
            deadline: std::time::Instant::now() + deadline_duration,
        }
    }

    #[test]
    fn test_detector_fault_injection() {
        let detector = Arc::new(FakeDetector {
            fail_with: Some(ErrorCode::D002),
            findings: Vec::new(),
        });
        let policy = Arc::new(FakePolicyEngine {
            fail_with: None,
            decisions: Vec::new(),
        });
        let protector = Arc::new(FakeProtector {
            called: AtomicBool::new(false),
            masked_output: "masked".to_string(),
        });
        let restorer = Arc::new(FakeRestorer);

        let engine = Engine::new(
            detector,
            policy,
            protector,
            restorer,
            Arc::new(Config::default()),
            None,
        );

        let ctx = test_ctx(Duration::from_secs(10));
        let res = engine.protect(&ctx, "test content");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::D002);
    }

    #[test]
    fn test_deadline_overrun_returns_t001() {
        let detector = Arc::new(FakeDetector {
            fail_with: None,
            findings: Vec::new(),
        });
        let policy = Arc::new(FakePolicyEngine {
            fail_with: None,
            decisions: Vec::new(),
        });
        let protector = Arc::new(FakeProtector {
            called: AtomicBool::new(false),
            masked_output: "masked".to_string(),
        });
        let restorer = Arc::new(FakeRestorer);

        let engine = Engine::new(
            detector,
            policy,
            protector,
            restorer,
            Arc::new(Config::default()),
            None,
        );

        let mut ctx = test_ctx(Duration::from_secs(10));
        // Force deadline to past
        ctx.deadline = std::time::Instant::now() - Duration::from_millis(100);

        let res = engine.protect(&ctx, "test content");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().code(), ErrorCode::T001);
    }

    #[test]
    fn test_blocked_short_circuits_protector() {
        let finding = Finding {
            rule_id: RuleId::from_static("test.secret"),
            category: Category::KnownSecret,
            span: Span::new_raw(0, 10),
            parts: Vec::new(),
            confidence: Confidence::High,
        };

        let detector = Arc::new(FakeDetector {
            fail_with: None,
            findings: vec![finding],
        });

        let policy = Arc::new(FakePolicyEngine {
            fail_with: None,
            decisions: vec![Decision {
                finding: 0,
                action: Action::Block,
                rule_id: RuleId::from_static("test.secret"),
                reason: std::borrow::Cow::Borrowed("policy blocked"),
            }],
        });

        let protector = Arc::new(FakeProtector {
            called: AtomicBool::new(false),
            masked_output: "masked".to_string(),
        });
        let restorer = Arc::new(FakeRestorer);

        let engine = Engine::new(
            detector,
            policy,
            Arc::clone(&protector) as Arc<dyn Protector>,
            restorer,
            Arc::new(Config::default()),
            None,
        );

        let ctx = test_ctx(Duration::from_secs(10));
        let outcome = engine.protect(&ctx, "secret_key").expect("protect outcome");

        match outcome {
            ProtectOutcome::Blocked { report } => {
                assert_eq!(report.blocked.len(), 1);
            }
            _ => panic!("Expected Blocked outcome"),
        }

        // Verify Protector was NEVER invoked
        assert!(
            !protector.called.load(Ordering::SeqCst),
            "Protector must be short-circuited when blocked"
        );
    }

    #[test]
    fn test_find_placeholders() {
        let engine = Engine::new(
            Arc::new(FakeDetector {
                fail_with: None,
                findings: Vec::new(),
            }),
            Arc::new(FakePolicyEngine {
                fail_with: None,
                decisions: Vec::new(),
            }),
            Arc::new(FakeProtector {
                called: AtomicBool::new(false),
                masked_output: String::new(),
            }),
            Arc::new(FakeRestorer),
            Arc::new(Config::default()),
            None,
        );

        let text = "Token DPG_SECRET_7K2M9QXA and DPG_SECRET_ABC12345 in text";
        let placeholders = engine.find_placeholders(text);
        assert_eq!(placeholders.len(), 2);
        assert_eq!(placeholders[0].1, "DPG_SECRET_7K2M9QXA");
        assert_eq!(placeholders[1].1, "DPG_SECRET_ABC12345");
    }
}
