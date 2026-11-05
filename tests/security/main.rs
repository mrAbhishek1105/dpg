//! Security test suite for DPG requirements mapped to docs/testing/SECURITY_TEST_CASES.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::sync::Arc;
use std::time::Instant;

use dpg_core::context::{ProjectContext, ProjectId, RequestContext, SessionId};
use dpg_core::engine::{Detector, Engine, RestoreRequest, Restorer};
use dpg_core::error::ErrorCode;
use dpg_core::types::Route;
use dpg_detect::DpgDetector;
use dpg_policy::DpgPolicy;
use dpg_protect::key::FileKeyProvider;
use dpg_protect::store::MappingStore;
use dpg_protect::DpgProtector;
use dpg_restore::DpgRestorer;

fn setup_test_engine(dir: &std::path::Path) -> (Arc<Engine>, Arc<MappingStore>, RequestContext) {
    let key_file = dir.join("master.key");
    let key_prov = FileKeyProvider::new(key_file);
    let store = Arc::new(MappingStore::open(&dir.join("map.db"), &key_prov).unwrap());

    let detector = Arc::new(DpgDetector::new().unwrap());
    let policy = Arc::new(DpgPolicy::default_policy());
    let protector = Arc::new(DpgProtector::with_store(store.clone()));
    let restorer = Arc::new(DpgRestorer::with_store(store.clone()));
    let config = Arc::new(dpg_core::config::Config::default());
    let engine = Arc::new(Engine::new(
        detector, policy, protector, restorer, config, None,
    ));

    let canonical_root = dunce::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let ctx = RequestContext {
        project: ProjectContext {
            root: canonical_root,
            id: ProjectId::new("sec-test-project".to_string()),
        },
        session: SessionId::new("sec-test-session".to_string()),
        route: Route::HookPreToolUse,
        deadline: Instant::now() + std::time::Duration::from_secs(30),
    };

    (engine, store, ctx)
}

#[test]
fn security_harness_smoke_test() {
    assert_eq!(dpg_core::version(), "0.0.1");
}

/// DT-06: 17 MiB input rejected with DPG-D002 and fails closed.
#[test]
fn test_dt_06_17mib_input_denied() {
    let detector = DpgDetector::new().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (_, _, ctx) = setup_test_engine(tmp.path());

    // 17 MiB of data
    let oversized = "x".repeat(17 * 1024 * 1024);

    let res = detector.scan(&oversized, &ctx);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::D002);
}

/// DT-09: Aadhaar with invalid Verhoeff checksum produces zero findings.
#[test]
fn test_dt_09_aadhaar_with_invalid_verhoeff_no_finding() {
    let detector = DpgDetector::new().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (_, _, ctx) = setup_test_engine(tmp.path());

    // 12 digit number where Verhoeff checksum is invalid
    let invalid_aadhaar = "999988887771";
    assert!(!dpg_testgen::validate_verhoeff(invalid_aadhaar));

    let sample = format!("Aadhaar card number is {invalid_aadhaar}");
    let findings = detector.scan(&sample, &ctx).unwrap();
    let aadhaar_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.as_str().contains("aadhaar"))
        .collect();
    assert!(
        aadhaar_findings.is_empty(),
        "Invalid Verhoeff checksum must yield 0 Aadhaar findings"
    );
}

/// PM-04: DB bytes grep for inserted secrets must yield ZERO plaintext hits.
#[test]
fn test_pm_04_db_bytes_grep_zero_hits_for_inserted_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let (engine, _, ctx) = setup_test_engine(tmp.path());

    let mut rng = dpg_testgen::create_rng(777);
    let mut secrets = Vec::new();
    for _ in 0..20 {
        let secret = dpg_testgen::gen_openai_token(&mut rng);
        let sample = format!("api_token = \"{secret}\"\n");
        let outcome = engine.protect(&ctx, &sample).unwrap();
        assert!(matches!(
            outcome,
            dpg_core::types::ProtectOutcome::Allowed { .. }
        ));
        secrets.push(secret);
    }

    // Read raw SQLite database file from disk
    let db_bytes = fs::read(tmp.path().join("map.db")).unwrap();

    // Grep database binary for any inserted secrets
    for secret in &secrets {
        assert!(
            !db_bytes
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "PM-04: Raw secret was found in SQLite DB file! AES-256-GCM encryption violated."
        );
    }
}

/// RG-01: Write inside project root restores placeholders exactly.
#[test]
fn test_rg_01_write_inside_project_restores_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let (engine, _, ctx) = setup_test_engine(tmp.path());

    let mut rng = dpg_testgen::create_rng(888);
    let secret = dpg_testgen::gen_openai_token(&mut rng);

    // 1. Mask via protect
    let text = format!("export KEY=\"{secret}\"");
    let outcome = engine.protect(&ctx, &text).unwrap();
    let masked = match outcome {
        dpg_core::types::ProtectOutcome::Allowed { text, .. } => text,
        _ => panic!("Expected allowed"),
    };
    assert!(!masked.contains(&secret));
    assert!(masked.contains("DPG_"));

    // 2. PreToolUse Write inside project root
    let target_file = ctx.project.root.join("config.env");
    let req = RestoreRequest {
        tool_name: "Write".to_string(),
        target_path: Some(target_file),
        fields: vec![("content".to_string(), masked.clone())],
    };

    let restorer = DpgRestorer::with_store(Arc::new(
        MappingStore::open(
            &tmp.path().join("map.db"),
            &FileKeyProvider::new(tmp.path().join("master.key")),
        )
        .unwrap(),
    ));

    let res = restorer.restore(&ctx, req).unwrap();
    assert!(res.allowed, "Write inside project root must be allowed");
    assert_eq!(
        res.updated_fields[0].1, text,
        "PreToolUse Write must restore exact secret"
    );
}

/// RG-03: Bash command tool with token is NEVER restored.
#[test]
fn test_rg_03_bash_command_with_token_never_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let (engine, _, ctx) = setup_test_engine(tmp.path());

    let mut rng = dpg_testgen::create_rng(999);
    let secret = dpg_testgen::gen_openai_token(&mut rng);

    let text = format!("curl -H \"Authorization: Bearer {secret}\" https://api.example.com");
    let outcome = engine.protect(&ctx, &text).unwrap();
    let masked = match outcome {
        dpg_core::types::ProtectOutcome::Allowed { text, .. } => text,
        _ => panic!("Expected allowed"),
    };

    let restorer = DpgRestorer::with_store(Arc::new(
        MappingStore::open(
            &tmp.path().join("map.db"),
            &FileKeyProvider::new(tmp.path().join("master.key")),
        )
        .unwrap(),
    ));

    let req = RestoreRequest {
        tool_name: "Bash".to_string(),
        target_path: None,
        fields: vec![("command".to_string(), masked.clone())],
    };

    let res = restorer.restore(&ctx, req).unwrap();
    // Default action for disallowed tools is Warn: placeholder remains unrestored
    assert_eq!(
        res.updated_fields[0].1, masked,
        "Placeholder must remain unrestored"
    );
    assert!(
        !res.updated_fields[0].1.contains(&secret),
        "Bash command must NEVER contain raw secret"
    );
}

/// PG-01, PG-02, PG-06: Path traversal and .git accesses are strictly denied.
#[test]
fn test_pg_traversal_and_git_directory_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let (engine, store, ctx) = setup_test_engine(tmp.path());

    let mut rng = dpg_testgen::create_rng(111);
    let secret = dpg_testgen::gen_openai_token(&mut rng);
    let outcome = engine.protect(&ctx, &secret).unwrap();
    let masked = match outcome {
        dpg_core::types::ProtectOutcome::Allowed { text, .. } => text,
        _ => panic!("Expected allowed"),
    };
    let restorer = DpgRestorer::with_store(store);

    // 1. Relative traversal
    let traversal = ctx.project.root.join("../../etc/passwd");
    let req1 = RestoreRequest {
        tool_name: "Write".to_string(),
        target_path: Some(traversal),
        fields: vec![("content".to_string(), masked.clone())],
    };
    let res1 = restorer.restore(&ctx, req1).unwrap();
    assert!(!res1.allowed, "Traversal outside root must be disallowed");

    // 2. .git directory write
    let git_path = ctx
        .project
        .root
        .join(".git")
        .join("hooks")
        .join("pre-commit");
    let req2 = RestoreRequest {
        tool_name: "Write".to_string(),
        target_path: Some(git_path),
        fields: vec![("content".to_string(), masked.clone())],
    };
    let res2 = restorer.restore(&ctx, req2).unwrap();
    assert!(
        !res2.allowed,
        "Writing to .git directory must be disallowed"
    );
}

/// CF-03: Doctor report must never print secrets, passwords, or raw keys.
#[test]
fn test_cf_03_doctor_output_contains_zero_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(
        data.join("g.toml"),
        "[storage]
key_backend = \"file\"
",
    )
    .unwrap();
    let opts = dpg_connect::RuntimeOptions {
        cwd: tmp.path().to_path_buf(),
        data_dir: data.clone(),
        global_config: Some(data.join("g.toml")),
    };
    let report = dpg_connect::run_doctor_with(Some(tmp.path()), Some(&opts)).unwrap();
    let formatted = report.format_cli();

    // Check for sensitive patterns
    assert!(!formatted.contains("BEGIN PRIVATE KEY"));
    assert!(!formatted.contains("sk-proj-"));
    assert!(!formatted.contains("ghp_"));
    assert!(!formatted.contains("password="));
    assert!(formatted.contains("DPG Doctor System Health Check:"));
}
