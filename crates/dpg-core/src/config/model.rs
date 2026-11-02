//! Configuration data structures for DPG.

use serde::{Deserialize, Serialize};

/// Action severity levels configured in policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionConfig {
    /// Allow the finding with no modification or warning.
    Allow = 0,
    /// Warn on the finding but allow content through.
    Warn = 1,
    /// Mask the finding with a placeholder token.
    Mask = 2,
    /// Block the content containing the finding entirely.
    Block = 3,
}

impl ActionConfig {
    /// Returns numerical severity (0 = Allow, 1 = Warn, 2 = Mask, 3 = Block).
    pub const fn severity(&self) -> u8 {
        *self as u8
    }
}

/// Policy action assignments for each finding category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Action for standard known secrets.
    #[serde(default = "default_mask")]
    pub known_secret: ActionConfig,
    /// Action for private keys.
    #[serde(default = "default_mask")]
    pub private_key: ActionConfig,
    /// Action for key-value secrets (e.g. `api_key = ...`).
    #[serde(default = "default_mask")]
    pub key_value_secret: ActionConfig,
    /// Action for connection strings with credentials.
    #[serde(default = "default_mask")]
    pub connection_string: ActionConfig,
    /// Action for custom project or global terms.
    #[serde(default = "default_mask")]
    pub custom_term: ActionConfig,
    /// Action for Indian identity numbers (Aadhaar, PAN, GSTIN).
    #[serde(default = "default_mask")]
    pub indian_id: ActionConfig,
    /// Action for personal identifiable information (emails, phone numbers).
    #[serde(default = "default_warn")]
    pub pii: ActionConfig,
    /// Action for Shannon high-entropy findings.
    #[serde(default = "default_warn")]
    pub entropy: ActionConfig,
    /// Action for known secrets detected in user prompts.
    #[serde(default = "default_block")]
    pub prompt_known_secret: ActionConfig,
    /// Action when placeholders are encountered in other tools (Bash, MCP, etc.).
    #[serde(default = "default_warn")]
    pub placeholder_in_other_tool: ActionConfig,
}

const fn default_mask() -> ActionConfig {
    ActionConfig::Mask
}

const fn default_warn() -> ActionConfig {
    ActionConfig::Warn
}

const fn default_block() -> ActionConfig {
    ActionConfig::Block
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            known_secret: ActionConfig::Mask,
            private_key: ActionConfig::Mask,
            key_value_secret: ActionConfig::Mask,
            connection_string: ActionConfig::Mask,
            custom_term: ActionConfig::Mask,
            indian_id: ActionConfig::Mask,
            pii: ActionConfig::Warn,
            entropy: ActionConfig::Warn,
            prompt_known_secret: ActionConfig::Block,
            placeholder_in_other_tool: ActionConfig::Warn,
        }
    }
}

/// Restoration rules and allowlists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreConfig {
    /// Tool names permitted to restore real values.
    #[serde(default = "default_restore_tools")]
    pub tools: Vec<String>,
    /// Path prefixes explicitly denied from restoration.
    #[serde(default = "default_deny_paths")]
    pub deny_paths: Vec<String>,
}

fn default_restore_tools() -> Vec<String> {
    vec!["Write".to_string(), "Edit".to_string()]
}

fn default_deny_paths() -> Vec<String> {
    vec![".git/".to_string()]
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            tools: default_restore_tools(),
            deny_paths: default_deny_paths(),
        }
    }
}

/// Mapping storage and encryption configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Backend used for encryption key (`keychain` or `file`).
    #[serde(default = "default_key_backend")]
    pub key_backend: String,
    /// Expiration period in days since last access.
    #[serde(default = "default_expiry_days")]
    pub expiry_days: u32,
}

fn default_key_backend() -> String {
    "keychain".to_string()
}

const fn default_expiry_days() -> u32 {
    30
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            key_backend: default_key_backend(),
            expiry_days: default_expiry_days(),
        }
    }
}

/// Hook execution timing and timeouts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Timeout in seconds configured for agent hooks.
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
    /// Ratio of hook timeout at which internal deadline triggers fail-closed response.
    #[serde(default = "default_internal_deadline_ratio")]
    pub internal_deadline_ratio: f64,
}

const fn default_hook_timeout() -> u64 {
    10
}

const fn default_internal_deadline_ratio() -> f64 {
    0.8
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_hook_timeout(),
            internal_deadline_ratio: default_internal_deadline_ratio(),
        }
    }
}

/// Local proxy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Loopback address to bind to.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Port number for the local proxy.
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    /// Maximum allowed request body size in bytes.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Upstream Anthropic API URL.
    #[serde(default = "default_upstream_anthropic")]
    pub upstream_anthropic: String,
    /// Upstream OpenAI API URL.
    #[serde(default = "default_upstream_openai")]
    pub upstream_openai: String,
    /// Whether to restore placeholders in text responses from model.
    #[serde(default = "default_true")]
    pub restore_in_responses: bool,
    /// Upstream connection timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    /// Upstream total request timeout in seconds.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

const fn default_proxy_port() -> u16 {
    8787
}

const fn default_max_body_bytes() -> usize {
    33_554_432 // 32 MiB
}

fn default_upstream_anthropic() -> String {
    "https://api.anthropic.com".to_string()
}

fn default_upstream_openai() -> String {
    "https://api.openai.com".to_string()
}

const fn default_true() -> bool {
    true
}

const fn default_connect_timeout() -> u64 {
    10
}

const fn default_request_timeout() -> u64 {
    600
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_proxy_port(),
            max_body_bytes: default_max_body_bytes(),
            upstream_anthropic: default_upstream_anthropic(),
            upstream_openai: default_upstream_openai(),
            restore_in_responses: default_true(),
            connect_timeout_seconds: default_connect_timeout(),
            request_timeout_seconds: default_request_timeout(),
        }
    }
}

/// Logging and audit event logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Logging level for stderr tracing output (`info`, `warn`, `debug`, etc.).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Whether metadata-only JSONL event logging is enabled.
    #[serde(default = "default_true")]
    pub events: bool,
    /// Maximum size of an event log file in bytes before rotation.
    #[serde(default = "default_max_log_bytes")]
    pub max_file_bytes: u64,
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_max_log_bytes() -> u64 {
    10_485_760 // 10 MiB
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            events: default_true(),
            max_file_bytes: default_max_log_bytes(),
        }
    }
}

/// Custom confidential terms to protect.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermsConfig {
    /// List of exact terms to protect.
    #[serde(default)]
    pub values: Vec<String>,
}

/// A custom regular expression detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRuleConfig {
    /// Unique identifier for the rule.
    pub id: String,
    /// Category name for findings from this rule.
    pub category: String,
    /// Regular expression pattern.
    pub regex: String,
}

/// Fully resolved and validated runtime configuration for DPG.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Policy configuration.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Restoration configuration.
    #[serde(default)]
    pub restore: RestoreConfig,
    /// Storage configuration.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Hook execution configuration.
    #[serde(default)]
    pub hook: HookConfig,
    /// Proxy configuration.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,
    /// Confidential terms.
    #[serde(default)]
    pub terms: TermsConfig,
    /// Custom detection rules.
    #[serde(default)]
    pub rules: Vec<CustomRuleConfig>,
}

/// Non-fatal warning emitted during configuration loading or merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Config key or section triggering the warning.
    pub key: String,
    /// Human-readable description of why the key was adjusted or ignored.
    pub message: String,
}

/// Non-sensitive diagnostic summary of active configuration (CF-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiagnostics {
    /// Active log level.
    pub log_level: String,
    /// Proxy bind address and port.
    pub proxy_endpoint: String,
    /// Number of configured terms (never the values).
    pub terms_count: usize,
    /// Number of configured custom rules.
    pub rules_count: usize,
    /// Storage key backend.
    pub storage_backend: String,
}

impl Config {
    /// Produces a non-sensitive diagnostic summary conforming to CF-02.
    pub fn diagnostics(&self) -> ConfigDiagnostics {
        ConfigDiagnostics {
            log_level: self.log.level.clone(),
            proxy_endpoint: format!("{}:{}", self.proxy.bind_address, self.proxy.port),
            terms_count: self.terms.values.len(),
            rules_count: self.rules.len(),
            storage_backend: self.storage.key_backend.clone(),
        }
    }
}
