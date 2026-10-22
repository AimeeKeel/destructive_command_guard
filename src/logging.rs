//! Structured logging for allow/deny decisions.
//!
//! This module provides structured logging for command evaluation decisions,
//! supporting both text and JSON output formats with optional redaction.
//!
//! Full redaction replaces free-form diagnostics and runtime metadata as well
//! as commands before either format is serialized. Rule identities come from
//! built-in rules or configuration, not command captures, and remain useful
//! alongside decisions, timing, and other enum-derived metadata.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::evaluator::{EvaluationDecision, EvaluationResult};
use crate::packs::DecisionMode;

// ============================================================================
// Configuration Types
// ============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct LoggingConfig {
    /// Whether structured logging is enabled.
    pub enabled: bool,
    /// Path to log file. Supports ~ expansion.
    pub file: Option<String>,
    /// Output format: "text" or "json".
    pub format: LogFormat,
    /// Redaction settings.
    pub redaction: RedactionConfig,
    /// Events to log.
    pub events: LogEventFilter,
    /// Name of an environment variable whose value identifies the caller,
    /// recorded as `caller` on each entry (#378), e.g. `FLYWHEEL_AGENT_ID`.
    /// Opt-in. The value is a label only: it is sanitized, bounded, and never
    /// consulted by any decision.
    pub caller_env: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            file: None,
            format: LogFormat::Text,
            redaction: RedactionConfig::default(),
            events: LogEventFilter::default(),
            caller_env: None,
        }
    }
}

/// Longest caller label recorded, in characters.
const MAX_CALLER_CHARS: usize = 64;

/// The caller label from the configured environment variable, if set (#378).
///
/// Anyone who can set the variable controls it, so it is reduced to a short,
/// single-line label (printable ASCII only), fit for an audit record and
/// unable to forge log structure. Full redaction replaces this free-form value.
#[must_use]
pub fn caller_label(config: &LoggingConfig) -> Option<String> {
    let name = config.caller_env.as_deref()?;
    let label = sanitize_caller_label(&std::env::var(name).ok()?)?;
    Some(if config.redaction.is_full() {
        "[REDACTED]".to_string()
    } else {
        label
    })
}

/// Reduce a raw caller value to the label [`caller_label`] records.
fn sanitize_caller_label(raw: &str) -> Option<String> {
    let label: String = raw
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_CALLER_CHARS)
        .collect();
    let label = label.trim().to_string();
    (!label.is_empty()).then_some(label)
}

/// Log output format.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub mode: RedactionMode,
    pub max_argument_len: usize,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RedactionMode::Arguments,
            max_argument_len: 50,
        }
    }
}

impl RedactionConfig {
    /// Whether full-record suppression is active (mode alone is insufficient).
    pub(crate) const fn is_full(&self) -> bool {
        self.enabled && matches!(self.mode, RedactionMode::Full)
    }
}

/// Redaction mode.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum RedactionMode {
    None,
    #[default]
    Arguments,
    // Suppress command text, diagnostics, caller labels, audit paths and hashes.
    // Stable rule identifiers, decisions, timestamps and counters remain.
    Full,
}

/// Filter for which events to log.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct LogEventFilter {
    pub deny: bool,
    pub warn: bool,
    pub allow: bool,
}

impl Default for LogEventFilter {
    fn default() -> Self {
        Self {
            deny: true,
            warn: true,
            allow: false,
        }
    }
}

// ============================================================================
// Log Entry
// ============================================================================

/// A structured log entry for a command evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub decision: String,
    pub mode: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_skip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_layer: Option<String>,
    /// Caller label from `[logging] caller_env` (#378).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
}

impl LogEntry {
    /// Create a new log entry from an evaluation result.
    #[must_use]
    pub fn from_result(
        result: &EvaluationResult,
        command: &str,
        normalized: Option<&str>,
        mode: DecisionMode,
        redaction: &RedactionConfig,
        elapsed_us: Option<u64>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or_else(
                |_| "1970-01-01T00:00:00Z".to_string(),
                |d| time_to_iso8601(d.as_secs()),
            );

        let decision_str = match result.decision {
            EvaluationDecision::Allow => "allow",
            EvaluationDecision::Deny => match mode {
                DecisionMode::Deny => "deny",
                DecisionMode::Ask => "ask",
                DecisionMode::Warn => "warn",
                DecisionMode::Log => "log",
            },
            EvaluationDecision::Indeterminate => "indeterminate",
        };

        // No policy mode applies to an allowed command; report the outcome
        // itself rather than whichever placeholder the caller passed.
        let mode_str = match (result.decision, mode) {
            (EvaluationDecision::Allow, _) => "allow",
            (_, DecisionMode::Deny) => "deny",
            (_, DecisionMode::Ask) => "ask",
            (_, DecisionMode::Warn) => "warn",
            (_, DecisionMode::Log) => "log",
        };

        let (pack_id, pattern_name, rule_id, reason) =
            result
                .pattern_info
                .as_ref()
                .map_or((None, None, None, None), |pm| {
                    let pack = pm.pack_id.as_deref().map(String::from);
                    let pattern = pm.pattern_name.as_deref().map(String::from);
                    // Construct rule_id as "pack_id:pattern_name" if both are present
                    let rule = match (&pm.pack_id, &pm.pattern_name) {
                        (Some(p), Some(n)) => Some(format!("{p}:{n}")),
                        _ => None,
                    };
                    // Reasons may quote transformed command fragments (including
                    // lowercased pipeline producers). Substring replacement is
                    // insufficient: full mode must never copy diagnostic text.
                    let r = Some(redact_reason(&pm.reason, redaction));
                    (pack, pattern, rule, r)
                });

        let allowlist_layer = result
            .allowlist_override
            .as_ref()
            .map(|o| o.layer.label().to_string());

        let redacted_command = redact_command(command, redaction);
        let redacted_normalized = normalized.map(|n| redact_command(n, redaction));

        Self {
            timestamp,
            decision: decision_str.to_string(),
            mode: mode_str.to_string(),
            command: redacted_command,
            normalized_command: redacted_normalized,
            pack_id,
            pattern_name,
            rule_id,
            reason,
            elapsed_us,
            budget_skip: if result.skipped_due_to_budget {
                Some(true)
            } else {
                None
            },
            allowlist_layer,
            caller: None,
        }
    }

    /// Format as text log line.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        parts.push(format!("[{}]", self.timestamp));
        parts.push(self.decision.to_uppercase());
        if let Some(ref rule_id) = self.rule_id {
            parts.push(rule_id.clone());
        }
        parts.push(format!("\"{}\"", self.command));
        if let Some(ref reason) = self.reason {
            parts.push(format!("-- {reason}"));
        }
        if let Some(us) = self.elapsed_us {
            parts.push(format!("({us}us)"));
        }
        if self.budget_skip.unwrap_or(false) {
            parts.push("[budget-skip]".to_string());
        }
        if let Some(ref layer) = self.allowlist_layer {
            parts.push(format!("[allowlist:{layer}]"));
        }
        if let Some(ref caller) = self.caller {
            parts.push(format!("[caller:{caller}]"));
        }
        parts.join(" ")
    }

    /// Format as JSON line.
    #[must_use]
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================================
// Logger
// ============================================================================

/// A structured logger for command evaluation decisions.
pub struct DecisionLogger {
    config: LoggingConfig,
    writer: Option<Mutex<BufWriter<File>>>,
}

impl DecisionLogger {
    /// Create a new logger from configuration.
    #[must_use]
    pub fn new(config: &LoggingConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let writer = config.file.as_ref().and_then(|path| {
            let expanded = expand_tilde(path);
            open_log_file(&expanded)
                .ok()
                .map(|f| Mutex::new(BufWriter::new(f)))
        });
        Some(Self {
            config: config.clone(),
            writer,
        })
    }

    /// Log an evaluation result.
    pub fn log(
        &self,
        result: &EvaluationResult,
        command: &str,
        normalized: Option<&str>,
        mode: DecisionMode,
        elapsed_us: Option<u64>,
    ) {
        if !self.should_log(result, mode) {
            return;
        }
        let entry = LogEntry::from_result(
            result,
            command,
            normalized,
            mode,
            &self.config.redaction,
            elapsed_us,
        );
        let entry = LogEntry {
            caller: caller_label(&self.config),
            ..entry
        };
        let line = match self.config.format {
            LogFormat::Text => entry.format_text(),
            LogFormat::Json => entry.format_json(),
        };
        if let Some(ref writer) = self.writer {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
    }

    /// Determine if this result should be logged based on event filters.
    ///
    /// When a command matches a destructive pattern (Deny decision), we use the deny
    /// filter regardless of mode. Log mode means "don't block, just observe" - but
    /// the pattern still matched, so users who enable deny logging should see it.
    const fn should_log(&self, result: &EvaluationResult, mode: DecisionMode) -> bool {
        match result.decision {
            EvaluationDecision::Allow => self.config.events.allow,
            EvaluationDecision::Deny => match mode {
                DecisionMode::Warn => self.config.events.warn,
                // Ask remains security-relevant, and log mode still means a
                // destructive pattern matched. Use the deny filter for both.
                DecisionMode::Deny | DecisionMode::Ask | DecisionMode::Log => {
                    self.config.events.deny
                }
            },
            // There is no separate legacy event filter for evaluation
            // failures. Treat them as security-relevant deny events instead
            // of silently dropping the audit record.
            EvaluationDecision::Indeterminate => self.config.events.deny,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn expand_tilde(path: &str) -> String {
    // Expand a leading `~/` or `~\` using $HOME first (honored for test
    // isolation), then the platform home dir (USERPROFILE on Windows). On native
    // Windows `HOME` is normally unset, so the `config::home_dir()` fallback is what
    // keeps `~`-prefixed log paths from collapsing into a junk relative path.
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir_string() {
            return format!("{}/{}", home.trim_end_matches(['/', '\\']), rest);
        }
    } else if path == "~" {
        if let Some(home) = home_dir_string() {
            return home;
        }
    }
    path.to_string()
}

/// Resolve the user's home directory as a `String`, preferring `$HOME` (so tests
/// can override it for isolation) and falling back to the platform home
/// (`USERPROFILE` on Windows) via [`crate::config::home_dir`].
fn home_dir_string() -> Option<String> {
    if let Some(home) = std::env::var_os("HOME") {
        let s = home.to_string_lossy();
        if !s.is_empty() {
            return Some(s.into_owned());
        }
    }
    crate::config::home_dir().map(|p| p.to_string_lossy().into_owned())
}

fn open_log_file(path: &str) -> std::io::Result<File> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

pub(crate) fn redact_command(command: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return command.to_string();
    }
    match config.mode {
        RedactionMode::None => command.to_string(),
        RedactionMode::Full => "[REDACTED]".to_string(),
        RedactionMode::Arguments => redact_arguments(command, config.max_argument_len),
    }
}

/// Free-form metadata is not shell syntax. Argument truncation cannot safely
/// sanitize it; full mode replaces it wholesale, other modes preserve it.
pub(crate) fn redact_metadata(value: &str, config: &RedactionConfig) -> String {
    if config.is_full() {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

/// Retain a safe explanation without attempting to recognize every possible
/// transformation of a command fragment in evaluator or operator diagnostics.
pub(crate) fn redact_reason(reason: &str, config: &RedactionConfig) -> String {
    if config.is_full() {
        "Diagnostic details redacted.".to_string()
    } else {
        reason.to_string()
    }
}

fn redact_arguments(command: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(command.len());
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut arg_len = 0;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            if in_quote && arg_len < max_len {
                result.push(c);
                arg_len += 1;
            }
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            if !in_quote || arg_len < max_len {
                result.push(c);
                if in_quote {
                    arg_len += 1;
                }
            }
            continue;
        }
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            arg_len = 0;
            result.push(c);
            continue;
        }
        if in_quote && c == quote_char {
            in_quote = false;
            if arg_len > max_len {
                result.push_str("...");
            }
            result.push(c);
            continue;
        }
        if in_quote {
            if arg_len < max_len {
                result.push(c);
            }
            arg_len += 1;
        } else {
            result.push(c);
        }
    }
    result
}

fn time_to_iso8601(secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_YEAR: u64 = 365;
    const DAYS_PER_4YEARS: u64 = 1461;
    const DAYS_PER_100YEARS: u64 = 36524;
    const DAYS_PER_400YEARS: u64 = 146_097;

    let mut days = secs / SECS_PER_DAY;
    let time_of_day = secs % SECS_PER_DAY;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    days += 719_468;
    let era = days / DAYS_PER_400YEARS;
    let doe = days % DAYS_PER_400YEARS;
    let yoe = (doe - doe / DAYS_PER_4YEARS + doe / DAYS_PER_100YEARS - doe / DAYS_PER_400YEARS)
        / DAYS_PER_YEAR;
    let year = yoe + era * 400;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

// ============================================================================
// Pack Testing Logger
// ============================================================================

/// Log level for pack testing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackTestLogLevel {
    /// Only errors and failures.
    Error,
    /// Warnings and above.
    Warn,
    /// Standard output (default).
    #[default]
    Info,
    /// Detailed debugging output.
    Debug,
    /// Trace-level output (very verbose).
    Trace,
}

impl PackTestLogLevel {
    /// Check if this level should log at the given threshold.
    #[must_use]
    pub const fn should_log(&self, threshold: Self) -> bool {
        (*self as u8) >= (threshold as u8)
    }
}

/// Configuration for pack test logging.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PackTestLogConfig {
    /// Logging level.
    pub level: PackTestLogLevel,
    /// Output in JSON format instead of text.
    pub json_mode: bool,
    /// Show timing information.
    pub show_timing: bool,
    /// Show regex pattern details.
    pub show_patterns: bool,
}

/// A pattern match event for logging.
#[derive(Debug, Clone, Serialize)]
pub struct PatternMatchEvent {
    pub timestamp: String,
    pub pack: String,
    pub pattern: String,
    pub input: String,
    pub matched: bool,
    pub duration_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A test result event for logging.
#[derive(Debug, Clone, Serialize)]
pub struct TestResultEvent {
    pub timestamp: String,
    pub pack: String,
    pub test_name: String,
    pub passed: bool,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_matched: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Summary of a pack test run.
#[derive(Debug, Clone, Serialize)]
pub struct TestSummary {
    pub pack: String,
    pub timestamp: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub duration_ms: f64,
}

/// Full test report in structured JSON format.
#[derive(Debug, Clone, Serialize)]
pub struct PackTestReport {
    pub pack: String,
    pub timestamp: String,
    pub tests: Vec<TestResultEvent>,
    pub summary: TestSummaryCompact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_matches: Option<Vec<PatternMatchEvent>>,
}

/// Compact summary for inclusion in reports.
#[derive(Debug, Clone, Serialize)]
pub struct TestSummaryCompact {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

/// A structured logger for pack testing and debugging.
pub struct PackTestLogger {
    level: PackTestLogLevel,
    json_mode: bool,
    pack_name: String,
    show_timing: bool,
    show_patterns: bool,
    pattern_matches: Vec<PatternMatchEvent>,
    test_results: Vec<TestResultEvent>,
    start_time: std::time::Instant,
}

impl PackTestLogger {
    /// Create a new pack test logger.
    #[must_use]
    pub fn new(pack_name: &str, config: &PackTestLogConfig) -> Self {
        Self {
            level: config.level,
            json_mode: config.json_mode,
            pack_name: pack_name.to_string(),
            show_timing: config.show_timing,
            show_patterns: config.show_patterns,
            pattern_matches: Vec::new(),
            test_results: Vec::new(),
            start_time: std::time::Instant::now(),
        }
    }

    /// Create a logger with default configuration.
    #[must_use]
    pub fn default_for_pack(pack_name: &str) -> Self {
        Self::new(pack_name, &PackTestLogConfig::default())
    }

    /// Create a debug-mode logger with verbose output.
    #[must_use]
    pub fn debug_mode(pack_name: &str) -> Self {
        Self::new(
            pack_name,
            &PackTestLogConfig {
                level: PackTestLogLevel::Debug,
                json_mode: false,
                show_timing: true,
                show_patterns: true,
            },
        )
    }

    /// Log a pattern match attempt.
    pub fn log_pattern_match(
        &mut self,
        pattern: &str,
        input: &str,
        matched: bool,
        duration_us: u64,
    ) {
        self.log_pattern_match_detailed(pattern, input, matched, duration_us, None, None);
    }

    /// Log a pattern match with additional details.
    pub fn log_pattern_match_detailed(
        &mut self,
        pattern: &str,
        input: &str,
        matched: bool,
        duration_us: u64,
        severity: Option<&str>,
        reason: Option<&str>,
    ) {
        if !self.level.should_log(PackTestLogLevel::Debug) && !self.show_patterns {
            return;
        }

        let event = PatternMatchEvent {
            timestamp: current_iso8601(),
            pack: self.pack_name.clone(),
            pattern: pattern.to_string(),
            input: input.to_string(),
            matched,
            duration_us,
            severity: severity.map(String::from),
            reason: reason.map(String::from),
        };

        if self.json_mode {
            if let Ok(json) = serde_json::to_string(&event) {
                eprintln!("{json}");
            }
        } else if self.level.should_log(PackTestLogLevel::Debug) {
            let status = if matched { "MATCH" } else { "no-match" };
            let timing = if self.show_timing {
                format!(" ({duration_us}us)")
            } else {
                String::new()
            };
            eprintln!(
                "[DEBUG] {} | {} | {} | {}{}",
                self.pack_name, pattern, status, input, timing
            );
        }

        self.pattern_matches.push(event);
    }

    /// Log a test result.
    pub fn log_test_result(&mut self, test_name: &str, passed: bool, details: &str) {
        self.log_test_result_detailed(test_name, passed, details, None, None);
    }

    /// Log a test result with additional details.
    pub fn log_test_result_detailed(
        &mut self,
        test_name: &str,
        passed: bool,
        details: &str,
        pattern_matched: Option<&str>,
        input: Option<&str>,
    ) {
        let duration_ms = self.start_time.elapsed().as_secs_f64() * 1000.0;

        let event = TestResultEvent {
            timestamp: current_iso8601(),
            pack: self.pack_name.clone(),
            test_name: test_name.to_string(),
            passed,
            duration_ms,
            pattern_matched: pattern_matched.map(String::from),
            input: input.map(String::from),
            error: if passed {
                None
            } else {
                Some(details.to_string())
            },
        };

        if self.json_mode {
            if let Ok(json) = serde_json::to_string(&event) {
                eprintln!("{json}");
            }
        } else {
            let status = if passed { "PASS" } else { "FAIL" };
            let timing = if self.show_timing {
                format!(" ({duration_ms:.2}ms)")
            } else {
                String::new()
            };
            if passed {
                if self.level.should_log(PackTestLogLevel::Info) {
                    eprintln!("[{status}] {test_name}{timing}");
                }
            } else {
                eprintln!("[{status}] {test_name}{timing}: {details}");
            }
        }

        self.test_results.push(event);
    }

    /// Log a summary of test results.
    pub fn log_summary(&self, total: usize, passed: usize, failed: usize) {
        self.log_summary_detailed(total, passed, failed, 0);
    }

    /// Log a detailed summary of test results.
    pub fn log_summary_detailed(&self, total: usize, passed: usize, failed: usize, skipped: usize) {
        let duration_ms = self.start_time.elapsed().as_secs_f64() * 1000.0;

        let summary = TestSummary {
            pack: self.pack_name.clone(),
            timestamp: current_iso8601(),
            total,
            passed,
            failed,
            skipped,
            duration_ms,
        };

        if self.json_mode {
            if let Ok(json) = serde_json::to_string(&summary) {
                eprintln!("{json}");
            }
        } else {
            eprintln!();
            eprintln!("=== {} Test Summary ===", self.pack_name);
            eprintln!("  Total:   {total}");
            eprintln!("  Passed:  {passed}");
            eprintln!("  Failed:  {failed}");
            if skipped > 0 {
                eprintln!("  Skipped: {skipped}");
            }
            if self.show_timing {
                eprintln!("  Duration: {duration_ms:.2}ms");
            }
            eprintln!();
        }
    }

    /// Generate a full test report.
    #[must_use]
    pub fn generate_report(&self) -> PackTestReport {
        let passed = self.test_results.iter().filter(|r| r.passed).count();
        let failed = self.test_results.len() - passed;

        PackTestReport {
            pack: self.pack_name.clone(),
            timestamp: current_iso8601(),
            tests: self.test_results.clone(),
            summary: TestSummaryCompact {
                total: self.test_results.len(),
                passed,
                failed,
            },
            pattern_matches: if self.show_patterns {
                Some(self.pattern_matches.clone())
            } else {
                None
            },
        }
    }

    /// Output the report as JSON.
    #[must_use]
    pub fn report_json(&self) -> String {
        let report = self.generate_report();
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the number of pattern matches recorded.
    #[must_use]
    pub fn pattern_match_count(&self) -> usize {
        self.pattern_matches.len()
    }

    /// Get the number of test results recorded.
    #[must_use]
    pub fn test_result_count(&self) -> usize {
        self.test_results.len()
    }

    /// Reset the logger for a new test run.
    pub fn reset(&mut self) {
        self.pattern_matches.clear();
        self.test_results.clear();
        self.start_time = std::time::Instant::now();
    }
}

/// Get current time as ISO 8601 string.
fn current_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    time_to_iso8601(secs)
}

// ============================================================================
// Allow-Once Event Logging (git_safety_guard-oien.1.5)
// ============================================================================

/// Event types for allow-once audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowOnceEvent {
    /// Short code was issued (command blocked, pending exception created).
    Issued,
    /// Short code was redeemed (allow-once entry created).
    Granted,
    /// Allow-once entry was consumed (single-use entry used).
    Consumed,
    /// Record was pruned due to expiry.
    Expired,
}

impl AllowOnceEvent {
    /// Human-readable label for this event type.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Granted => "granted",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
}

/// A structured log entry for allow-once events.
/// Full redaction also suppresses command-derived hashes and short codes.
#[derive(Debug, Clone, Serialize)]
pub struct AllowOnceLogEntry {
    pub timestamp: String,
    pub event: AllowOnceEvent,
    pub short_code: String,
    pub full_hash: String,
    pub command: String,
    pub cwd: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_use: Option<bool>,
}

impl AllowOnceLogEntry {
    /// Create an entry for issuance (command blocked, pending exception created).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn issued(
        short_code: &str,
        full_hash: &str,
        command: &str,
        cwd: &str,
        expires_at: &str,
        reason: &str,
        single_use: bool,
        redaction: &RedactionConfig,
    ) -> Self {
        Self {
            timestamp: current_iso8601(),
            event: AllowOnceEvent::Issued,
            short_code: redact_metadata(short_code, redaction),
            full_hash: redact_metadata(full_hash, redaction),
            command: redact_command(command, redaction),
            cwd: redact_metadata(cwd, redaction),
            expires_at: expires_at.to_string(),
            scope_kind: None,
            scope_path: None,
            reason: Some(redact_reason(reason, redaction)),
            single_use: Some(single_use),
        }
    }

    /// Create an entry for grant (allow-once entry created from pending).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn granted(
        short_code: &str,
        full_hash: &str,
        command: &str,
        cwd: &str,
        expires_at: &str,
        scope_kind: &str,
        scope_path: &str,
        single_use: bool,
        redaction: &RedactionConfig,
    ) -> Self {
        Self {
            timestamp: current_iso8601(),
            event: AllowOnceEvent::Granted,
            short_code: redact_metadata(short_code, redaction),
            full_hash: redact_metadata(full_hash, redaction),
            command: redact_command(command, redaction),
            cwd: redact_metadata(cwd, redaction),
            expires_at: expires_at.to_string(),
            scope_kind: Some(if matches!(scope_kind, "cwd" | "project") {
                scope_kind.to_string()
            } else {
                redact_metadata(scope_kind, redaction)
            }),
            scope_path: Some(redact_metadata(scope_path, redaction)),
            reason: None,
            single_use: Some(single_use),
        }
    }

    /// Create an entry for consumption (single-use entry used).
    #[must_use]
    pub fn consumed(
        short_code: &str,
        full_hash: &str,
        command: &str,
        cwd: &str,
        redaction: &RedactionConfig,
    ) -> Self {
        Self {
            timestamp: current_iso8601(),
            event: AllowOnceEvent::Consumed,
            short_code: redact_metadata(short_code, redaction),
            full_hash: redact_metadata(full_hash, redaction),
            command: redact_command(command, redaction),
            cwd: redact_metadata(cwd, redaction),
            expires_at: String::new(),
            scope_kind: None,
            scope_path: None,
            reason: None,
            single_use: None,
        }
    }

    /// Create an entry for expiry (record pruned).
    #[must_use]
    pub fn expired(
        short_code: &str,
        full_hash: &str,
        expires_at: &str,
        redaction: &RedactionConfig,
    ) -> Self {
        Self {
            timestamp: current_iso8601(),
            event: AllowOnceEvent::Expired,
            short_code: redact_metadata(short_code, redaction),
            full_hash: redact_metadata(full_hash, redaction),
            command: String::new(),
            cwd: String::new(),
            expires_at: expires_at.to_string(),
            scope_kind: None,
            scope_path: None,
            reason: None,
            single_use: None,
        }
    }

    /// Format as text log line.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        parts.push(format!("[{}]", self.timestamp));
        parts.push(format!("[allow-once:{}]", self.event.label()));
        parts.push(format!("code={}", self.short_code));
        if !self.command.is_empty() {
            parts.push(format!("cmd=\"{}\"", self.command));
        }
        if !self.cwd.is_empty() {
            parts.push(format!("cwd=\"{}\"", self.cwd));
        }
        if let Some(ref scope) = self.scope_kind {
            parts.push(format!("scope={scope}"));
        }
        if !self.expires_at.is_empty() {
            parts.push(format!("expires={}", self.expires_at));
        }
        if let Some(ref reason) = self.reason {
            parts.push(format!("reason=\"{reason}\""));
        }
        parts.join(" ")
    }

    /// Format as JSON line.
    #[must_use]
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Log an allow-once event to a file.
///
/// Supports ~ expansion for paths. Creates parent directories if needed.
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or writing the log file.
pub fn log_allow_once_event(
    log_file: &str,
    entry: &AllowOnceLogEntry,
    format: LogFormat,
) -> std::io::Result<()> {
    let expanded = expand_tilde(log_file);
    let mut file = open_log_file(&expanded)?;

    let line = match format {
        LogFormat::Text => entry.format_text(),
        LogFormat::Json => entry.format_json(),
    };
    writeln!(file, "{line}")?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The caller label is attacker-settable text in an audit record (#378):
    /// single-line, printable, bounded, and absent when empty.
    #[test]
    fn caller_label_is_a_bounded_single_line_label_issue_378() {
        assert_eq!(
            sanitize_caller_label("agent-7 (swarm)").as_deref(),
            Some("agent-7 (swarm)")
        );
        assert_eq!(
            sanitize_caller_label("ok\n[DENY] forged\x1b[31m").as_deref(),
            Some("ok[DENY] forged[31m"),
            "newlines and control bytes cannot forge log structure"
        );
        assert_eq!(
            sanitize_caller_label(&"x".repeat(500)).map(|l| l.len()),
            Some(64)
        );
        assert_eq!(sanitize_caller_label("  \t\n "), None);

        let entry = LogEntry {
            caller: Some("agent-7".to_string()),
            ..LogEntry::from_result(
                &EvaluationResult::allowed(),
                "ls",
                None,
                DecisionMode::Deny,
                &RedactionConfig::default(),
                None,
            )
        };
        assert!(entry.format_text().ends_with("[caller:agent-7]"));
        assert!(entry.format_json().contains("\"caller\":\"agent-7\""));
        assert!(LoggingConfig::default().caller_env.is_none(), "opt-in");
    }

    #[test]
    fn logging_config_defaults() {
        let config = LoggingConfig::default();
        assert!(!config.enabled);
        assert!(config.file.is_none());
        assert_eq!(config.format, LogFormat::Text);
    }

    #[test]
    fn redact_full_mode() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn redact_disabled() {
        let config = RedactionConfig {
            enabled: false,
            mode: RedactionMode::Full,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "git reset --hard HEAD");
    }

    #[test]
    fn full_redaction_covers_complete_records_and_preserves_decisions() {
        let marker = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        let reason = format!("Unverified producer: {}", marker.to_lowercase());
        let result = EvaluationResult::denied_by_pack_pattern(
            "core.git",
            "reset-hard",
            &reason,
            None,
            crate::packs::Severity::High,
            &[],
        );
        for mode in [
            DecisionMode::Deny,
            DecisionMode::Warn,
            DecisionMode::Ask,
            DecisionMode::Log,
        ] {
            for enabled in [false, true] {
                for redaction_mode in [
                    RedactionMode::None,
                    RedactionMode::Arguments,
                    RedactionMode::Full,
                ] {
                    let config = RedactionConfig {
                        enabled,
                        mode: redaction_mode,
                        max_argument_len: 8,
                    };
                    let entry = LogEntry::from_result(
                        &result,
                        marker,
                        Some(&marker.to_lowercase()),
                        mode,
                        &config,
                        Some(42),
                    );
                    assert_eq!(entry.rule_id.as_deref(), Some("core.git:reset-hard"));
                    assert_eq!(entry.decision, format!("{mode:?}").to_lowercase());
                    for serialized in [entry.format_json(), entry.format_text()] {
                        assert_eq!(
                            serialized.to_lowercase().contains(&marker.to_lowercase()),
                            !(enabled && redaction_mode == RedactionMode::Full),
                            "{serialized}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn full_redaction_covers_complete_decision_records_issue_585() {
        let marker = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        let normalized_marker = "DCG_SYNTHETIC_NORMALIZED_ARGUMENT_2c7a";
        let reason = format!("unmodeled producer {:?}", marker.to_ascii_lowercase());
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            ..RedactionConfig::default()
        };
        let mut result = EvaluationResult::denied_by_pack_pattern(
            "heredoc.posix",
            "pipeline-consumer",
            &reason,
            Some(marker),
            crate::packs::Severity::Critical,
            &[],
        );

        for (decision, mode, expected, expected_mode) in [
            (
                EvaluationDecision::Allow,
                DecisionMode::Deny,
                "allow",
                "allow",
            ),
            (EvaluationDecision::Deny, DecisionMode::Deny, "deny", "deny"),
            (EvaluationDecision::Deny, DecisionMode::Ask, "ask", "ask"),
            (EvaluationDecision::Deny, DecisionMode::Warn, "warn", "warn"),
            (EvaluationDecision::Deny, DecisionMode::Log, "log", "log"),
            (
                EvaluationDecision::Indeterminate,
                DecisionMode::Deny,
                "indeterminate",
                "deny",
            ),
        ] {
            result.decision = decision;
            let entry = LogEntry::from_result(
                &result,
                marker,
                Some(normalized_marker),
                mode,
                &redaction,
                Some(123),
            );
            for serialized in [entry.format_json(), entry.format_text()] {
                let lowercase = serialized.to_ascii_lowercase();
                assert!(!lowercase.contains(&marker.to_ascii_lowercase()));
                assert!(!lowercase.contains(&normalized_marker.to_ascii_lowercase()));
                assert!(serialized.contains("heredoc.posix:pipeline-consumer"));
                assert!(serialized.contains("Diagnostic details redacted."));
            }
            let json: serde_json::Value = serde_json::from_str(&entry.format_json()).unwrap();
            assert_eq!(json["command"], "[REDACTED]");
            assert_eq!(json["normalized_command"], "[REDACTED]");
            assert_eq!(json["decision"], expected);
            assert_eq!(json["mode"], expected_mode);
            assert_eq!(json["pack_id"], "heredoc.posix");
            assert_eq!(json["pattern_name"], "pipeline-consumer");
            assert_eq!(json["elapsed_us"], 123);
            assert_eq!(result.decision, decision);
            assert_eq!(result.pattern_info.as_ref().unwrap().reason, reason);
        }
    }

    #[test]
    fn full_redaction_covers_allow_once_metadata() {
        let marker = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            max_argument_len: 8,
        };
        for entry in [
            AllowOnceLogEntry::issued(
                "abcd", "hash", marker, marker, "expiry", marker, true, &config,
            ),
            AllowOnceLogEntry::granted(
                "abcd", "hash", marker, marker, "expiry", "cwd", marker, true, &config,
            ),
            AllowOnceLogEntry::consumed("abcd", "hash", marker, marker, &config),
        ] {
            assert_eq!(entry.short_code, "[REDACTED]");
            assert_eq!(entry.full_hash, "[REDACTED]");
            for serialized in [entry.format_json(), entry.format_text()] {
                assert!(
                    !serialized.to_lowercase().contains(&marker.to_lowercase()),
                    "{serialized}"
                );
                assert!(!serialized.contains("abcd"));
            }
        }
    }

    #[test]
    fn non_full_redaction_preserves_diagnostic_details_issue_585() {
        let reason = "producer dcg_synthetic_private_argument_9b4e is unmodeled";
        let result = EvaluationResult::denied_by_legacy(reason);
        for (enabled, mode) in [
            (false, RedactionMode::Full),
            (true, RedactionMode::None),
            (true, RedactionMode::Arguments),
        ] {
            let redaction = RedactionConfig {
                enabled,
                mode,
                ..RedactionConfig::default()
            };
            let entry = LogEntry::from_result(
                &result,
                "producer | python -",
                None,
                DecisionMode::Deny,
                &redaction,
                None,
            );
            assert_eq!(entry.reason.as_deref(), Some(reason));
            assert!(entry.format_json().contains(reason));
            assert!(entry.format_text().contains(reason));
            assert_eq!(redact_metadata(reason, &redaction), reason);
        }
    }

    #[test]
    fn time_to_iso8601_epoch() {
        assert_eq!(time_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn time_to_iso8601_known_date() {
        // 2024-01-15 12:30:45 UTC = 1705321845 seconds since epoch
        let result = time_to_iso8601(1_705_321_845);
        assert_eq!(result, "2024-01-15T12:30:45Z");
    }

    #[test]
    fn redact_none_mode() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::None,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "git reset --hard HEAD");
    }

    #[test]
    fn redact_arguments_truncates_long_strings() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 10,
        };
        let result = redact_command(
            r#"echo "this is a very long string that should be truncated""#,
            &config,
        );
        assert_eq!(result, r#"echo "this is a ...""#);
    }

    #[test]
    fn redact_arguments_preserves_short_strings() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 50,
        };
        let result = redact_command(r#"echo "short""#, &config);
        assert_eq!(result, r#"echo "short""#);
    }

    #[test]
    fn expand_tilde_with_home() {
        if std::env::var_os("HOME").is_some() {
            let result = expand_tilde("~/test/path");
            assert!(!result.starts_with("~/"));
            assert!(result.ends_with("/test/path"));
        }
    }

    #[test]
    fn expand_tilde_without_tilde() {
        let result = expand_tilde("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }

    #[test]
    fn expand_tilde_backslash_form_and_bare_tilde() {
        // `~\` (Windows-style) must expand just like `~/`, and bare `~` resolves
        // to the home dir. Uses home_dir_string(), which falls back to
        // config::home_dir() (USERPROFILE on Windows) when $HOME is unset, so this
        // runs on any host.
        if home_dir_string().is_some() {
            let result = expand_tilde(r"~\test\path");
            assert!(!result.starts_with('~'));
            assert!(result.ends_with("/test\\path") || result.ends_with("/test/path"));

            let bare = expand_tilde("~");
            assert!(!bare.starts_with('~'));
            assert!(!bare.is_empty());
        }
    }

    #[test]
    fn log_event_filter_defaults() {
        let filter = LogEventFilter::default();
        assert!(filter.deny);
        assert!(filter.warn);
        assert!(!filter.allow);
    }

    // PackTestLogger tests

    #[test]
    fn pack_test_log_level_ordering() {
        assert!(PackTestLogLevel::Trace.should_log(PackTestLogLevel::Error));
        assert!(PackTestLogLevel::Debug.should_log(PackTestLogLevel::Info));
        assert!(PackTestLogLevel::Info.should_log(PackTestLogLevel::Info));
        assert!(!PackTestLogLevel::Error.should_log(PackTestLogLevel::Info));
    }

    #[test]
    fn pack_test_logger_creation() {
        let logger = PackTestLogger::default_for_pack("test.pack");
        assert_eq!(logger.pattern_match_count(), 0);
        assert_eq!(logger.test_result_count(), 0);
    }

    #[test]
    fn pack_test_logger_debug_mode() {
        let logger = PackTestLogger::debug_mode("test.pack");
        assert!(logger.show_timing);
        assert!(logger.show_patterns);
    }

    #[test]
    fn pack_test_logger_records_pattern_matches() {
        let config = PackTestLogConfig {
            level: PackTestLogLevel::Debug,
            show_patterns: true,
            ..Default::default()
        };
        let mut logger = PackTestLogger::new("test.pack", &config);

        logger.log_pattern_match("pattern1", "input1", true, 100);
        logger.log_pattern_match("pattern2", "input2", false, 50);

        assert_eq!(logger.pattern_match_count(), 2);
    }

    #[test]
    fn pack_test_logger_records_test_results() {
        let mut logger = PackTestLogger::default_for_pack("test.pack");

        logger.log_test_result("test_one", true, "");
        logger.log_test_result("test_two", false, "assertion failed");

        assert_eq!(logger.test_result_count(), 2);
    }

    #[test]
    fn pack_test_logger_generates_report() {
        let config = PackTestLogConfig {
            show_patterns: true,
            ..Default::default()
        };
        let mut logger = PackTestLogger::new("test.pack", &config);

        logger.log_test_result("test_pass", true, "");
        logger.log_test_result("test_fail", false, "error");

        let report = logger.generate_report();
        assert_eq!(report.pack, "test.pack");
        assert_eq!(report.summary.total, 2);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
    }

    #[test]
    fn pack_test_logger_reset_clears_data() {
        let mut logger = PackTestLogger::default_for_pack("test.pack");

        logger.log_test_result("test", true, "");
        assert_eq!(logger.test_result_count(), 1);

        logger.reset();
        assert_eq!(logger.test_result_count(), 0);
    }

    #[test]
    fn pack_test_log_config_defaults() {
        let config = PackTestLogConfig::default();
        assert_eq!(config.level, PackTestLogLevel::Info);
        assert!(!config.json_mode);
        assert!(!config.show_timing);
        assert!(!config.show_patterns);
    }

    // =========================================================================
    // Allow-Once Logging Tests (git_safety_guard-oien.1.5)
    // =========================================================================

    #[test]
    fn allow_once_event_labels() {
        assert_eq!(AllowOnceEvent::Issued.label(), "issued");
        assert_eq!(AllowOnceEvent::Granted.label(), "granted");
        assert_eq!(AllowOnceEvent::Consumed.label(), "consumed");
        assert_eq!(AllowOnceEvent::Expired.label(), "expired");
    }

    #[test]
    fn allow_once_log_entry_issued() {
        let redaction = RedactionConfig::default();
        let entry = AllowOnceLogEntry::issued(
            "abc1",
            "full_hash_abc1",
            "git reset --hard",
            "/repo",
            "2026-01-11T12:00:00Z",
            "destroys uncommitted changes",
            false,
            &redaction,
        );

        assert_eq!(entry.event, AllowOnceEvent::Issued);
        assert_eq!(entry.short_code, "abc1");
        assert_eq!(entry.full_hash, "full_hash_abc1");
        assert_eq!(entry.command, "git reset --hard");
        assert_eq!(entry.cwd, "/repo");
        assert!(entry.reason.is_some());
        assert_eq!(entry.single_use, Some(false));
    }

    #[test]
    fn allow_once_log_entry_granted() {
        let redaction = RedactionConfig::default();
        let entry = AllowOnceLogEntry::granted(
            "abc1",
            "full_hash_abc1",
            "git reset --hard",
            "/repo",
            "2026-01-11T12:00:00Z",
            "cwd",
            "/repo",
            true,
            &redaction,
        );

        assert_eq!(entry.event, AllowOnceEvent::Granted);
        assert_eq!(entry.scope_kind, Some("cwd".to_string()));
        assert_eq!(entry.scope_path, Some("/repo".to_string()));
        assert_eq!(entry.single_use, Some(true));
    }

    #[test]
    fn allow_once_log_entry_consumed() {
        let redaction = RedactionConfig::default();
        let entry = AllowOnceLogEntry::consumed(
            "abc1",
            "full_hash_abc1",
            "git reset --hard",
            "/repo",
            &redaction,
        );

        assert_eq!(entry.event, AllowOnceEvent::Consumed);
        assert_eq!(entry.short_code, "abc1");
    }

    #[test]
    fn allow_once_log_entry_expired() {
        let entry = AllowOnceLogEntry::expired(
            "abc1",
            "full_hash_abc1",
            "2026-01-10T12:00:00Z",
            &RedactionConfig::default(),
        );

        assert_eq!(entry.event, AllowOnceEvent::Expired);
        assert_eq!(entry.expires_at, "2026-01-10T12:00:00Z");
        assert!(entry.command.is_empty());
    }

    #[test]
    fn allow_once_log_entry_format_text() {
        let redaction = RedactionConfig::default();
        let entry = AllowOnceLogEntry::issued(
            "abc1",
            "full_hash",
            "git reset --hard",
            "/repo",
            "2026-01-11T12:00:00Z",
            "reason",
            false,
            &redaction,
        );

        let text = entry.format_text();
        assert!(text.contains("[allow-once:issued]"));
        assert!(text.contains("code=abc1"));
        assert!(text.contains(r#"cmd="git reset --hard""#));
        assert!(text.contains("expires=2026-01-11T12:00:00Z"));
    }

    #[test]
    fn allow_once_log_entry_format_json() {
        let redaction = RedactionConfig::default();
        let entry = AllowOnceLogEntry::issued(
            "abc1",
            "full_hash",
            "git reset --hard",
            "/repo",
            "2026-01-11T12:00:00Z",
            "reason",
            false,
            &redaction,
        );

        let json = entry.format_json();
        assert!(json.contains(r#""event":"issued""#));
        assert!(json.contains(r#""short_code":"abc1""#));
        assert!(json.contains(r#""command":"git reset --hard""#));
    }

    #[test]
    fn allow_once_log_entry_redacts_command() {
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            max_argument_len: 50,
        };
        let entry = AllowOnceLogEntry::issued(
            "abc1",
            "full_hash",
            "git reset --hard",
            "/repo",
            "2026-01-11T12:00:00Z",
            "reason",
            false,
            &redaction,
        );

        assert_eq!(entry.command, "[REDACTED]");
    }

    #[test]
    fn allow_once_full_redaction_covers_complete_records_issue_585() {
        let marker = "DCG_SYNTHETIC_PRIVATE_ARGUMENT_9b4e";
        let cwd = format!("/repo/{marker}");
        let reason = format!("producer {} is unmodeled", marker.to_ascii_lowercase());
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            ..RedactionConfig::default()
        };
        let entries = [
            AllowOnceLogEntry::issued(
                "abc1",
                "full_hash",
                marker,
                &cwd,
                "2026-01-11T12:00:00Z",
                &reason,
                true,
                &redaction,
            ),
            AllowOnceLogEntry::granted(
                "abc1",
                "full_hash",
                marker,
                &cwd,
                "2026-01-11T12:00:00Z",
                "project",
                &cwd,
                true,
                &redaction,
            ),
            AllowOnceLogEntry::granted(
                "abc1",
                "full_hash",
                marker,
                &cwd,
                "2026-01-11T12:00:00Z",
                marker,
                &cwd,
                true,
                &redaction,
            ),
            AllowOnceLogEntry::consumed("abc1", "full_hash", marker, &cwd, &redaction),
            AllowOnceLogEntry::expired("abc1", "full_hash", "2026-01-11T12:00:00Z", &redaction),
        ];
        for entry in &entries {
            for serialized in [entry.format_json(), entry.format_text()] {
                assert!(
                    !serialized
                        .to_ascii_lowercase()
                        .contains(&marker.to_ascii_lowercase())
                );
                assert!(!serialized.contains("abc1"));
                assert!(serialized.contains("[REDACTED]"));
            }
            assert_eq!(entry.full_hash, "[REDACTED]");
            assert_eq!(entry.short_code, "[REDACTED]");
        }
        assert_eq!(entries[1].scope_kind.as_deref(), Some("project"));
        assert_eq!(entries[1].scope_path.as_deref(), Some("[REDACTED]"));
        assert_eq!(entries[2].scope_kind.as_deref(), Some("[REDACTED]"));
    }

    #[test]
    fn allow_once_log_entry_redacts_arguments() {
        let redaction = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 5,
        };
        let entry = AllowOnceLogEntry::issued(
            "abc1",
            "full_hash",
            r#"echo "this is a long string""#,
            "/repo",
            "2026-01-11T12:00:00Z",
            "reason",
            false,
            &redaction,
        );

        assert_eq!(entry.command, r#"echo "this ...""#);
    }

    #[test]
    fn allow_once_log_file_write() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let log_path = dir.path().join("allow_once.log");
        let redaction = RedactionConfig::default();

        let entry = AllowOnceLogEntry::issued(
            "test",
            "hash",
            "cmd",
            "/cwd",
            "2026-01-11T12:00:00Z",
            "reason",
            false,
            &redaction,
        );

        log_allow_once_event(log_path.to_str().unwrap(), &entry, LogFormat::Json).unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains(r#""event":"issued""#));
        assert!(content.contains(r#""short_code":"test""#));
    }
}
