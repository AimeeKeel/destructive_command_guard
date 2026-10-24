//! Regression coverage for loss of trusted policy on config errors (#568).
use super::*;
use crate::allowlist::LayeredAllowlist;
use crate::evaluator::{EvaluationDecision, evaluate_command_with_pack_order};

fn load(path: &Path, source: ConfigSource, layer: ConfigFileLayer) -> Option<ConfigLayer> {
    Config::load_layer_from_file_with_outcome(
        path,
        source,
        layer,
        if source == ConfigSource::AutoProject {
            ConfigFileAuthority::EnforcementOnly
        } else {
            ConfigFileAuthority::Full
        },
        false,
    )
    .0
}

#[test]
fn malformed_trusted_layers_retain_errors_without_diagnostic_tracing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for content in [
        "[general",
        "[policy.rules]\n\"core.git:reset-hard\" = \"not-a-mode\"",
    ] {
        fs::write(&path, content).unwrap();
        for layer in [ConfigFileLayer::User, ConfigFileLayer::Explicit] {
            let mut config = Config::default();
            config.merge_layer(load(&path, ConfigSource::Untrusted, layer).unwrap());
            let reason = config.configuration_error().unwrap();
            assert!(reason.contains("config.toml"));
            assert!(reason.contains("line"));
            assert!(reason.contains("dcg doctor --strict"));
            assert!(config.is_fail_closed());
            assert!(config.unverified_denies());
        }
    }
}

#[test]
fn missing_optional_sources_are_not_missing_explicit_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    assert!(load(&path, ConfigSource::Untrusted, ConfigFileLayer::User).is_none());
    assert!(load(&path, ConfigSource::System, ConfigFileLayer::System).is_none());
    assert!(
        load(
            &path,
            ConfigSource::AutoProject,
            ConfigFileLayer::AutomaticProject
        )
        .is_none()
    );
    let mut config = Config::default();
    config.merge_layer(load(&path, ConfigSource::Untrusted, ConfigFileLayer::Explicit).unwrap());
    assert!(
        config
            .configuration_error()
            .unwrap()
            .contains("does not exist")
    );
}

#[test]
fn trusted_read_failures_cannot_fall_back_to_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for content in [vec![0xff, 0xfe], vec![b' '; MAX_CONFIG_BYTES as usize + 1]] {
        fs::write(&path, content).unwrap();
        let mut config = Config::default();
        config.merge_layer(load(&path, ConfigSource::Untrusted, ConfigFileLayer::User).unwrap());
        assert!(config.configuration_error().is_some());
        assert!(
            load(
                &path,
                ConfigSource::AutoProject,
                ConfigFileLayer::AutomaticProject
            )
            .is_none()
        );
    }
}

#[test]
fn system_trust_rejection_and_post_validation_content_failure_are_distinct() {
    let rejected = ConfigReadFailure::Rejected("untrusted ownership".into());
    assert!(!rejected.blocks_trusted_layer(ConfigSource::System, ConfigFileLayer::System));
    assert!(rejected.blocks_trusted_layer(ConfigSource::Untrusted, ConfigFileLayer::User));
    let unreadable = ConfigReadFailure::Content("invalid UTF-8 after trusted open".into());
    assert!(unreadable.blocks_trusted_layer(ConfigSource::System, ConfigFileLayer::System));
    assert!(
        !unreadable
            .blocks_trusted_layer(ConfigSource::AutoProject, ConfigFileLayer::AutomaticProject)
    );
}

#[test]
fn later_allow_policy_cannot_erase_a_required_layer_failure() {
    let mut config = Config::default();
    config.merge_layer(Config::failed_config_layer(
        Path::new("admin.toml"),
        "invalid policy",
    ));
    config.merge_layer(
        toml::from_str::<ConfigLayer>(
            "[overrides]\nallow = [\".*\"]\n[policy]\ndefault_mode = \"log\"",
        )
        .unwrap(),
    );
    let compiled = config.overrides.compile();
    assert!(compiled.check_allow("git reset --hard"));
    for command in ["", "git status", "printf dcg-protected", "git reset --hard"] {
        let result = evaluate_command_with_pack_order(
            command,
            &[],
            &[],
            None,
            &compiled,
            &LayeredAllowlist::default(),
            &HeredocSettings::default(),
        );
        assert_eq!(result.decision, EvaluationDecision::Deny, "{command}");
        assert!(result.reason().unwrap().contains("admin.toml"));
        assert!(!result.quick_rejected);
    }
}

#[test]
fn automatic_malformed_policy_is_ignored_not_promoted_to_global_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dcg.toml");
    fs::write(
        &path,
        "[policy.rules]\n\"core.git:reset-hard\" = \"malicious-invalid-mode\"",
    )
    .unwrap();
    assert!(
        load(
            &path,
            ConfigSource::AutoProject,
            ConfigFileLayer::AutomaticProject
        )
        .is_none()
    );
    let trusted = load(&path, ConfigSource::Untrusted, ConfigFileLayer::Explicit).unwrap();
    let mut config = Config::default();
    config.merge_layer(trusted);
    assert!(config.configuration_error().is_some());
}

#[test]
fn runtime_failure_marker_cannot_be_injected_or_serialized() {
    let config: Config =
        toml::from_str("[overrides]\nconfiguration_error = \"attacker-controlled denial\"")
            .unwrap();
    assert!(config.configuration_error().is_none());
    let mut failed = Config::default();
    failed.merge_layer(Config::failed_config_layer(
        Path::new("required.toml"),
        "bad TOML",
    ));
    assert!(
        !toml::to_string(&failed)
            .unwrap()
            .contains("configuration_error")
    );
    assert!(failed.save_to_user_config().is_err());
}

#[test]
fn valid_configuration_and_optional_absence_preserve_harmless_evaluation() {
    let config = Config::default();
    let compiled = config.overrides.compile();
    let result = evaluate_command_with_pack_order(
        "git status",
        &[],
        &[],
        None,
        &compiled,
        &LayeredAllowlist::default(),
        &HeredocSettings::default(),
    );
    assert_eq!(result.decision, EvaluationDecision::Allow);
}
