//! Integration tests for `cairn_mod::config::Config` — wire shape +
//! validation + the AdminConfigToml → AdminConfig conversion L4
//! depends on.

use std::net::{IpAddr, Ipv4Addr};

use cairn_mod::config::{AdminConfigToml, Config, DEFAULT_BIND_ADDR};

fn minimum_required() -> serde_json::Value {
    serde_json::json!({
        "service_did": "did:web:labeler.example",
        "service_endpoint": "https://labeler.example",
        "db_path": "/var/lib/cairn/cairn.db",
        "signing_key_path": "/etc/cairn/signing-key.hex",
    })
}

#[test]
fn bind_addr_defaults_to_loopback() {
    let cfg: Config = serde_json::from_value(minimum_required()).unwrap();
    assert_eq!(cfg.bind_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(cfg.bind_addr.port(), 3000);
    assert_eq!(cfg.bind_addr.to_string(), DEFAULT_BIND_ADDR);
}

#[test]
fn admin_table_defaults_to_empty() {
    let cfg: Config = serde_json::from_value(minimum_required()).unwrap();
    assert!(cfg.admin.label_values.is_none());
}

#[test]
fn admin_table_is_nested() {
    let mut v = minimum_required();
    v["admin"] = serde_json::json!({
        "label_values": ["spam", "abuse"]
    });
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert_eq!(
        cfg.admin.label_values,
        Some(vec!["spam".into(), "abuse".into()])
    );
}

#[test]
fn bind_addr_accepts_custom_value() {
    let mut v = minimum_required();
    v["bind_addr"] = serde_json::json!("0.0.0.0:9000");
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert_eq!(cfg.bind_addr.port(), 9000);
    assert_eq!(cfg.bind_addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn validate_rejects_malformed_service_endpoint() {
    let mut v = minimum_required();
    v["service_endpoint"] = serde_json::json!("not a url");
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_accepts_valid_service_endpoint() {
    let cfg: Config = serde_json::from_value(minimum_required()).unwrap();
    cfg.validate().expect("validate");
}

#[test]
fn admin_toml_converts_to_runtime_admin_config() {
    let toml = AdminConfigToml {
        label_values: Some(vec!["spam".into()]),
    };
    let runtime: cairn_mod::AdminConfig = toml.into();
    assert_eq!(runtime.label_values, Some(vec!["spam".into()]));
}

#[test]
fn retention_block_defaults_when_absent() {
    let cfg: Config = serde_json::from_value(minimum_required()).unwrap();
    assert!(cfg.retention.sweep_enabled);
    assert_eq!(cfg.retention.sweep_run_at_utc_hour, 4);
    assert_eq!(cfg.retention.sweep_batch_size, 1000);
}

#[test]
fn retention_block_accepts_custom_values() {
    let mut v = minimum_required();
    v["retention"] = serde_json::json!({
        "sweep_enabled": false,
        "sweep_run_at_utc_hour": 3,
        "sweep_batch_size": 500
    });
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert!(!cfg.retention.sweep_enabled);
    assert_eq!(cfg.retention.sweep_run_at_utc_hour, 3);
    assert_eq!(cfg.retention.sweep_batch_size, 500);
}

#[test]
fn retention_block_partial_override_inherits_other_defaults() {
    let mut v = minimum_required();
    v["retention"] = serde_json::json!({
        "sweep_run_at_utc_hour": 6
    });
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert!(cfg.retention.sweep_enabled, "default true preserved");
    assert_eq!(cfg.retention.sweep_run_at_utc_hour, 6);
    assert_eq!(cfg.retention.sweep_batch_size, 1000, "default preserved");
}

#[test]
fn validate_rejects_out_of_range_sweep_hour() {
    let mut v = minimum_required();
    v["retention"] = serde_json::json!({"sweep_run_at_utc_hour": 24});
    let cfg: Config = serde_json::from_value(v).unwrap();
    let err = cfg.validate().expect_err("hour=24 must reject");
    assert!(format!("{err}").contains("sweep_run_at_utc_hour"));
}

#[test]
fn validate_rejects_zero_or_negative_batch_size() {
    let mut v = minimum_required();
    v["retention"] = serde_json::json!({"sweep_batch_size": 0});
    let cfg: Config = serde_json::from_value(v).unwrap();
    assert!(
        cfg.validate().is_err(),
        "batch_size=0 must reject (DELETE LIMIT 0 is a no-op loop)"
    );
}

#[test]
fn retention_toml_converts_to_runtime_retention_config() {
    use cairn_mod::config::RetentionConfigToml;
    let toml = RetentionConfigToml {
        sweep_enabled: false,
        sweep_run_at_utc_hour: 2,
        sweep_batch_size: 250,
    };
    let runtime: cairn_mod::RetentionConfig = toml.into();
    assert!(!runtime.sweep_enabled);
    assert_eq!(runtime.sweep_run_at_utc_hour, 2);
    assert_eq!(runtime.sweep_batch_size, 250);
}
