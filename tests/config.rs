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
