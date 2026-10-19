//! Declarative rule engine (`rule_map` in xdp/maps.h).
//!
//! The config describes ports/protocols outside the minecraft range (any
//! server software, forks, admin interfaces, ...) as allow/drop/rate rules
//! with optional length and magic checks; this module compiles them into the
//! fixed-layout `struct rule` values and the `{proto, port}` keys the packet
//! path looks up. `open_tcp_ports`/`open_udp_ports` are sugar for allow
//! rules without checks.

use anyhow::{Context, Result, bail};
use aya::maps::HashMap;
use aya::maps::MapData;
use aya::Pod;

use crate::config::{Config, RuleAction, RuleConfig};

/// Maximum number of rules; mirrors `max_entries` of `rule_map` (xdp/maps.h).
pub const MAX_RULES: usize = 256;

/// Rule actions, mirroring `enum rule_action` (xdp/maps.h).
pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_RATE: u8 = 2;
/// Rule flags, mirroring `enum rule_flags` (xdp/maps.h).
pub const FLAG_STATEFUL: u8 = 1 << 0;

/// Mirror of `struct rule_key` (4 bytes). `port` is network byte order: the
/// eBPF side compares it against the destination port as it appears in the
/// packet.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RuleKey {
    pub proto: u8,
    pub pad: u8,
    pub port: u16,
}
// SAFETY: repr(C) struct with an explicit pad field, no implicit padding.
unsafe impl Pod for RuleKey {}
const _: () = assert!(std::mem::size_of::<RuleKey>() == 4);

/// Mirror of `struct rule` (32 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub magic: u64,
    pub magic_mask: u64,
    pub max_rate: u32,
    pub rule_id: u32,
    pub min_len: u16,
    pub max_len: u16,
    pub action: u8,
    pub flags: u8,
    pub magic_off: u8,
    pub pad: u8,
}
// SAFETY: repr(C) struct of integers with explicit padding to 32 bytes.
unsafe impl Pod for Rule {}
const _: () = assert!(std::mem::size_of::<Rule>() == 32);

/// The compiled rule set in load order (`rule_id` = table index).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub entries: Vec<(RuleKey, Rule)>,
}

impl Rules {
    /// Compiles the `[[rules]]` sections and the `open_*_ports` sugar.
    ///
    /// Config validation already checked the individual values; this adds
    /// the cross-rule checks (duplicate keys, table capacity).
    pub fn from_config(config: &Config) -> Result<Rules> {
        let mut entries: Vec<(RuleKey, Rule)> = Vec::new();

        for rule in &config.rules {
            let (key, value) = compile(rule, entries.len())?;
            append(&mut entries, key, value, rule.name.as_deref())?;
        }
        for (proto, name, ports) in [
            (6u8, "open_tcp_ports", &config.ingress.open_tcp_ports),
            (17u8, "open_udp_ports", &config.ingress.open_udp_ports),
        ] {
            for port in ports {
                let key = RuleKey {
                    proto,
                    pad: 0,
                    port: port.to_be(),
                };
                let value = Rule {
                    action: ACTION_ALLOW,
                    rule_id: entries.len() as u32,
                    ..Rule::default()
                };
                append(&mut entries, key, value, Some(name))?;
            }
        }

        if entries.len() > MAX_RULES {
            bail!(
                "{} rules compiled, but rule_map holds at most {MAX_RULES}",
                entries.len()
            );
        }
        Ok(Rules { entries })
    }

    /// Replaces the map contents with this rule set and returns the count.
    pub fn apply(&self, map: &mut HashMap<MapData, RuleKey, Rule>) -> Result<usize> {
        let stale: Vec<RuleKey> = map.keys().filter_map(|key| key.ok()).collect();
        for key in stale {
            map.remove(&key)
                .context("failed to remove an existing rule")?;
        }
        for (key, value) in &self.entries {
            map.insert(key, value, 0).with_context(|| {
                format!(
                    "failed to insert rule proto={} port={}",
                    key.proto,
                    u16::from_be(key.port)
                )
            })?;
        }
        Ok(self.entries.len())
    }

    /// One human-readable line per rule, for the startup log.
    pub fn describe(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(key, rule)| {
                let action = match rule.action {
                    ACTION_DROP => "drop",
                    ACTION_RATE => "rate",
                    _ => "allow",
                };
                let mut extra = String::new();
                if rule.action == ACTION_RATE {
                    if rule.max_rate > 0 {
                        extra.push_str(&format!(" max_rate={}", rule.max_rate));
                    } else {
                        extra.push_str(" max_rate=tunable");
                    }
                }
                if rule.min_len != 0 || rule.max_len != 0 {
                    extra.push_str(&format!(" len={}..{}", rule.min_len, rule.max_len));
                }
                if rule.magic_mask != 0 {
                    extra.push_str(&format!(" magic=0x{:x}", rule.magic));
                }
                if rule.flags & FLAG_STATEFUL != 0 {
                    extra.push_str(" stateful");
                }
                format!(
                    "proto={} port={} action={action}{extra}",
                    key.proto,
                    u16::from_be(key.port)
                )
            })
            .collect()
    }
}

/// Compiles one `[[rules]]` entry into its key and value.
fn compile(rule: &RuleConfig, rule_id: usize) -> Result<(RuleKey, Rule)> {
    let (proto, has_ports) = rule.proto_number_and_ports();
    if !has_ports {
        bail!(
            "[[rules]] proto={} is not tcp/udp; port-based rules need a transport protocol",
            rule.proto
        );
    }
    let (magic, magic_mask) = rule.magic_bytes();
    let action = match rule.action {
        RuleAction::Allow => ACTION_ALLOW,
        RuleAction::Drop => ACTION_DROP,
        RuleAction::Rate => ACTION_RATE,
    };
    let key = RuleKey {
        proto,
        pad: 0,
        port: rule.port.to_be(),
    };
    let value = Rule {
        magic,
        magic_mask,
        max_rate: rule.max_rate,
        rule_id: rule_id as u32,
        min_len: rule.min_len,
        max_len: rule.max_len,
        action,
        flags: if rule.stateful { FLAG_STATEFUL } else { 0 },
        magic_off: rule.magic_offset,
        pad: 0,
    };
    Ok((key, value))
}

/// Appends one rule, rejecting duplicates and re-assigning the rule id so
/// dropping/reordering config entries cannot leave stale ids behind.
fn append(
    entries: &mut Vec<(RuleKey, Rule)>,
    key: RuleKey,
    mut value: Rule,
    label: Option<&str>,
) -> Result<()> {
    if entries.iter().any(|(existing, _)| *existing == key) {
        bail!(
            "duplicate rule for proto={} port={} (from {})",
            key.proto,
            u16::from_be(key.port),
            label.unwrap_or("[[rules]]")
        );
    }
    value.rule_id = entries.len() as u32;
    entries.push((key, value));
    Ok(())
}

/// Takes `rule_map`, applies the compiled rules and logs a summary. Returns
/// the number of rules installed (0 when `RULES_ENABLED` stays off).
pub fn start(ebpf: &mut aya::Ebpf, config: &Config) -> Result<usize> {
    let rules = Rules::from_config(config)?;
    if rules.entries.is_empty() {
        return Ok(0);
    }
    let map = ebpf
        .take_map("rule_map")
        .context("can't take map 'rule_map'")?;
    let mut map: HashMap<MapData, RuleKey, Rule> = HashMap::try_from(map)?;
    let count = rules.apply(&mut map)?;
    for line in rules.describe() {
        log::info!("Rule: {line}");
    }
    log::info!("Rule engine loaded: {count} rules");
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with(rules_toml: &str) -> Config {
        // tests that supply their own [ingress] section keep it as-is
        let text = if rules_toml.contains("[ingress]") {
            rules_toml.to_string()
        } else {
            format!("[ingress]\ndefault_deny = true\negress_tracking = true\n{rules_toml}")
        };
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn compiles_actions_and_checks() {
        let config = config_with(
            r#"
[[rules]]
name = "game"
proto = "udp"
port = 27015
action = "rate"
max_rate = 100
min_len = 2
max_len = 1200
magic = "0a0b"
magic_offset = 4
stateful = true

[[rules]]
proto = "tcp"
port = 22
action = "allow"
"#,
        );
        let rules = Rules::from_config(&config).unwrap();
        assert_eq!(rules.entries.len(), 2);

        let (key, value) = &rules.entries[0];
        assert_eq!(key.proto, 17);
        assert_eq!(u16::from_be(key.port), 27015);
        assert_eq!(value.action, ACTION_RATE);
        assert_eq!(value.max_rate, 100);
        assert_eq!(value.min_len, 2);
        assert_eq!(value.max_len, 1200);
        assert_eq!(value.magic, 0x0b0a); // first payload byte = low byte
        assert_eq!(value.magic_mask, 0xffff);
        assert_eq!(value.magic_off, 4);
        assert_eq!(value.flags & FLAG_STATEFUL, FLAG_STATEFUL);
        assert_eq!(value.rule_id, 0);

        let (key, value) = &rules.entries[1];
        assert_eq!(key.proto, 6);
        assert_eq!(u16::from_be(key.port), 22);
        assert_eq!(value.action, ACTION_ALLOW);
        assert_eq!(value.rule_id, 1);
        assert_eq!(value.flags, 0);
    }

    #[test]
    fn open_ports_become_allow_rules() {
        let config = config_with(
            r#"
[ingress]
open_tcp_ports = [8080, 8443]
open_udp_ports = [51820]
"#,
        );
        let rules = Rules::from_config(&config).unwrap();
        assert_eq!(rules.entries.len(), 3);
        for (key, value) in &rules.entries {
            assert_eq!(value.action, ACTION_ALLOW);
            assert_eq!(value.magic_mask, 0);
            assert!(matches!(key.proto, 6 | 17));
        }
    }

    #[test]
    fn rejects_duplicate_keys() {
        let config = config_with(
            r#"
[[rules]]
proto = "tcp"
port = 8080
action = "allow"

[[rules]]
proto = "tcp"
port = 8080
action = "drop"
"#,
        );
        let error = Rules::from_config(&config).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate"), "{error:#}");
    }

    #[test]
    fn rejects_open_port_overlapping_a_rule() {
        let config = config_with(
            r#"
[ingress]
open_tcp_ports = [8080]

[[rules]]
proto = "tcp"
port = 8080
action = "allow"
"#,
        );
        let error = Rules::from_config(&config).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate"), "{error:#}");
    }

    #[test]
    fn rate_rules_without_max_rate_fall_back_to_the_tunable() {
        let config = config_with(
            r#"
[[rules]]
proto = "udp"
port = 19132
action = "rate"
"#,
        );
        let rules = Rules::from_config(&config).unwrap();
        assert_eq!(rules.entries[0].1.max_rate, 0);
        assert!(rules.describe()[0].contains("max_rate=tunable"));
    }
}
