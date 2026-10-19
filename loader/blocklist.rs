//! Operator blocklist (LPM, CIDR file) and the kernel auto-block table.
//!
//! Two pieces of state live here:
//!
//!  - `blocklist_map`: operator-supplied CIDRs, parsed from a file (same
//!    text format as the allowlist) and re-read on SIGHUP. Entries are
//!    permanent until removed from the file.
//!
//!  - `autoblock_map`: exact-address blocks with an expiry. The *kernel*
//!    inserts them when a source keeps violating the rate limits
//!    (blocklist.h), the ML scorer inserts through the same store, and this
//!    module prunes expired entries, tracks them for the logs and exports
//!    the active set for upstream enforcement (nftables/blackhole routes).
//!
//! The kernel also checks `expires_ns` on every lookup, so an entry that is
//! expired but not yet pruned is harmless; pruning exists to give the slots
//! back and to drive the export/metrics.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;
use aya::maps::lpm_trie::LpmTrie;
use log::{debug, error, info, warn};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;

use crate::cidr::CidrList;
use crate::config::Config;
use crate::metrics;
use crate::shutdown::Shutdown;
use crate::state::{BlockEntry, EgressValue, FlowKey, HostKey, now_ns};

/// A parsed operator blocklist file, ready to be pushed into the trie.
pub type Blocklist = CidrList;

/// Map layout must match `blocklist_map` (xdp/maps.h): the same LPM key as
/// the allowlist, `struct block_entry` as the value.
pub type BlocklistMap = LpmTrie<MapData, [u8; 16], BlockEntry>;

/// Exact-address auto-block table; shared with the ML scorer.
pub type AutoblockMap = AyaHashMap<MapData, HostKey, BlockEntry>;

/// Shared handle to the autoblock table: prune/export and ML enforcement both
/// lock it, so a block can never be exported after it was removed.
pub type AutoblockStore = Arc<Mutex<AutoblockMap>>;

/// Egress flow table (read-only here, for the `minecraft_egress_flows`
/// gauge).
pub type EgressMap = AyaHashMap<MapData, FlowKey, EgressValue>;

/// How often expired blocks are pruned, exported and logged.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
/// SIGHUP/timeout poll of the maintenance thread.
const TICK: Duration = Duration::from_secs(1);
/// Cap on the number of block/unblock log lines per maintenance pass.
const MAX_LOG_LINES: usize = 10;

/// Everything the blocklist side handed to the rest of the loader.
pub struct BlocklistRuntime {
    pub handle: Option<JoinHandle<()>>,
    /// Shared auto-block table (the ML scorer inserts through the same lock).
    pub autoblocks: Option<AutoblockStore>,
}

/// Replaces the trie contents with `list` and returns the entry count.
fn apply_operator_list(list: &CidrList, map: &mut BlocklistMap) -> Result<usize> {
    let stale: Vec<aya::maps::lpm_trie::Key<[u8; 16]>> =
        map.keys().filter_map(|key| key.ok()).collect();
    for key in stale {
        map.remove(&key)
            .context("failed to remove an existing blocklist entry")?;
    }
    for entry in &list.entries {
        map.insert(&entry.key(), BlockEntry::permanent(), 0)
            .with_context(|| {
                format!(
                    "failed to insert blocklist entry {} (raise [blocklist] max_entries?)",
                    entry.display()
                )
            })?;
    }
    Ok(list.entries.len())
}

/// Installs the operator blocklist (when configured), takes the auto-block
/// (and egress) maps and spawns the maintenance thread. Returns `None` when
/// neither a blocklist file nor auto-blocking is active.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    blocklist: Option<Blocklist>,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<BlocklistRuntime>> {
    let operator = match &config.blocklist.blocklist_file {
        Some(file) => {
            let Some(list) = blocklist else {
                bail!(
                    "blocklist_file is set but no parsed blocklist was passed to blocklist::start"
                );
            };
            let max_entries = config.blocklist.max_entries as usize;
            if list.entries.len() > max_entries {
                bail!(
                    "blocklist file '{file}' has {} entries, more than [blocklist] max_entries = {max_entries}",
                    list.entries.len()
                );
            }
            let map = ebpf
                .take_map("blocklist_map")
                .context("can't take map 'blocklist_map'")?;
            let mut map: BlocklistMap = LpmTrie::try_from(map)?;
            let count = apply_operator_list(&list, &mut map)?;
            metrics::BLOCKLIST_ENTRIES.set(count as i64);
            info!("Blocklist loaded from '{file}': {count} entries");
            Some((PathBuf::from(file), map, max_entries))
        }
        None => None,
    };

    let need_autoblocks = config.blocklist.autoblock
        || config.blocklist.export_file.is_some()
        || config.ml.enabled;
    let autoblocks = if need_autoblocks {
        let map = ebpf
            .take_map("autoblock_map")
            .context("can't take map 'autoblock_map'")?;
        Some(Arc::new(Mutex::new(AutoblockMap::try_from(map)?)))
    } else {
        None
    };

    let egress = if config.ingress.egress_tracking {
        let map = ebpf
            .take_map("egress_flows")
            .context("can't take map 'egress_flows'")?;
        Some(Arc::new(Mutex::new(EgressMap::try_from(map)?)))
    } else {
        None
    };

    if operator.is_none() && autoblocks.is_none() && egress.is_none() {
        return Ok(None);
    }

    let export_file = config
        .blocklist
        .export_file
        .clone()
        .map(PathBuf::from);
    let shutdown = shutdown.clone();
    let maintenance_autoblocks = autoblocks.clone();
    let maintenance_egress = egress.clone();
    let handle = thread::Builder::new()
        .name("blocklist".into())
        .spawn(move || {
            let mut signals = match operator.is_some() {
                true => match Signals::new([SIGHUP]) {
                    Ok(signals) => Some(signals),
                    Err(error) => {
                        warn!("failed to register the SIGHUP handler: {error}");
                        None
                    }
                },
                false => None,
            };
            let mut operator = operator;
            let mut snapshot: HashMap<HostKey, BlockEntry> = HashMap::new();
            let mut last_export: Option<String> = None;
            let mut next_maintenance = Instant::now();
            loop {
                if let (Some(signals), Some((path, map, max_entries))) =
                    (signals.as_mut(), operator.as_mut())
                {
                    for _ in signals.pending() {
                        info!("Received SIGHUP, reloading blocklist from '{}'", path.display());
                        let mut reload = || -> Result<usize> {
                            let list = Blocklist::load(path)?;
                            if list.entries.len() > *max_entries {
                                bail!(
                                    "file has {} entries, more than [blocklist] max_entries = {max_entries}",
                                    list.entries.len()
                                );
                            }
                            apply_operator_list(&list, map)
                        };
                        match reload() {
                            Ok(count) => {
                                metrics::BLOCKLIST_ENTRIES.set(count as i64);
                                info!("Blocklist reloaded: {count} entries");
                            }
                            Err(error) => error!(
                                "Blocklist reload failed, the map may hold a partial list: {error:#}"
                            ),
                        }
                    }
                }

                if Instant::now() >= next_maintenance {
                    next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
                    if let Some(store) = &maintenance_autoblocks
                        && let Err(error) = maintain(
                            store,
                            export_file.as_deref(),
                            &mut snapshot,
                            &mut last_export,
                        )
                    {
                        // maintenance is auxiliary: a failure must never
                        // take the filter down, and the next pass retries
                        warn!("Auto-block maintenance failed (retrying): {error:#}");
                    }
                    if let Some(egress) = &maintenance_egress {
                        match egress.lock() {
                            Ok(map) => {
                                metrics::EGRESS_FLOWS.set(map.keys().count() as i64);
                            }
                            Err(_) => metrics::EGRESS_FLOWS.set(0),
                        }
                    }
                }

                if !shutdown.sleep(TICK) {
                    return;
                }
            }
        })?;

    Ok(Some(BlocklistRuntime {
        handle: Some(handle),
        autoblocks,
    }))
}

/// One maintenance pass over the auto-block table: prune expired entries,
/// publish the count, log new/escalated/expired blocks and rewrite the export
/// file when the active set changed.
fn maintain(
    store: &AutoblockStore,
    export_file: Option<&std::path::Path>,
    snapshot: &mut HashMap<HostKey, BlockEntry>,
    last_export: &mut Option<String>,
) -> Result<()> {
    let now = now_ns();
    let mut map = store.lock().expect("autoblock store poisoned");
    let current: Vec<(HostKey, BlockEntry)> = map
        .iter()
        .filter_map(|entry| entry.ok())
        .collect();

    let mut blocked = 0usize;
    let mut new_blocks = Vec::new();
    let mut escalated = Vec::new();
    let mut next_snapshot = HashMap::with_capacity(current.len());
    for (key, entry) in &current {
        if entry.is_expired(now) {
            map.remove(key)
                .with_context(|| format!("failed to prune expired block {}", key.to_ip()))?;
            continue;
        }
        blocked += 1;
        match snapshot.get(key) {
            Some(previous) if previous.strikes < entry.strikes => {
                escalated.push((*key, *entry));
            }
            None => new_blocks.push((*key, *entry)),
            Some(_) => {}
        }
        next_snapshot.insert(*key, *entry);
    }
    let expired: Vec<HostKey> = snapshot
        .keys()
        .filter(|key| !next_snapshot.contains_key(*key))
        .copied()
        .collect();
    *snapshot = next_snapshot;
    metrics::AUTOBLOCK_ENTRIES.set(blocked as i64);

    for (key, entry) in new_blocks.iter().take(MAX_LOG_LINES) {
        info!(
            "Auto-blocked {}: strikes={} expires_in={}s reason={}",
            key.to_ip(),
            entry.strikes,
            remaining_secs(entry.expires_ns, now),
            metrics::drop_reason_name(entry.reason),
        );
    }
    for (key, entry) in escalated.iter().take(MAX_LOG_LINES) {
        info!(
            "Auto-block escalated for {}: strikes={} expires_in={}s reason={}",
            key.to_ip(),
            entry.strikes,
            remaining_secs(entry.expires_ns, now),
            metrics::drop_reason_name(entry.reason),
        );
    }
    for key in expired.iter().take(MAX_LOG_LINES) {
        debug!("Auto-block expired for {}", key.to_ip());
    }
    let logged = new_blocks.len() + escalated.len() + expired.len();
    if logged > MAX_LOG_LINES {
        info!("... and {} more auto-block changes", logged - MAX_LOG_LINES);
    }

    if let Some(path) = export_file {
        let rendered = render_export(&current, now);
        if last_export.as_deref() != Some(rendered.as_str()) {
            write_atomic(path, &rendered)
                .with_context(|| format!("failed to write export file '{}'", path.display()))?;
            *last_export = Some(rendered);
            debug!(
                "Exported {blocked} active auto-blocks to '{}'",
                path.display()
            );
        }
    }
    Ok(())
}

/// Blocks one source for `ttl_ns` (used by the ML scorer in `enforce` mode).
///
/// An existing block is only extended (never shortened, never downgraded),
/// and the strike level escalates like the kernel's own auto-blocker so a
/// repeat offender ends up with the longer duration.
pub fn block_source(
    store: &AutoblockStore,
    host: &HostKey,
    ttl_ns: u64,
    reason: u32,
) -> Result<BlockEntry> {
    let now = now_ns();
    let mut map = store.lock().expect("autoblock store poisoned");
    let entry = match map.get(host, 0) {
        Ok(existing) => {
            let mut upgraded = existing;
            upgraded.strikes = (existing.strikes + 1).min(31);
            upgraded.expires_ns = existing.expires_ns.max(now.saturating_add(ttl_ns));
            upgraded.last_strike_ns = now;
            upgraded.reason = reason;
            upgraded
        }
        Err(_) => BlockEntry::ttl(now.saturating_add(ttl_ns), reason),
    };
    map.insert(*host, entry, 0)
        .with_context(|| format!("failed to insert an auto-block for {}", host.to_ip()))?;
    Ok(entry)
}

/// True when the store currently holds an unexpired block for `host`.
pub fn is_blocked(store: &AutoblockStore, host: &HostKey) -> bool {
    let now = now_ns();
    let map = store.lock().expect("autoblock store poisoned");
    map.get(host, 0)
        .map(|entry| !entry.is_expired(now))
        .unwrap_or(false)
}

fn remaining_secs(expires_ns: u64, now: u64) -> u64 {
    if expires_ns == 0 {
        return 0; // permanent
    }
    expires_ns.saturating_sub(now) / 1_000_000_000
}

/// Renders the export file: a header, then one `<address> # ...` line per
/// active block. The address is the first field, so `awk '{print $1}'` works
/// for nftables/ipset consumers.
fn render_export(entries: &[(HostKey, BlockEntry)], now: u64) -> String {
    let mut output = String::from(
        "# minecraft-xdp auto-block export\n\
         # one source per line: <address> # strikes=<n> expires_in_s=<n|permanent> reason=<name>\n",
    );
    let mut sorted: Vec<&(HostKey, BlockEntry)> = entries.iter().collect();
    sorted.sort_by_key(|(key, _)| key.addr);
    for (key, entry) in sorted {
        let expires = match entry.expires_ns {
            0 => "permanent".to_string(),
            _ => remaining_secs(entry.expires_ns, now).to_string(),
        };
        output.push_str(&format!(
            "{} # strikes={} expires_in_s={} reason={}\n",
            key.to_ip(),
            entry.strikes,
            expires,
            metrics::drop_reason_name(entry.reason),
        ));
    }
    output
}

/// Writes `contents` to `path` through a temporary file so consumers never
/// read a half-written list.
fn write_atomic(path: &std::path::Path, contents: &str) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("failed to write '{}'", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to move '{}' into place", temporary.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_lists_addresses_first() {
        let entries = vec![
            (
                HostKey::from_ip("203.0.113.9".parse().unwrap()),
                BlockEntry::ttl(10_000_000_000, 41),
            ),
            (
                HostKey::from_ip("2001:db8::1".parse().unwrap()),
                BlockEntry::permanent(),
            ),
        ];
        let rendered = render_export(&entries, 4_000_000_000);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with('#'));
        assert!(lines[2].starts_with("203.0.113.9 "), "{}", lines[2]);
        assert!(lines[2].contains("strikes=1"));
        assert!(lines[2].contains("expires_in_s=6"));
        assert!(lines[2].contains("reason=autoblock"));
        assert!(lines[3].starts_with("2001:db8::1 "), "{}", lines[3]);
        assert!(lines[3].contains("expires_in_s=permanent"));
    }

    #[test]
    fn export_is_stable_for_unchanged_sets() {
        let entries = vec![(
            HostKey::from_ip("198.51.100.7".parse().unwrap()),
            BlockEntry::ttl(5_000_000_000, 41),
        )];
        assert_eq!(
            render_export(&entries, 1_000_000_000),
            render_export(&entries, 1_000_000_000)
        );
    }
}
