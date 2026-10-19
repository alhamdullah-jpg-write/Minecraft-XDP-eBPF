//! Source address allowlist.
//!
//! The list is a plain text file (one IPv4/IPv6 address or CIDR per line,
//! `#` comments and blank lines ignored), parsed by `cidr.rs` and pushed into
//! the `allowlist_map` LPM trie of the eBPF program. The map is consulted
//! before any other check for traffic on the filtered ports, so allowlisted
//! sources skip the SYN throttle and the connection tracking entirely.
//!
//! The file is read at startup (a broken file stops the loader instead of
//! silently filtering everything) and re-read on SIGHUP. See the warning in
//! the default config: allowlisting a source only makes sense when the
//! upstream filters spoofed source addresses (uRPF/BCP38), otherwise an
//! attacker can impersonate an allowlisted address.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::MapData;
use aya::maps::lpm_trie::LpmTrie;
use log::{error, info};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;

use crate::cidr::CidrList;
use crate::config::Config;
use crate::metrics::ALLOWLIST_ENTRIES;
use crate::shutdown::Shutdown;

/// Map layout must match the `allowlist_map` definition in xdp/maps.h:
/// `struct lpm_key { __u32 prefixlen; __u8 addr[16]; }` as the key and `__u8`
/// as the value. aya's packed `Key<[u8; 16]>` has exactly that layout.
pub type AllowlistMap = LpmTrie<MapData, [u8; 16], u8>;

/// A parsed allowlist file, ready to be pushed into the map.
pub type Allowlist = CidrList;

/// Replaces the map contents with `list` and returns the entry count.
///
/// Old entries are removed first so shrinking the file actually takes
/// effect. A failure halfway through leaves a partial list behind; the
/// caller must treat the map as unusable in that case.
fn apply(list: &CidrList, map: &mut AllowlistMap) -> Result<usize> {
    let stale: Vec<aya::maps::lpm_trie::Key<[u8; 16]>> =
        map.keys().filter_map(|key| key.ok()).collect();
    for key in stale {
        map.remove(&key)
            .context("failed to remove an existing allowlist entry")?;
    }
    for entry in &list.entries {
        map.insert(&entry.key(), 1u8, 0).with_context(|| {
            format!(
                "failed to insert allowlist entry {} (raise [xdp] max_allowlist_entries?)",
                entry.display()
            )
        })?;
    }
    Ok(list.entries.len())
}

/// Pushes `allowlist` into `allowlist_map` and spawns the SIGHUP reload
/// thread. No-op when no allowlist file is configured.
///
/// `allowlist` is parsed by the caller before the XDP program is attached, so
/// a misconfigured file cannot leave a half-working filter behind.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    allowlist: Option<Allowlist>,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    let Some(file) = config.xdp.allowlist_file.clone() else {
        return Ok(None);
    };
    let Some(allowlist) = allowlist else {
        bail!("allowlist_file is set but no parsed allowlist was passed to allowlist::start");
    };
    let path = PathBuf::from(file);
    let max_entries = config.xdp.max_allowlist_entries as usize;
    if allowlist.entries.len() > max_entries {
        bail!(
            "allowlist file '{}' has {} entries, more than [xdp] max_allowlist_entries = {max_entries}",
            path.display(),
            allowlist.entries.len()
        );
    }

    let map = ebpf
        .take_map("allowlist_map")
        .context("can't take map 'allowlist_map'")?;
    let mut map: AllowlistMap = LpmTrie::try_from(map)?;
    let count = apply(&allowlist, &mut map)?;
    ALLOWLIST_ENTRIES.set(count as i64);
    info!(
        "Allowlist loaded from '{}': {count} entries",
        path.display()
    );

    let mut signals = Signals::new([SIGHUP]).context("failed to register the SIGHUP handler")?;
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("allowlist-reload".into())
        .spawn(move || {
            loop {
                for _ in signals.pending() {
                    info!("Received SIGHUP, reloading allowlist from '{}'", path.display());
                    let mut reload = || -> Result<usize> {
                        let allowlist = Allowlist::load(&path)?;
                        if allowlist.entries.len() > max_entries {
                            bail!(
                                "file has {} entries, more than [xdp] max_allowlist_entries = {max_entries}",
                                allowlist.entries.len()
                            );
                        }
                        apply(&allowlist, &mut map)
                    };
                    match reload() {
                        Ok(count) => {
                            ALLOWLIST_ENTRIES.set(count as i64);
                            info!("Allowlist reloaded: {count} entries");
                        }
                        Err(error) => error!(
                            "Allowlist reload failed, the map may hold a partial list: {error:#}"
                        ),
                    }
                }
                // the poll interval only bounds how quickly a SIGHUP is
                // noticed; the sleep wakes up immediately on shutdown
                if !shutdown.sleep(Duration::from_secs(1)) {
                    return;
                }
            }
        })?;
    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_families_through_the_shared_cidr_list() {
        let list: Allowlist = Allowlist::parse("10.0.0.0/8\n2001:db8::/32\n").unwrap();
        assert_eq!(list.entries.len(), 2);
        let keys: Vec<_> = list.entries.iter().map(|entry| entry.key()).collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn rejects_bad_lines() {
        let error = Allowlist::parse("8.8.8.8\n10.0.0.0/33\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("larger than 32"), "{message}");
    }
}
