//! Source address allowlist.
//!
//! The list is a plain text file (one IPv4 address or CIDR per line, `#`
//! comments and blank lines ignored), parsed here and pushed into the
//! `allowlist_map` LPM trie of the eBPF program. The map is consulted before
//! any other check for traffic on the filtered ports, so allowlisted sources
//! skip the SYN throttle and the connection tracking entirely.
//!
//! The file is read at startup (a broken file stops the loader instead of
//! silently filtering everything) and re-read on SIGHUP. See the warning in
//! the default config: allowlisting a source only makes sense when the
//! upstream filters spoofed source addresses (uRPF/BCP38), otherwise an
//! attacker can impersonate an allowlisted address.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use log::{error, info};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;

use crate::config::Config;
use crate::metrics::ALLOWLIST_ENTRIES;
use crate::shutdown::Shutdown;

/// Map type must match the `allowlist_map` definition in
/// xdp/minecraft_filter.c: `struct lpm_key_v4 { __u32 prefixlen; __u32 addr; }`
/// as the key and `__u8` (1) as the value. aya's `Key<u32>` is exactly
/// `prefix_len` followed by the network order address, and
/// `u32::to_be()` reproduces the byte layout of `ip->saddr` the eBPF side
/// compares against.
type AllowlistMap = LpmTrie<MapData, u32, u8>;

/// One parsed allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Number of leading bits of `addr` that must match, 0..=32.
    pub prefix_len: u32,
    /// Address in network byte order (as it appears in the packet), with the
    /// bits below `prefix_len` cleared.
    pub addr: u32,
}

impl Entry {
    fn display(&self) -> String {
        let addr = Ipv4Addr::from(u32::from_be(self.addr));
        if self.prefix_len == 32 {
            addr.to_string()
        } else {
            format!("{addr}/{}", self.prefix_len)
        }
    }
}

/// A parsed allowlist file, ready to be pushed into the map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    pub entries: Vec<Entry>,
}

impl Allowlist {
    /// Parses the text format. `line N: ...` errors point at the offending
    /// line, and up to a few sample errors are reported so a typo does not
    /// require one restart per fix.
    pub fn parse(contents: &str) -> Result<Allowlist> {
        let mut entries = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for (index, raw_line) in contents.lines().enumerate() {
            // strip comments, then whitespace; this also allows trailing
            // comments after an entry
            let line = raw_line
                .split_once('#')
                .map_or(raw_line, |(before, _)| before)
                .trim();
            if line.is_empty() {
                continue;
            }

            let parsed = (|| -> Result<Entry> {
                if line.contains(':') {
                    bail!(
                        "'{line}' looks like an IPv6 address; the filter is IPv4-only \
                         (see docs/roadmap.md)"
                    );
                }
                let (addr, prefix_len) = match line.split_once('/') {
                    Some((addr, prefix)) => {
                        let addr = Ipv4Addr::from_str(addr.trim())
                            .with_context(|| format!("invalid IPv4 address '{}'", addr.trim()))?;
                        let prefix_len: u32 = prefix
                            .trim()
                            .parse()
                            .with_context(|| format!("invalid prefix length '{}'", prefix.trim()))?;
                        if prefix_len > 32 {
                            bail!("prefix length {prefix_len} is larger than 32");
                        }
                        (addr, prefix_len)
                    }
                    None => (
                        Ipv4Addr::from_str(line).with_context(|| "invalid IPv4 address")?,
                        32,
                    ),
                };
                // clear the bits below the prefix so a /8 lists as a network
                // address, and duplicate spellings of one prefix collapse
                let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
                Ok(Entry {
                    prefix_len,
                    addr: (u32::from(addr) & mask).to_be(),
                })
            })();

            match parsed {
                Ok(entry) => entries.push(entry),
                Err(error) => errors.push(format!("line {}: {error:#}", index + 1)),
            }
        }

        if !errors.is_empty() {
            let shown = errors.iter().take(10).cloned().collect::<Vec<_>>();
            let more = errors.len().saturating_sub(shown.len());
            let mut message = format!(
                "{} invalid allowlist entr{}:\n  {}",
                errors.len(),
                if errors.len() == 1 { "y" } else { "ies" },
                shown.join("\n  ")
            );
            if more > 0 {
                message.push_str(&format!("\n  ... and {more} more"));
            }
            bail!("{message}");
        }

        entries.sort_by_key(|entry| (entry.prefix_len, u32::from_be(entry.addr)));
        entries.dedup();
        Ok(Allowlist { entries })
    }

    /// Reads and parses `path`.
    pub fn load(path: &Path) -> Result<Allowlist> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read allowlist file '{}'", path.display()))?;
        Allowlist::parse(&contents)
            .with_context(|| format!("failed to parse allowlist file '{}'", path.display()))
    }

    /// Replaces the map contents with this list and returns the entry count.
    ///
    /// Old entries are removed first so shrinking the file actually takes
    /// effect. A failure halfway through leaves a partial list behind; the
    /// caller must treat the map as unusable in that case.
    pub fn apply(&self, map: &mut AllowlistMap) -> Result<usize> {
        let stale: Vec<Key<u32>> = map.keys().filter_map(|key| key.ok()).collect();
        for key in stale {
            map.remove(&key)
                .context("failed to remove an existing allowlist entry")?;
        }
        for entry in &self.entries {
            map.insert(&Key::new(entry.prefix_len, entry.addr), 1u8, 0)
                .with_context(|| {
                    format!(
                        "failed to insert allowlist entry {} (raise [xdp] max_allowlist_entries?)",
                        entry.display()
                    )
                })?;
        }
        Ok(self.entries.len())
    }
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
    let count = allowlist.apply(&mut map)?;
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
                        allowlist.apply(&mut map)
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

    fn parse(text: &str) -> Allowlist {
        Allowlist::parse(text).expect("allowlist parses")
    }

    #[test]
    fn parses_addresses_and_cidrs() {
        let list = parse(
            "\
# servers\n\
8.8.8.8\n\
10.0.0.0/8\n\
192.168.1.0/24  # trailing comment\n\
\n\
   203.0.113.7   \n",
        );
        assert_eq!(
            list.entries,
            vec![
                Entry { prefix_len: 8, addr: u32::from(Ipv4Addr::new(10, 0, 0, 0)).to_be() },
                Entry { prefix_len: 24, addr: u32::from(Ipv4Addr::new(192, 168, 1, 0)).to_be() },
                Entry { prefix_len: 32, addr: u32::from(Ipv4Addr::new(8, 8, 8, 8)).to_be() },
                Entry { prefix_len: 32, addr: u32::from(Ipv4Addr::new(203, 0, 113, 7)).to_be() },
            ]
        );
    }

    #[test]
    fn clears_bits_below_the_prefix() {
        let list = parse("10.1.2.3/8\n172.16.5.5/12\n0.0.0.0/0\n");
        let entry = |prefix_len| {
            list.entries
                .iter()
                .find(|entry| entry.prefix_len == prefix_len)
                .expect("entry present")
        };
        assert_eq!(
            entry(8).addr,
            u32::from(Ipv4Addr::new(10, 0, 0, 0)).to_be()
        );
        assert_eq!(
            entry(12).addr,
            u32::from(Ipv4Addr::new(172, 16, 0, 0)).to_be()
        );
        assert_eq!(entry(0).addr, 0);
    }

    #[test]
    fn collapses_duplicates() {
        let list = parse("10.0.0.0/8\n10.0.0.1/8\n10.0.0.0/8\n");
        assert_eq!(list.entries.len(), 1);
    }

    #[test]
    fn rejects_bad_lines_with_line_numbers() {
        let error = Allowlist::parse("8.8.8.8\n10.0.0.0/33\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("larger than 32"), "{message}");
    }

    #[test]
    fn rejects_ipv6_with_a_pointer_to_the_roadmap() {
        let error = Allowlist::parse("2001:db8::1\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("IPv6"), "{message}");
        assert!(message.contains("line 1"), "{message}");
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["not-an-ip", "300.1.2.3", "10.0.0.1/", "10.0.0.1/abc", "/8"] {
            assert!(
                Allowlist::parse(bad).is_err(),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn accepts_empty_input() {
        assert_eq!(parse(""), Allowlist::default());
        assert_eq!(parse("# only comments\n\n"), Allowlist::default());
    }
}
