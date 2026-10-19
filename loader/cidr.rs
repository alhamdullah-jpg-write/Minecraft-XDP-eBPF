//! Shared IPv4/IPv6 address and CIDR list parsing for the allowlist and the
//! operator blocklist.
//!
//! Both maps are LPM tries whose key is `struct lpm_key { u32 prefixlen;
//! u8 addr[16]; }` (xdp/flow.h). Addresses are stored in the same 16 byte
//! form the eBPF side uses: IPv6 as-is, IPv4 in the v4-mapped form
//! (`::ffff:a.b.c.d`), so one trie holds both families. An IPv4 CIDR
//! therefore becomes prefix length 96 + the IPv4 prefix length.

use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use aya::maps::lpm_trie::Key;

/// One address (or CIDR) in the on-the-wire 16 byte representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrEntry {
    /// Number of leading bits of `addr` that must match, 0..=128.
    pub prefix_len: u32,
    /// 16 byte address with the bits below `prefix_len` cleared.
    pub addr: [u8; 16],
}

impl CidrEntry {
    /// The exact-match entry for one address (`/32` or `/128`).
    #[allow(dead_code)] // the parse path covers the binary; tests use this
    pub fn host(addr: IpAddr) -> CidrEntry {
        match addr {
            IpAddr::V4(v4) => CidrEntry {
                prefix_len: 128,
                addr: v4_mapped(v4),
            },
            IpAddr::V6(v6) => CidrEntry {
                prefix_len: 128,
                addr: v6.octets(),
            },
        }
    }

    /// Parses `2001:db8::/32`, `10.0.0.0/8` or a bare address.
    pub fn parse(line: &str) -> Result<CidrEntry> {
        if line.contains(':') {
            let (addr, prefix_len) = match line.split_once('/') {
                Some((addr, prefix)) => (
                    Ipv6Addr::from_str(addr.trim())
                        .with_context(|| format!("invalid IPv6 address '{}'", addr.trim()))?,
                    Some(
                        prefix
                            .trim()
                            .parse::<u32>()
                            .with_context(|| format!("invalid prefix length '{}'", prefix.trim()))?,
                    ),
                ),
                None => (
                    Ipv6Addr::from_str(line).with_context(|| "invalid IPv6 address")?,
                    None,
                ),
            };
            let prefix_len = prefix_len.unwrap_or(128);
            if prefix_len > 128 {
                bail!("prefix length {prefix_len} is larger than 128");
            }
            let mut bytes = addr.octets();
            clear_bits(&mut bytes, prefix_len);
            Ok(CidrEntry {
                prefix_len,
                addr: bytes,
            })
        } else {
            let (addr, prefix_len) = match line.split_once('/') {
                Some((addr, prefix)) => (
                    Ipv4Addr::from_str(addr.trim())
                        .with_context(|| format!("invalid IPv4 address '{}'", addr.trim()))?,
                    Some(
                        prefix
                            .trim()
                            .parse::<u32>()
                            .with_context(|| format!("invalid prefix length '{}'", prefix.trim()))?,
                    ),
                ),
                None => (
                    Ipv4Addr::from_str(line).with_context(|| "invalid IPv4 address")?,
                    None,
                ),
            };
            let prefix_len = prefix_len.unwrap_or(32);
            if prefix_len > 32 {
                bail!("prefix length {prefix_len} is larger than 32");
            }
            let mut bytes = v4_mapped(addr);
            clear_bits(&mut bytes, 96 + prefix_len);
            Ok(CidrEntry {
                prefix_len: 96 + prefix_len,
                addr: bytes,
            })
        }
    }

    /// LPM key for this entry, ready for `allowlist_map`/`blocklist_map`.
    pub fn key(&self) -> Key<[u8; 16]> {
        Key::new(self.prefix_len, self.addr)
    }

    /// Renders the entry in the file format (IPv4 as `a.b.c.d/len`).
    pub fn display(&self) -> String {
        let mapped = is_v4_mapped(&self.addr);
        if mapped {
            let v4 = Ipv4Addr::new(self.addr[12], self.addr[13], self.addr[14], self.addr[15]);
            if self.prefix_len == 128 {
                v4.to_string()
            } else {
                format!("{v4}/{}", self.prefix_len - 96)
            }
        } else {
            let v6 = Ipv6Addr::from(self.addr);
            if self.prefix_len == 128 {
                v6.to_string()
            } else {
                format!("{v6}/{}", self.prefix_len)
            }
        }
    }
}

/// A parsed list of entries, deduplicated and sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrList {
    pub entries: Vec<CidrEntry>,
}

impl CidrList {
    /// Parses the text format (one address or CIDR per line, `#` comments
    /// and blank lines ignored). All errors carry `line N: ...` positions,
    /// and up to ten samples are reported so a typo does not require one
    /// restart per fix.
    pub fn parse(contents: &str) -> Result<CidrList> {
        let mut entries = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for (index, raw_line) in contents.lines().enumerate() {
            let line = raw_line
                .split_once('#')
                .map_or(raw_line, |(before, _)| before)
                .trim();
            if line.is_empty() {
                continue;
            }
            match CidrEntry::parse(line) {
                Ok(entry) => entries.push(entry),
                Err(error) => errors.push(format!("line {}: {error:#}", index + 1)),
            }
        }

        if !errors.is_empty() {
            let shown = errors.iter().take(10).cloned().collect::<Vec<_>>();
            let more = errors.len().saturating_sub(shown.len());
            let mut message = format!(
                "{} invalid entr{}:\n  {}",
                errors.len(),
                if errors.len() == 1 { "y" } else { "ies" },
                shown.join("\n  ")
            );
            if more > 0 {
                let _ = write!(message, "\n  ... and {more} more");
            }
            bail!("{message}");
        }

        entries.sort_by_key(|entry| (entry.prefix_len, entry.addr));
        entries.dedup();
        Ok(CidrList { entries })
    }

    /// Reads and parses `path`; the returned error names the file.
    pub fn load(path: &Path) -> Result<CidrList> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        CidrList::parse(&contents)
            .with_context(|| format!("failed to parse '{}'", path.display()))
    }
}

/// The `::ffff:a.b.c.d` 16 byte form of an IPv4 address.
pub fn v4_mapped(addr: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    bytes[12..].copy_from_slice(&addr.octets());
    bytes
}

/// True when the 16 bytes are the v4-mapped form.
pub fn is_v4_mapped(bytes: &[u8; 16]) -> bool {
    bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff
}

/// Clears every bit at or after `prefix_len`.
fn clear_bits(bytes: &mut [u8; 16], prefix_len: u32) {
    for index in 0..128u32 {
        if index >= prefix_len {
            bytes[(index / 8) as usize] &= !(0x80u8 >> (index % 8));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> CidrList {
        CidrList::parse(text).expect("list parses")
    }

    #[test]
    fn parses_ipv4_addresses_and_cidrs() {
        let list = parse("8.8.8.8\n10.0.0.0/8\n192.168.1.0/24  # trailing comment\n");
        assert_eq!(
            list.entries,
            vec![
                CidrEntry::parse("10.0.0.0/8").unwrap(),
                CidrEntry::parse("192.168.1.0/24").unwrap(),
                CidrEntry::host("8.8.8.8".parse().unwrap()),
            ]
        );
        // v4 entries are v4-mapped with the 96 bit prefix
        let entry = list.entries[0];
        assert_eq!(entry.prefix_len, 104); // 96 + 8
        assert!(is_v4_mapped(&entry.addr));
        assert_eq!(&entry.addr[12..], &[10, 0, 0, 0]);
    }

    #[test]
    fn parses_ipv6_addresses_and_cidrs() {
        let exact = CidrEntry::parse("2001:db8::1").unwrap();
        assert_eq!(exact.prefix_len, 128);
        let cidr = CidrEntry::parse("2001:db8::/32").unwrap();
        assert_eq!(cidr.prefix_len, 32);
        assert_eq!(&cidr.addr[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        let loopback = CidrEntry::parse("::1").unwrap();
        assert_eq!(loopback.addr[15], 1);
        assert!(!is_v4_mapped(&loopback.addr));
    }

    #[test]
    fn clears_bits_below_the_prefix() {
        let list = parse("10.1.2.3/8\n172.16.5.5/12\n2001:db8:ffff::1/32\n0.0.0.0/0\n");
        let find = |text: &str| {
            *list
                .entries
                .iter()
                .find(|entry| entry == &&CidrEntry::parse(text).unwrap())
                .expect("entry present")
        };
        assert_eq!(find("10.0.0.0/8").addr[12], 10);
        assert_eq!(find("10.0.0.0/8").addr[13], 0);
        assert_eq!(find("172.16.0.0/12").addr[13], 16);
        let v6 = find("2001:db8::/32");
        assert_eq!(&v6.addr[4..], &[0u8; 12]);
        // /0 keeps the v4-mapped prefix (prefixlen 96 = "any v4 address")
        let any_v4 = find("0.0.0.0/0");
        assert_eq!(any_v4.prefix_len, 96);
        assert_eq!(any_v4.addr, v4_mapped(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn collapses_duplicates() {
        let list = parse("10.0.0.0/8\n10.0.0.1/8\n10.0.0.0/8\n");
        assert_eq!(list.entries.len(), 1);
    }

    #[test]
    fn rejects_bad_lines_with_line_numbers() {
        for (text, needle) in [
            ("8.8.8.8\n10.0.0.0/33\n", "larger than 32"),
            ("8.8.8.8\n2001:db8::/129\n", "larger than 128"),
            ("8.8.8.8\nnot-an-ip\n", "invalid IPv4"),
            ("8.8.8.8\n300.1.2.3\n", "line 2"),
            ("8.8.8.8\n10.0.0.1/abc\n", "prefix length"),
        ] {
            let error = CidrList::parse(text).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(needle), "'{needle}' missing from: {message}");
        }
    }

    #[test]
    fn displays_entries_like_the_file_format() {
        assert_eq!(CidrEntry::parse("10.0.0.0/8").unwrap().display(), "10.0.0.0/8");
        assert_eq!(CidrEntry::parse("8.8.8.8").unwrap().display(), "8.8.8.8");
        assert_eq!(
            CidrEntry::parse("2001:db8::/32").unwrap().display(),
            "2001:db8::/32"
        );
        assert_eq!(CidrEntry::parse("::1").unwrap().display(), "::1");
    }

    #[test]
    fn accepts_empty_input() {
        assert_eq!(parse(""), CidrList::default());
        assert_eq!(parse("# only comments\n\n"), CidrList::default());
    }
}
