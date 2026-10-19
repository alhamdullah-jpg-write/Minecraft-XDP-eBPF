//! Userspace mirrors of the eBPF key/value structs from xdp/flow.h and
//! xdp/maps.h.
//!
//! Every struct here is `repr(C)` and has a size assertion mirroring the
//! `_Static_assert` in the C header, so a layout change on the kernel side
//! fails this build instead of silently corrupting map reads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya::Pod;

use crate::cidr::v4_mapped;

/// Monotonic nanoseconds - the same clock `bpf_ktime_get_ns()` uses, so this
/// is directly comparable with the `expires_ns`/`last_seen_ns` fields the
/// kernel writes into the block/egress maps.
pub fn now_ns() -> u64 {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: out-pointer to a valid timespec; CLOCK_MONOTONIC cannot fail
    // on Linux for a valid argument.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) };
    if result != 0 {
        return 0;
    }
    timespec.tv_sec as u64 * 1_000_000_000 + timespec.tv_nsec as u64
}

/// Address family byte of `struct host_key`/`struct flow_key`.
pub const FAM_V4: u8 = 4;
#[allow(dead_code)] // used by HostKey::from_ip, which tests exercise
pub const FAM_V6: u8 = 6;

/// Mirror of `struct host_key` (20 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HostKey {
    pub family: u8,
    pub pad: [u8; 3],
    /// IPv4 in the v4-mapped form, IPv6 raw.
    pub addr: [u8; 16],
}
// SAFETY: repr(C) struct with an explicit pad field, no implicit padding.
unsafe impl Pod for HostKey {}
const _: () = assert!(std::mem::size_of::<HostKey>() == 20);

impl HostKey {
    /// Builds the key for one address (`family` follows the address family).
    /// The packet path builds keys on its own; this is the userspace/test
    /// side of the same conversion.
    #[allow(dead_code)]
    pub fn from_ip(ip: IpAddr) -> HostKey {
        match ip {
            IpAddr::V4(v4) => HostKey {
                family: FAM_V4,
                pad: [0; 3],
                addr: v4_mapped(v4),
            },
            IpAddr::V6(v6) => HostKey {
                family: FAM_V6,
                pad: [0; 3],
                addr: v6.octets(),
            },
        }
    }

    /// The address this key refers to. The family byte wins; a v4-mapped
    /// address under `family == 6` is still rendered as IPv4 for logging.
    pub fn to_ip(&self) -> IpAddr {
        if self.family == FAM_V4 || crate::cidr::is_v4_mapped(&self.addr) {
            IpAddr::V4(Ipv4Addr::new(
                self.addr[12],
                self.addr[13],
                self.addr[14],
                self.addr[15],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.addr))
        }
    }
}

/// Mirror of `struct flow_key` (40 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub family: u8,
    pub proto: u8,
    pub pad: [u8; 2],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}
// SAFETY: repr(C) struct with explicit pad fields, no implicit padding.
unsafe impl Pod for FlowKey {}
const _: () = assert!(std::mem::size_of::<FlowKey>() == 40);

/// Mirror of `struct egress_value` (32 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressValue {
    pub base_seq: u64,
    pub next_seq: u64,
    pub last_seen_ns: u64,
    pub packets: u32,
    pub pad: u32,
}
// SAFETY: repr(C) struct of integers without padding.
unsafe impl Pod for EgressValue {}
const _: () = assert!(std::mem::size_of::<EgressValue>() == 32);

/// Mirror of `struct block_entry` (24 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockEntry {
    /// Ktime nanoseconds; 0 = permanent.
    pub expires_ns: u64,
    pub last_strike_ns: u64,
    pub strikes: u32,
    /// eBPF drop reason that created/last escalated the entry (informational).
    pub reason: u32,
}
// SAFETY: repr(C) struct of integers without padding.
unsafe impl Pod for BlockEntry {}
const _: () = assert!(std::mem::size_of::<BlockEntry>() == 24);

impl BlockEntry {
    /// A permanent operator blocklist entry.
    pub fn permanent() -> BlockEntry {
        BlockEntry::default()
    }

    /// A loader-inserted (ML) block: starts at strike 1 so the packet path
    /// counts it as a real block, and is bounded by `ttl_ns`.
    pub fn ttl(expires_ns: u64, reason: u32) -> BlockEntry {
        BlockEntry {
            expires_ns,
            last_strike_ns: 0,
            strikes: 1,
            reason,
        }
    }

    pub fn is_expired(&self, now_ns: u64) -> bool {
        self.expires_ns != 0 && now_ns >= self.expires_ns
    }
}

/// Mirror of `struct verified_entry` (32 bytes). The kernel-side `bpf_timer`
/// is kept as an opaque placeholder: the loader only ever reads the keys.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedEntry {
    pub timer: [u64; 2],
    pub last_seen_ns: u64,
    pub pad: u64,
}
// SAFETY: repr(C) struct of integers without padding.
unsafe impl Pod for VerifiedEntry {}
const _: () = assert!(std::mem::size_of::<VerifiedEntry>() == 32);

/// Mirror of `struct talker_entry` (40 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TalkerEntry {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub drops: u32,
    pub syns: u32,
}
// SAFETY: repr(C) struct of integers without padding.
unsafe impl Pod for TalkerEntry {}
const _: () = assert!(std::mem::size_of::<TalkerEntry>() == 40);

// drop reasons the loader itself writes into `block_entry.reason`
pub const REASON_AUTOBLOCK: u32 = 41; // DROP_AUTOBLOCK (xdp/stats.h)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_v4_uses_the_mapped_form() {
        let key = HostKey::from_ip("203.0.113.7".parse().unwrap());
        assert_eq!(key.family, FAM_V4);
        assert_eq!(&key.addr[..10], &[0u8; 10]);
        assert_eq!(&key.addr[10..], &[0xff, 0xff, 203, 0, 113, 7]);
        assert_eq!(key.to_ip(), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn host_key_v6_round_trips() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let key = HostKey::from_ip(ip);
        assert_eq!(key.family, FAM_V6);
        assert_eq!(key.to_ip(), ip);
    }

    #[test]
    fn block_entry_expiry() {
        let entry = BlockEntry::permanent();
        assert!(!entry.is_expired(u64::MAX));
        let entry = BlockEntry::ttl(1_000, REASON_AUTOBLOCK);
        assert!(!entry.is_expired(999));
        assert!(entry.is_expired(1_000));
        assert_eq!(entry.strikes, 1);
    }
}
