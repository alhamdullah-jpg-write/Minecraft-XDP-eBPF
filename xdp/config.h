#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

/*
 * Runtime configuration.
 *
 * The Rust loader patches these values into the BPF .rodata section via
 * aya's set_global() (with must_exist) before the program is loaded, so all
 * of them are always overridden; the zeros are only placeholders. The types
 * must match the set_global() calls in loader/ebpf.rs exactly. Loaded
 * standalone (without the loader), the all-zero config filters nothing.
 *
 * Every flag below is `volatile const`, so the verifier knows its value at
 * load time and removes the disabled feature from the program entirely: an
 * option that is off costs nothing at runtime.
 *
 * Defining (not just declaring) these in a header is safe because the BPF
 * program is a single translation unit; the test build replaces this header
 * entirely via its include guard.
 */
volatile const __u8 PROMETHEUS = 0;           // collect statistics in stats_map
volatile const __u8 ONLINE_NAMES = 0;         // enforce online-mode usernames (max 16 chars)
volatile const __u8 DRY_RUN = 0;              // count would-be drops but pass the packets instead
volatile const __u8 DROP_RESERVED_SOURCES = 0; // drop 0/8, 169.254/16, 224/4, 240/4 sources
volatile const __u8 DROP_PRIVATE_SOURCES = 0;  // also drop RFC1918, loopback and CGNAT sources
volatile const __u8 ALLOWLIST_ENABLED = 0;     // consult allowlist_map for the filtered ports
volatile const __u32 START_PORT = 0;          // first TCP port of the filtered range (inclusive)
volatile const __u32 END_PORT = 0;            // last TCP port of the filtered range (inclusive)
volatile const __u32 HIT_COUNT = 0;           // max SYNs per source ip per window, 0 disables the throttle
volatile const __u64 HIT_COUNT_RESET_NS = 0;  // throttle window length in nanoseconds
volatile const __u64 PLAYER_IDLE_NS = 0;      // idle check interval for verified connections in nanoseconds;
                                              // entries are removed after one to two intervals without packets

#endif
