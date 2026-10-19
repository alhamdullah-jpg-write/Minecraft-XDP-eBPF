#!/usr/bin/env bash
#
# End-to-end test: loads the real eBPF object with every feature enabled,
# pushes real traffic through it across a veth pair and checks both what
# passes and what is dropped, plus the observability, blocklist and
# auto-blocking paths.
#
# The filter attaches to a veth in generic (skb) mode. Generic mode is a
# deliberate choice: it exists on every kernel/driver, so the test is about
# the filter's semantics, not about a driver's XDP support. The netns peer
# is a genuinely different host, so the stateful egress pinhole and the
# default-deny path behave like they do in production.
#
# Needs root (BPF, XDP, tc, netns) and python3.
#
#   sudo ./tests/e2e_loader.sh
#
# The release binary is used when present, the debug binary otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS="xdp-e2e"
HOST_IF="ve2e-host"   # filtered side, lives in the root namespace
PEER_IF="ve2e-peer"   # traffic source, lives in the netns
HOST_IP="10.99.0.1"
PEER_IP="10.99.0.2"
# a second peer address that never completes a minecraft login: the SYN flood
# and the ML scoring stage use it, so its source is unverified by definition
PEER_IP2="10.99.0.3"
METRICS_URL="http://127.0.0.1:19199/metrics"

if [[ "$(id -u)" != "0" ]]; then
    echo "e2e: must run as root (BPF, XDP, tc and netns)" >&2
    exit 2
fi
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null || {
    echo "e2e: python3 is required" >&2
    exit 2
}

BIN="${XDP_LOADER_BIN:-$ROOT/target/release/xdp-loader}"
# an explicitly given binary always wins; otherwise prefer release, but never
# a release build that is *older* than the debug one (testing a stale artifact
# is worse than testing the debug build)
if [[ -z "${XDP_LOADER_BIN:-}" && -x "$ROOT/target/debug/xdp-loader" ]] &&
    { [[ ! -x "$BIN" ]] || [[ "$ROOT/target/debug/xdp-loader" -nt "$BIN" ]]; }; then
    BIN="$ROOT/target/debug/xdp-loader"
fi
if [[ ! -x "$BIN" ]]; then
    echo "e2e: build the loader first (cargo build --release)" >&2
    exit 2
fi
echo "e2e: using loader binary $BIN"

WORK="$(mktemp -d /tmp/minecraft-xdp-e2e.XXXXXX)"
LOADER_PID=""
SERVER_PID=""
KEEP_WORK=0

cleanup() {
    if [[ -n "$LOADER_PID" ]] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    if [[ "$KEEP_WORK" == "1" ]]; then
        echo "e2e: work directory kept at $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

fail() {
    echo "e2e FAIL: $*" >&2
    KEEP_WORK=1
    exit 1
}

metric() {
    # sums every sample of one metric family (any label set, with or
    # without the prometheus _total suffix)
    curl -fsS "$METRICS_URL" 2>/dev/null |
        awk -v name="$1" '
            index($1, name) == 1 { sum += $2 }
            END { printf "%d", sum + 0 }'
}

drop_reason() {
    # counts one minecraft_drop_reason{reason="..."} sample
    curl -fsS "$METRICS_URL" 2>/dev/null |
        awk -v label="reason=\"$1\"" '
            index($1, "minecraft_drop_reason") == 1 && index($0, label) { sum += $2 }
            END { printf "%d", sum + 0 }'
}

wait_for() {
    # wait_for <seconds> <shell command...>
    local deadline=$((SECONDS + $1))
    shift
    while ((SECONDS < deadline)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

wait_value() {
    # wait_value <seconds> <metric> <expected value>
    local deadline=$((SECONDS + $1))
    local name="$2" want="$3"
    while ((SECONDS < deadline)); do
        if [[ "$(metric "$name")" == "$want" ]]; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

# ---------------------------------------------------------------- interfaces

ip netns del "$NS" 2>/dev/null || true
ip link del "$HOST_IF" 2>/dev/null || true
ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$PEER_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$PEER_IP2/24" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up
echo "e2e: veth pair up ($HOST_IF=$HOST_IP, $PEER_IF in netns $NS=$PEER_IP/$PEER_IP2)"

# ------------------------------------------------------------------- config

printf '203.0.113.7\n' >"$WORK/blocklist.txt"
printf '198.51.100.0/24\n' >"$WORK/allowlist.txt"

cat >"$WORK/e2e.toml" <<EOF
[filter]
start_port = 25565
end_port = 25565
host_connection_limit = 20
subnet_connection_limit = 0
global_connection_limit = 0
udp_packet_limit = 0
window_ms = 1000
player_idle_timeout_secs = 60
online_names = true
reject_proxy_header = true
verified_pps_limit = 100
verified_bps_limit = 65536
dry_run = false
drop_reserved_sources = true
drop_private_sources = false

[xdp]
mode = "skb"
max_pending_connections = 4096
max_player_connections = 4096
max_throttled_ips = 4096
max_throttled_subnets = 1024
max_rule_rate_entries = 1024
max_verified_sources = 1024
max_talkers = 4096
max_egress_flows = 4096
max_autoblock_entries = 4096
allowlist_file = "$WORK/allowlist.txt"
max_allowlist_entries = 16

[bedrock]
enabled = true
port = 19132
strict_protocol_version = false
mtu_min = 576
mtu_max = 1500

[voice]
enabled = true
port = 24454
require_verified_ip = false
max_packet_type = 63

[ingress]
default_deny = true
egress_tracking = true
egress_timeout_secs = 60
icmp = "smart"
open_tcp_ports = [25998]

[[rules]]
name = "stateful-echo"
proto = "udp"
port = 25997
action = "allow"
stateful = true

[blocklist]
blocklist_file = "$WORK/blocklist.txt"
max_entries = 1024
autoblock = true
autoblock_strikes = 1
autoblock_base_ttl_secs = 30
autoblock_max_ttl_secs = 300
autoblock_decay_secs = 600
export_file = "$WORK/blocked.txt"

[autotune]
enabled = true
dry_run = true
interval_ms = 1000
tighten_syn_per_sec = 5.0
relax_syn_per_sec = 1.0
state_file = "$WORK/autotune.toml"

[ml]
enabled = true
mode = "shadow"
interval_secs = 1
min_packet_rate = 20.0
threshold = 0.5
model_file = "$WORK/ml_model.toml"

[advisor]
enabled = true

[metrics]
enabled = true
addr = "127.0.0.1:19199"
poll_secs = 1

[logging]
level = "info"
EOF

# ------------------------------------------------------------- start loader

cd "$WORK"   # any log file the logger writes lands in the work directory
"$BIN" "$HOST_IF" --config "$WORK/e2e.toml" >"$WORK/loader.log" 2>&1 &
LOADER_PID=$!

if ! wait_for 30 grep -q "BPF program attached" "$WORK/loader.log"; then
    cat "$WORK/loader.log" >&2
    fail "the loader never attached"
fi
grep -q "Egress flow tracking attached" "$WORK/loader.log" ||
    fail "the tc egress program was not attached"
echo "e2e: loader attached (pid $LOADER_PID)"

if ! wait_for 10 curl -fsS "$METRICS_URL"; then
    fail "the metrics endpoint is not reachable"
fi

# the operator blocklist and allowlist are loaded before attaching
wait_value 10 minecraft_blocklist_entries 1 ||
    fail "blocklist gauge is $(metric minecraft_blocklist_entries), want 1"
wait_value 10 minecraft_allowlist_entries 1 ||
    fail "allowlist gauge is $(metric minecraft_allowlist_entries), want 1"

# ------------------------------------------------------------ traffic phase

"$PYTHON" "$ROOT/tests/e2e_traffic.py" server "$HOST_IP" "$PEER_IP" "$WORK/server.report" 8.0 &
SERVER_PID=$!
sleep 0.5

ip netns exec "$NS" "$PYTHON" "$ROOT/tests/e2e_traffic.py" client "$HOST_IP" "$WORK/client.report"
wait "$SERVER_PID" || true
SERVER_PID=""

must_pass() {
    # must_pass <file> <pattern> <description>
    grep -q "$2" "$1" || fail "$3 (missing '$2')"
}
must_drop() {
    # must_drop <file> <pattern> <description>
    if grep -q "$2" "$1"; then
        fail "$3 (found '$2')"
    fi
}

must_pass "$WORK/client.report" "^tcp 25565 ok" "a plain TCP handshake on the protected port did not complete"
must_pass "$WORK/client.report" "^tcp 25998 ok" "the explicitly opened port did not pass"
must_pass "$WORK/client.report" "^tcp 25999 timeout" "an unopened port was not dropped"

must_pass "$WORK/server.report" "^tcp 25565 accept" "the protected port never accepted"
must_pass "$WORK/server.report" "^tcp 25998 accept" "the open port never accepted"
must_drop "$WORK/server.report" "^tcp 25999" "the denied port accepted a connection"

must_pass "$WORK/server.report" "RAKOK123" "a valid raknet handshake did not reach the server"
must_drop "$WORK/server.report" "BEDGARBAGE" "raknet garbage was passed"
must_pass "$WORK/server.report" "VOICE-OK" "a valid voice packet did not reach the server"
must_drop "$WORK/server.report" "VOICE-NO" "a voice packet with an invalid type was passed"

must_drop "$WORK/server.report" "UNSOLICITED" "a stateful rule passed an untracked flow"
must_pass "$WORK/server.report" "PUNCHED" "the egress pinhole did not let the reply through"
must_drop "$WORK/server.report" "OTHERFLOW" "the egress pinhole matched the wrong flow"
# the client proves the ordering it observed: un-punched datagram before the
# server's punch, punched reply after it (no clock guesswork)
must_pass "$WORK/client.report" "^pinhole unpunched" "the un-punched test datagram was not sent before the punch"
must_pass "$WORK/client.report" "^pinhole punched" "the client never observed the server's punch marker"
must_drop "$WORK/client.report" "^pinhole RACE" "the un-punched datagram raced the server's punch"
must_drop "$WORK/client.report" "^pinhole TIMEOUT" "the server never punched the pinhole"
echo "e2e: pass/drop semantics verified"

# the drop reasons the traffic above produced
sleep 1
[[ "$(drop_reason bedrock_invalid)" -ge 1 ]] || {
    curl -fsS "$METRICS_URL" | grep -i bedrock || true
    fail "the bedrock_invalid drop reason is missing"
}
[[ "$(drop_reason bedrock_untracked)" -ge 1 ]] ||
    fail "the bedrock_untracked drop reason is missing"
[[ "$(drop_reason voice_invalid)" -ge 1 ]] || fail "the voice_invalid drop reason is missing"
[[ "$(drop_reason unsolicited)" -ge 2 ]] || fail "the unsolicited drop reason is missing"
[[ "$(metric minecraft_udp_packets)" -ge 3 ]] || fail "the udp packet counter did not move"

# crafted-shape probes and the abuse caps: the traffic classes behind the
# nullping / packet-spam probes, checked against both the report (nothing
# reached the listener) and the reason counters (each class has its own)
must_drop "$WORK/server.report" "PROXY" "a proxy-protocol header reached the server"
[[ "$(drop_reason proxy_untrusted)" -ge 2 ]] ||
    fail "the PROXY header injection was not dropped as proxy_untrusted"
[[ "$(drop_reason handshake_invalid)" -ge 4 ]] ||
    fail "the crafted handshake probes were not all dropped"
[[ "$(drop_reason legacy_ping)" -ge 1 ]] ||
    fail "the legacy ping probe was not dropped"
[[ "$(drop_reason mc_packet_rate)" -ge 1 ]] ||
    fail "the post-handshake packet flood was not capped"
# valid logins must still pass: the spam connection's login reaches the
# listener (and is only capped afterwards), so the parser and the login path
# are untouched by the abuse controls
must_pass "$WORK/server.report" "^tcp 25565 data .*flooder" \
    "a valid login was dropped instead of only capped"
# the login burst is the nullping class: above the per-source limit it must
# be shed by the connection limiter (which also strikes the source, so the
# burst's own later payloads are dropped by the auto-block - that is the
# intended escalating behavior, not a regression)
[[ "$(drop_reason throttle_limit)" -ge 1 ]] ||
    fail "the login burst did not trip the per-source connection limit"
# kept as an upper bound: before the burst only the status query and the
# spam connection complete (the crafted probes never reach the listener at
# all), so 30 more would be 32
accepts="$(grep -c "^tcp 25565 accept" "$WORK/server.report" || true)"
(( accepts < 32 )) ||
    fail "the login burst got every connection through the per-source limit (accepts=$accepts)"
echo "e2e: crafted probes and abuse caps verified"

# -------------------------------------------------- SIGHUP list reloading

printf '203.0.113.7\n203.0.113.8\n' >"$WORK/blocklist.txt"
kill -HUP "$LOADER_PID"
wait_for 10 grep -q "Blocklist reloaded" "$WORK/loader.log" || fail "SIGHUP reload did not happen"
wait_value 10 minecraft_blocklist_entries 2 ||
    fail "blocklist gauge is $(metric minecraft_blocklist_entries) after reload, want 2"
echo "e2e: SIGHUP reload verified"

# --------------------------------------------------- autoblock + export

ip netns exec "$NS" "$PYTHON" "$ROOT/tests/e2e_traffic.py" flood "$HOST_IP" \
    --source "$PEER_IP2" --count 300 --gap 0.002

[[ "$(drop_reason throttle_limit)" -ge 1 ]] ||
    fail "the SYN burst never hit the per-source limit"
if ! wait_for 25 grep -q "10.99.0.2" "$WORK/blocked.txt"; then
    fail "the login-burst source is not in the export file"
fi
# the SYN flood comes from the second peer address, which no login ever
# verified: it must be auto-blocked as well
if ! wait_for 25 grep -q "$PEER_IP2" "$WORK/blocked.txt"; then
    fail "the SYN-flood source is not in the export file"
fi
grep -q "strikes=" "$WORK/blocked.txt" || fail "the export file has no strike counter"
[[ "$(metric minecraft_autoblock_entries)" -ge 1 ]] || fail "no auto-block is active"
[[ "$(drop_reason autoblock)" -ge 1 ]] ||
    fail "the auto-blocked source was not dropped"
echo "e2e: auto-block + export verified"

# -------------------------------------------------- auto-tuner dry run

# the SYN burst is what the loop reacts to, so this check runs after the
# flood: the host limit must have been *logged* as changing, not changed
if ! wait_for 20 grep -q "Auto-tuner would change" "$WORK/loader.log"; then
    fail "the auto-tuner never logged a (dry-run) change"
fi
[[ "$(metric minecraft_limit_host_connections)" == "20" ]] ||
    fail "the dry-run auto-tuner changed the live host limit"
echo "e2e: auto-tuner dry run verified"

# the flood source is unverified, so the scorer must have scored it (shadow
# mode only logs). Kept as a warning: the threshold is a tunable heuristic,
# not a guarantee, and the model is trained from this run's labels.
if ! wait_for 15 grep -q "ML: $PEER_IP2" "$WORK/loader.log"; then
    grep "ML" "$WORK/loader.log" | tail -5 >&2 || true
    echo "e2e WARN: the ML scorer did not log a line for the flooding source" >&2
fi
[[ -s "$WORK/ml_model.toml" ]] || echo "e2e WARN: the ML model was not persisted" >&2
# expected: in dry-run mode the tuner applies nothing, and the state file only
# tracks *applied* limits
[[ -s "$WORK/autotune.toml" ]] || echo "e2e note: no auto-tuner state written (dry run)" >&2

# ---------------------------------------------------------- clean shutdown

kill "$LOADER_PID"
if ! wait_for 15 grep -q "Good bye!" "$WORK/loader.log"; then
    cat "$WORK/loader.log" >&2
    fail "the loader did not shut down cleanly"
fi
wait "$LOADER_PID" || fail "the loader exited with a non-zero status"
LOADER_PID=""

# the interface must be usable again: a second attach proves nothing leaked
"$BIN" "$HOST_IF" --config "$WORK/e2e.toml" >"$WORK/loader2.log" 2>&1 &
LOADER_PID=$!
if ! wait_for 30 grep -q "BPF program attached" "$WORK/loader2.log"; then
    cat "$WORK/loader2.log" >&2
    fail "the interface could not be attached a second time"
fi
kill "$LOADER_PID" 2>/dev/null || true
wait "$LOADER_PID" 2>/dev/null || true
LOADER_PID=""
echo "e2e: clean shutdown verified (second attach succeeded)"

echo "e2e PASS"
