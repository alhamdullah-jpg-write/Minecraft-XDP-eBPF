#!/usr/bin/env python3
"""Traffic driver for tests/e2e_loader.sh.

The shell script puts the filtered interface on a veth pair and runs this
script in three roles:

  server    runs in the root namespace on the filtered side, binds one socket
            per feature port, writes everything that arrives to a report file
            and punches the stateful pinhole when the client asks it to.
  client    runs inside the network namespace on the peer side, walks a fixed
            timeline of connections/packets and records the outcomes in its
            own report file.
  flood     sends a burst of real SYNs from the netns peer (kernel stack).

The shell script then asserts on both reports and on the drop-reason
counters: a packet the filter should drop never shows up in the server
report, which is exactly what a peer sees.

The timeline is deliberately shaped like the traffic classes operators get
attacked with - including a valid-handshake "nullping"/login-slot burst and
a post-handshake packet flood on an already verified connection. Every stage
is bounded (fixed counts, short timeline, no loops) because this is a test
driver, not a traffic generator: it only ever runs against the namespace the
e2e script created. Needs python3 only, no third party modules.
"""

import argparse
import os
import select
import socket
import struct
import sys
import time

# the feature ports, mirrored from the generated config in e2e_loader.sh
MC_PORT = 25565
OPEN_TCP_PORT = 25998
DENIED_TCP_PORT = 25999
BEDROCK_PORT = 19132
VOICE_PORT = 24454
STATEFUL_UDP_PORT = 25997

# fixed client ports so the server can open the pinhole without coordination
PUNCH_SOURCE_PORT = 40001
OTHER_SOURCE_PORT = 40002

# the raknet unconnected-ping magic
RAKNET_MAGIC = bytes(
    [0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
     0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78]
)

# The pinhole punch is client-driven, not clock-driven: the server only sends
# its punch once the client has dropped a request marker, and the client only
# continues once the server has dropped its punched marker. Both roles run
# with the same working directory, so the ordering ("un-punched datagram is
# really sent before the punch") is proven by construction instead of hoping
# two processes' clocks agree.
REQUEST_PUNCH = "pinhole.request"  # client -> server: punch now
PUNCH_MARKER = "pinhole.punch"     # server -> client: punch sent

# a protocol version that exists in every client generation's window: the
# filter itself must not care about the value (see docs/threat-model.md)
MC_PROTOCOL = 763


def printable(data):
    """ASCII rendering of a payload so report lines stay greppable."""
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)


def mc_varint(value):
    """Minecraft VarInt (LEB128, 7 bits per byte, MSB = continuation)."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def mc_frame(payload):
    """[length varint][packet id + fields] framed like the real protocol."""
    return mc_varint(len(payload)) + payload


def mc_handshake(server_ip, next_state, host=None, protocol=MC_PROTOCOL):
    host = (host if host is not None else server_ip).encode()
    body = (
        mc_varint(protocol)
        + mc_varint(len(host))
        + host
        + struct.pack(">H", MC_PORT)
        + mc_varint(next_state)
    )
    return mc_frame(b"\x00" + body)


def mc_login_start(name, protocol=MC_PROTOCOL):
    """Login Start in the shape the given protocol era expects.

    the optional chat-key block exists for 759..760, the optional uuid flag
    for 760..763 and the mandatory uuid from 1.20.2 (764) on. The filter
    parses exactly this framing, so a packet that skips the era's fields is
    (correctly) rejected as malformed.
    """
    body = b"\x00" + mc_varint(len(name)) + name.encode()
    if 759 <= protocol < 761:
        body += b"\x00"  # has_public_key = false
    if protocol >= 760:
        if protocol >= 764:
            body += b"\x00" * 16  # mandatory uuid
        else:
            body += b"\x00"  # has_uuid = false
    return mc_frame(body)


def tcp_listener(bind_ip, port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, port))
    server.listen(64)
    return server


def udp_socket(bind_ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((bind_ip, port))
    return server


def tcp_read_burst(conn):
    """Everything the peer sent in one readiness burst, bounded by a short
    timeout so a partial segment never splits a report line."""
    conn.settimeout(0.05)
    chunks = []
    while True:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def run_server(bind_ip, client_ip, report_path, duration):
    report = open(report_path, "w", buffering=1)
    tcp = {tcp_listener(bind_ip, port): port for port in (MC_PORT, OPEN_TCP_PORT, DENIED_TCP_PORT)}
    udp = {udp_socket(bind_ip, port): port for port in (BEDROCK_PORT, VOICE_PORT, STATEFUL_UDP_PORT)}
    print(f"server listening on {bind_ip}", file=sys.stderr, flush=True)

    start = time.monotonic()
    punched = False
    data_conns = {}  # accepted connection -> its listener port
    listeners = list(tcp) + list(udp)
    while time.monotonic() - start < duration:
        readable, _, _ = select.select(listeners + list(data_conns), [], [], 0.1)
        for sock in readable:
            if sock in tcp:
                # accepted connections are kept open: a client that holds a
                # login slot (the nullping case) must be observable, and the
                # post-handshake flood needs a peer that does not close early
                conn, addr = sock.accept()
                print(f"tcp {tcp[sock]} accept {addr[0]}:{addr[1]}", file=report)
                try:
                    conn.sendall(b"hello\n")
                except OSError:
                    pass
                data_conns[conn] = tcp[sock]
            elif sock in udp:
                data, addr = sock.recvfrom(4096)
                print(f"udp {udp[sock]} {printable(data)}", file=report)
            else:
                port = data_conns[sock]
                data = tcp_read_burst(sock)
                if data:
                    print(f"tcp {port} data {printable(data)}", file=report)
                else:
                    sock.close()
                    del data_conns[sock]

        # punch the pinhole as soon as the client asks for it (see
        # pinhole_check): the client has proven the un-punched datagram was
        # sent before this point
        if not punched and os.path.exists(REQUEST_PUNCH):
            for sock in udp:
                if udp[sock] == STATEFUL_UDP_PORT:
                    sock.sendto(b"PUNCH", (client_ip, PUNCH_SOURCE_PORT))
            with open(PUNCH_MARKER, "w") as marker:
                marker.write("punched\n")
            print("server sent the pinhole punch", file=sys.stderr, flush=True)
            punched = True

    for conn in data_conns:
        conn.close()
    report.close()


def tcp_check(server_ip, report, port, timeout=1.0):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((server_ip, port))
        outcome = "ok"
        try:
            sock.recv(64)
        except OSError:
            pass
    except socket.timeout:
        outcome = "timeout"  # dropped: no syn-ack ever came back
    except ConnectionRefusedError:
        outcome = "refused"  # passed the filter, no listener behind it
    finally:
        sock.close()
    print(f"tcp {port} {outcome}", file=report, flush=True)


def mc_status_query(server_ip, report, timeout=1.5):
    """A real status query: handshake (next_state=1), status request, ping.

    A bare connect() is *not* enough behind this filter: the empty ACK that
    finishes the TCP handshake is swallowed on purpose and the backend only
    completes the connection once the first inspected data packet arrives.
    This is the minimal real client, and it is what makes the listener behind
    the filter accept at all.
    """
    sock = socket.socket()
    sock.settimeout(timeout)
    outcome = "ok"
    try:
        sock.connect((server_ip, MC_PORT))
        # handshake + status request in one segment (the parser handles that),
        # then the ping
        sock.sendall(mc_handshake(server_ip, 1) + mc_frame(b"\x00"))
        try:
            sock.recv(64)
        except OSError:
            pass
        sock.sendall(mc_frame(b"\x01" + b"\x00" * 8))
    except socket.timeout:
        outcome = "timeout"
    except OSError:
        outcome = "error"
    finally:
        sock.close()
    print(f"tcp {MC_PORT} {outcome}", file=report, flush=True)


def udp_send(server_ip, report, port, payload, source_port=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if source_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", source_port))
    sock.sendto(payload, (server_ip, port))
    sock.close()
    print(f"udp {port} sent {printable(payload)}", file=report, flush=True)


def rst_close(sock):
    """Close with RST (SO_LINGER 0) so nothing is held in TIME_WAIT."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def probe_malformed(server_ip, report):
    """One connection per crafted shape, sent as the first payload.

    These are the shapes a single-connection invalid-packet probe uses:
    a forwarded-header injection (both PROXY protocol versions), an invalid
    handshake next-state, an oversized hostname, an unterminated VarInt and
    a frame that claims to be huge but sends almost nothing, plus the legacy
    pre-1.7 ping. Each must be rejected by the parser with its own drop
    reason and must never reach the listener as data.
    """
    proxies = [
        ("proxy-v1", b"PROXY TCP4 1.2.3.4 10.99.0.1 12345 25565\r\n"
                      + mc_handshake(server_ip, 2)),
        # v2 signature (12 bytes) + a minimal v2 header with bogus fields
        ("proxy-v2", bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A,
                            0x51, 0x55, 0x49, 0x54, 0x0A])
                     + b"\x21\x11\x00\x0c" + b"\x00" * 12),
    ]
    crafted = [
        # next_state 3 is the "transfer" state of 1.20.5+; with a legacy
        # protocol number it can only be a wrapper-probing packet
        ("next-state-3", mc_handshake(server_ip, 3, protocol=47)),
        ("host-too-long", mc_handshake(server_ip, 2, host="a" * 1024)),
        ("varint-bomb", b"\x80\x80\x80\x80\x80\x01"),
        ("huge-length", b"\xff\xff\xff\x7f" + b"\x41" * 64),
        ("legacy-ping", b"\xfe\x01"),
    ]
    for name, payload in proxies + crafted:
        sock = socket.socket()
        sock.settimeout(1.0)  # the tcp handshake itself is fast on the veth
        try:
            sock.connect((server_ip, MC_PORT))
            sock.sendall(payload)
            # the reply would only come from a listener that accepted the
            # connection, which never happens for a dropped payload: keep the
            # timeout tiny so the sequential timeline is not stalled by the
            # (expected) silence
            sock.settimeout(0.05)
            try:
                sock.recv(64)  # a drop means nothing ever comes back
            except OSError:
                pass
        except OSError:
            pass
        rst_close(sock)
        print(f"probe {name}", file=report, flush=True)


def login_burst(server_ip, report, count=30, hold=0.3):
    """The "nullping" / login-slot shape: connection-per-join with a valid
    handshake and Login Start, random names, the slots held for a moment
    before RST. The point is the login *work* a real server has to do for
    every connection, at a rate above the per-source connection limit - the
    filter is expected to shed the excess (and to strike the source)."""
    sockets = []
    for _ in range(count):
        sock = socket.socket()
        sock.setblocking(False)
        sock.connect_ex((server_ip, MC_PORT))  # SYN only, completes later
        sockets.append(sock)

    # whatever finished the TCP handshake within the budget gets the login
    _, writable, _ = select.select([], sockets, [], 0.5)
    for index, sock in enumerate(writable):
        name = f"np{index:05d}"
        try:
            sock.setblocking(True)
            sock.sendall(mc_handshake(server_ip, 2) + mc_login_start(name))
        except OSError:
            pass

    time.sleep(hold)  # hold the login slots, like a real login flood does
    for sock in sockets:
        rst_close(sock)
    print(f"login burst {count} connections, {len(writable)} completed",
          file=sys.stderr, flush=True)
    print(f"login burst sent {count}", file=report, flush=True)


def verified_packet_flood(server_ip, report, packets=1000):
    """A connection the filter treats as verified (complete handshake + Login
    Start in one segment) that then floods the play state. The parser is
    intentionally blind here - this is exactly what the opt-in per-connection
    abuse cap is for."""
    sock = socket.socket()
    sock.settimeout(1.0)
    sock.connect((server_ip, MC_PORT))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # one write = one segment
    sock.sendall(mc_handshake(server_ip, 2) + mc_login_start("flooder"))
    blob = b"\x67" + b"\x00" * 15
    sent = 0
    try:
        for _ in range(packets):
            sock.sendall(blob)
            sent += 1
    except OSError:
        pass
    rst_close(sock)
    print(f"spam sent {sent}", file=sys.stderr, flush=True)
    print(f"spam sent {sent}", file=report, flush=True)


def pinhole_check(server_ip, report, wait_secs=10.0):
    """The stateful pinhole across both sides of the punch.

    Before the server has sent anything on the flow, a datagram from the
    client must be dropped ("UNSOLICITED"); after the server's punch, the
    reply on the same flow must pass ("PUNCHED"); a datagram from a *different*
    source port shares no flow and must still be dropped ("OTHERFLOW").

    The punch is requested by this side (REQUEST_PUNCH) and its completion is
    acknowledged through PUNCH_MARKER, so the order of the three datagrams is
    a property of the protocol, not of two processes' clocks.
    """
    if os.path.exists(PUNCH_MARKER):
        print("pinhole RACE", file=report, flush=True)
        return
    print("pinhole unpunched", file=report, flush=True)
    udp_send(server_ip, report, STATEFUL_UDP_PORT, b"UNSOLICITED", PUNCH_SOURCE_PORT)

    with open(REQUEST_PUNCH, "w") as request:
        request.write("punch\n")
    deadline = time.monotonic() + wait_secs
    while not os.path.exists(PUNCH_MARKER):
        if time.monotonic() > deadline:
            print("pinhole TIMEOUT", file=report, flush=True)
            return
        time.sleep(0.02)
    print("pinhole punched", file=report, flush=True)

    udp_send(server_ip, report, STATEFUL_UDP_PORT, b"PUNCHED", PUNCH_SOURCE_PORT)
    udp_send(server_ip, report, STATEFUL_UDP_PORT, b"OTHERFLOW", OTHER_SOURCE_PORT)


def run_client(server_ip, report_path):
    report = open(report_path, "w", buffering=1)
    raknet_ping = b"\x01" + b"RAKOK123" + RAKNET_MAGIC + b"\x00" * 8  # 33 bytes
    assert len(raknet_ping) == 33
    # same shape, corrupted magic: the stateless reject path without any state
    raknet_bad_magic = bytearray(raknet_ping)
    raknet_bad_magic[9] ^= 0xFF
    raknet_bad_magic = bytes(raknet_bad_magic)

    timeline = [
        (0.20, mc_status_query, (server_ip, report)),
        (0.50, tcp_check, (server_ip, report, OPEN_TCP_PORT)),
        (0.80, tcp_check, (server_ip, report, DENIED_TCP_PORT)),
        (1.00, probe_malformed, (server_ip, report)),
        (1.20, udp_send, (server_ip, report, BEDROCK_PORT, raknet_ping)),
        # a malformed *offline handshake* (id 0x01, corrupted magic): provably
        # garbage, rejected statelessly -> bedrock_invalid
        (1.40, udp_send, (server_ip, report, BEDROCK_PORT, raknet_bad_magic)),
        # an unknown shape from an untracked source: the stateless validator
        # cannot classify it, the stateful gate must -> bedrock_untracked
        (1.60, udp_send, (server_ip, report, BEDROCK_PORT, b"BEDGARBAGE")),
        (1.80, udp_send, (server_ip, report, VOICE_PORT, b"\x05VOICE-OK")),
        (2.00, udp_send, (server_ip, report, VOICE_PORT, b"\xffVOICE-NO")),
        # the pinhole stage requests the server's punch internally and waits
        # for the punched marker before sending the reply
        (2.20, pinhole_check, (server_ip, report)),
        # abuse caps: first a single verified connection flooding the play
        # state, then a burst of valid logins above the per-source limit
        (3.20, verified_packet_flood, (server_ip, report)),
        (4.40, login_burst, (server_ip, report)),
    ]

    start = time.monotonic()
    for at, action, args in timeline:
        delay = at - (time.monotonic() - start)
        if delay > 0:
            time.sleep(delay)
        action(*args)
    report.close()


def run_flood(server_ip, count, gap, source=None):
    """Real SYNs from the kernel stack: non-blocking connects on fresh
    sockets. More of them than any sane per-source limit, which is exactly
    how the kernel auto-blocker is supposed to fire. With --source they come
    from a secondary address of the peer, i.e. a source that never logged in
    (unverified), which is what the ML scoring stage wants to see."""
    sockets = []
    for _ in range(count):
        sock = socket.socket()
        sock.setblocking(False)
        if source:
            sock.bind((source, 0))
        sock.connect_ex((server_ip, MC_PORT))
        sockets.append(sock)
        if gap:
            time.sleep(gap)
    print(f"flood sent {len(sockets)} syns to {server_ip}:{MC_PORT} from {source or 'default'}",
          file=sys.stderr, flush=True)
    time.sleep(0.5)
    for sock in sockets:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="role", required=True)

    server = sub.add_parser("server")
    server.add_argument("bind_ip")
    server.add_argument("client_ip")
    server.add_argument("report")
    server.add_argument("duration", type=float)

    client = sub.add_parser("client")
    client.add_argument("server_ip")
    client.add_argument("report")

    flood = sub.add_parser("flood")
    flood.add_argument("server_ip")
    flood.add_argument("--count", type=int, default=300)
    flood.add_argument("--gap", type=float, default=0.002)
    flood.add_argument("--source", help="bind the SYNs to this local address")

    args = parser.parse_args()
    if args.role == "server":
        run_server(args.bind_ip, args.client_ip, args.report, args.duration)
    elif args.role == "client":
        run_client(args.server_ip, args.report)
    else:
        run_flood(args.server_ip, args.count, args.gap, args.source)


if __name__ == "__main__":
    main()
