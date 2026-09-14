#!/usr/bin/env python3
"""The FFXI world UDP relay must survive a ZERO-LENGTH datagram from the map.

Pins the 2026-08-23 FFXI-3001 wedge: LSB's map legally emits empty UDP
datagrams (map_networking.cpp `handle_incoming_packet` sends unconditionally
and several paths leave size 0), and the bridge's return-path thread treated
`recv() == b""` as EOF and died SILENTLY. From then on the c2s half kept
forwarding -- the map logged healthy `InsertPC` logins -- while every reply
queued unread on the dead flow's socket until SO_RCVBUF filled (measured live:
rx_queue 213,120 B, 22 drops in /proc/net/udp of the bridge container), and the
client heard nothing and raised FFXI-3001. Three of the evening's four drops
were exactly this.

Scenarios, each with the failure mode it pins:
  1. EMPTY DATAGRAM: map sends b"" then a real reply; the client must still
     receive the real reply (old code: return thread dead, reply never comes).
  2. SELF-HEAL: after the return path dies (upstream socket closed under it),
     the client's next datagram must rebuild the flow and traffic must round-
     trip again (old code: `peers` pinned the dead flow forever; only a bridge
     restart recovered).
  3. CAPTURE SURVIVES THE SELF-HEAL: a reaped flow's teardown runs LATE, after
     the client's next datagram has rebuilt the flow and opened a fresh world
     capture. The teardown must close its OWN capture, not its successor's --
     otherwise capture stops dead mid-session while the relay stays healthy,
     which reads as "the client went quiet". Same class of silent-blind-spot
     bug as scenario 1, in the instrument built to diagnose it.

Run from tools/: `python ffxi_udp_relay_check.py`. Exits non-zero on failure.
"""

import os
import shutil
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lsb"))

# The bridge module reads its config from env at import; keep it from writing
# packet dumps during the test (none of its sockets are opened at import time).
# The world capture is a separate knob -- scenario 3 exercises it, so point it
# at a scratch directory rather than the real logs tree.
os.environ["FFXI_PKT_DUMP"] = "0"
_CAPTMP = tempfile.mkdtemp(prefix="ffxi-relay-check-")
os.environ["FFXI_WORLD_CAP_DIR"] = _CAPTMP
import ffxi_bridge  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    # A fake map: plain UDP socket on loopback.
    fake_map = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fake_map.bind(("127.0.0.1", 0))
    map_port = fake_map.getsockname()[1]

    # Point the relay at it on an ephemeral port of its own. The relay binds
    # 0.0.0.0:BRIDGE_MAP, so pick a free port first.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    relay_port = probe.getsockname()[1]
    probe.close()

    ffxi_bridge.BRIDGE_MAP = relay_port
    ffxi_bridge.MAP_HOST = "127.0.0.1"
    ffxi_bridge.MAP_PORT = map_port
    threading.Thread(target=ffxi_bridge.udp_relay, daemon=True).start()
    time.sleep(0.2)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(2.0)

    # --- scenario 1: empty datagram must not kill the return path ----------
    client.sendto(b"hello-1", ("127.0.0.1", relay_port))
    pkt, up_addr = fake_map.recvfrom(65535)
    if pkt != b"hello-1":
        fail(f"map got {pkt!r}, want b'hello-1'")

    fake_map.sendto(b"", up_addr)          # the killer: a legal empty datagram
    fake_map.sendto(b"reply-1", up_addr)   # the reply the client must still get

    got = []
    try:
        while len(got) < 2:
            data, _ = client.recvfrom(65535)
            got.append(data)
    except socket.timeout:
        pass
    if b"reply-1" not in got:
        fail(f"client never received the reply after an empty datagram "
             f"(got {got!r}) -- the return-path thread died on b'' (the "
             f"2026-08-23 FFXI-3001 wedge)")
    if b"" not in got:
        fail(f"the empty datagram itself was not forwarded (got {got!r}); "
             f"the relay must be transparent, byte-for-byte")
    print("ok: empty datagram forwarded and the return path survived it")

    # --- scenario 2: a dead flow must self-heal on a later c2s datagram ----
    # Kill the map: the flow's connected socket now gets ICMP port-unreachable,
    # which surfaces as an exception on its recv (Linux ECONNREFUSED, Windows
    # WSAECONNRESET) or on a later send -- either of the fix's two teardown
    # paths must then reap the flow from _UDP_PEERS.
    if len(ffxi_bridge._UDP_PEERS) != 1:
        fail(f"expected exactly 1 relay flow, found {len(ffxi_bridge._UDP_PEERS)}")
    key = next(iter(ffxi_bridge._UDP_PEERS))
    fake_map.close()

    deadline = time.time() + 3.0
    while key in ffxi_bridge._UDP_PEERS and time.time() < deadline:
        client.sendto(b"poke", ("127.0.0.1", relay_port))  # provoke the ICMP
        time.sleep(0.1)
    if key in ffxi_bridge._UDP_PEERS:
        fail("dead flow was never removed from _UDP_PEERS -- the wedge would "
             "persist until a bridge restart, exactly the measured failure")

    # Bring the map back on the SAME port; the next datagram must rebuild the
    # flow and round-trip.
    fake_map2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fake_map2.settimeout(2.0)
    fake_map2.bind(("127.0.0.1", map_port))
    deadline = time.time() + 3.0
    pkt, up_addr2 = None, None
    while time.time() < deadline:
        client.sendto(b"hello-2", ("127.0.0.1", relay_port))
        try:
            pkt, up_addr2 = fake_map2.recvfrom(65535)
            if pkt == b"hello-2":
                break
        except socket.timeout:
            continue
    if pkt != b"hello-2":
        fail("client's datagram was not forwarded after flow teardown -- "
             "self-heal did not rebuild the upstream socket")
    fake_map2.sendto(b"reply-2", up_addr2)
    try:
        data = None
        deadline = time.time() + 2.0
        while time.time() < deadline:
            data, _ = client.recvfrom(65535)
            if data == b"reply-2":
                break
    except socket.timeout:
        pass
    if data != b"reply-2":
        fail(f"no reply over the rebuilt flow (last got {data!r}) -- return "
             f"path not restarted")
    print("ok: dead flow reaped and rebuilt; round trip works again")

    # --- scenario 3: a late teardown must not close its successor's capture --
    # Driven directly rather than through the sockets, because the race needs a
    # deterministic ordering: close(A) -> open(B) -> late close(A).
    victim = ("127.0.0.1", 59999)
    cap_a = ffxi_bridge.world_capture_open(victim)
    if cap_a is None:
        fail("world_capture_open returned nothing -- capture is off or unwritable")
    ffxi_bridge.world_capture_close(victim, cap_a)
    cap_b = ffxi_bridge.world_capture_open(victim)
    if cap_b is None or cap_b is cap_a:
        fail("reopening a capture for a rebuilt flow did not produce a new one")
    # The dead flow's udp_back finally, arriving late:
    ffxi_bridge.world_capture_close(victim, cap_a)
    if ffxi_bridge._WORLD_CAP.get(victim) is not cap_b:
        fail("a reaped flow's late teardown closed the REBUILT flow's capture -- "
             "evidence would stop silently mid-session")
    ffxi_bridge.world_capture(victim, "c2s", b"after-the-rebuild")
    if cap_b["n"] != 1:
        fail(f"capture stopped recording after the rebuild (n={cap_b['n']})")
    ffxi_bridge.world_capture_close(victim, cap_b)
    print("ok: late teardown closed its own capture, not the rebuilt flow's")

    shutil.rmtree(_CAPTMP, ignore_errors=True)
    print("PASS: ffxi_udp_relay_check")
    sys.exit(0)


if __name__ == "__main__":
    main()
