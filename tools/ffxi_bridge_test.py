#!/usr/bin/env python3
"""The FFXI bridge's pairing and attribution logic, driven offline.

WHAT THIS PINS
--------------
`lsb/ffxi_bridge.py` is a relay whose one job beyond copying bytes is to keep
POL Content IDs and LSB charids paired, and to know WHICH POL member launched.
Four defects were found by driving its own functions with synthetic packets --
none had been seen live, because the paths had never been exercised:

  1. **A second character SWAPPED Content IDs with the first.** The client
     names the Content ID on both `0x22` and `0x21` (packet captures
     show it), so the pending list grew two entries; the next
     `0x20` handed the first entry to slot 0 -- the EXISTING character -- and
     `content_id_for` rebound it. The new character was then refused as a
     duplicate, served untranslated (POL-0001 for that session), and on the
     client's own refetch inherited the freed old id. The client keeps macros
     under `USER/<hexid>/`, so the swap silently loses both characters' files.
  2. **A relaunch went to the other signed-in player.** A POL session was
     claimed one-shot on the premise that it launches FFXI once; after any
     drop the same Viewer relaunches, finds its own session claimed and sorted
     last, and gets whichever OTHER member is signed in.
  3. **The account map was written before the create was attempted**, so one
     unreachable LSB at a member's first launch wedged that member for good.
  4. **A refused delete re-paired the character to the lowest free id**, not
     the one it had -- another silent `USER/<hexid>/` move.

Plus the per-connection keying: companion, pending-create and swallow state
were keyed by client IP, so two players behind one router replaced each
other's LSB data session.

Run from tools/: `python ffxi_bridge_test.py`. Exits non-zero on failure. No
network, no LSB, no containers: every LSB call is stubbed.
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="ffxi-bridge-test-")
os.environ["FFXI_IDMAP_FILE"] = os.path.join(TMP, "ffxi_idmap.json")
os.environ["FFXI_ACCTMAP_FILE"] = os.path.join(TMP, "ffxi_accounts.json")
os.environ["POL_AUTH_SESSIONS"] = os.path.join(TMP, "auth-sessions.json")
os.environ["FFXI_PKT_DUMP"] = "0"
os.environ["FFXI_WORLD_CAPTURE"] = "0"
sys.path.insert(0, os.path.join(HERE, os.pardir, "lsb"))
import ffxi_bridge as B  # noqa: E402

FAILS = []


def check(cond, what):
    print(f"  {'OK  ' if cond else 'FAIL'} {what}")
    if not cond:
        FAILS.append(what)


def reset(pool):
    # getattr: an older bridge lacks some of these, and this test
    # must reach its logic checks against that code to prove it discriminates.
    for name in ("_idmap", "_charnames", "_worldfields", "_released_ids",
                 "_pending_create", "_create_pending", "_swallow_charlist",
                 "_claimed_sids"):
        getattr(B, name, {}).clear()
    B.pol_content_ids = lambda member_id=None: list(pool)


def c2s(cmd, cid, name=b""):
    p = bytearray(96)
    struct.pack_into("<I", p, 0, 96)
    p[4:8] = b"IXFF"
    p[8] = cmd
    struct.pack_into("<I", p, 28, cid)
    p[32:32 + len(name)] = name
    return bytes(p)


def s2c_20(chars):
    """A 0x20 char list: [(charid, name)] in LSB's slot order."""
    n = len(chars)
    size = 28 + 4 + 140 * n
    p = bytearray(size)
    struct.pack_into("<I", p, 0, size)
    p[4:8] = b"IXFF"
    p[8] = 0x20
    struct.pack_into("<I", p, 28, n)
    for i, (cid, nm) in enumerate(chars):
        off = 32 + i * 140
        struct.pack_into("<I", p, off, cid)
        struct.pack_into("<H", p, off + 4, cid & 0xFFFF)
        p[off + 12:off + 12 + len(nm)] = nm
    return bytes(p)


def served(pkt):
    n = struct.unpack_from("<I", pkt, 28)[0]
    return [struct.unpack_from("<I", pkt, 32 + i * 140)[0] for i in range(n)]


def s2c(pkt, member, ckey):
    """rewrite_s2c with the connection key; the pre-fix bridge has no such
    parameter, and the negative control must still reach the logic checks."""
    try:
        return B.rewrite_s2c(pkt, "s->c", member, ckey)
    except TypeError:
        return B.rewrite_s2c(pkt, "s->c", member)


def create(ckey, cid, name, member):
    """The client's create sequence as the captures show it: 0x22 then 0x21,
    both naming the Content ID of the empty slot it was shown."""
    B.rewrite_c2s(c2s(0x22, cid, name), "c->s", member, ckey)
    B.rewrite_c2s(c2s(0x21, cid, name), "c->s", member, ckey)


# ---------------------------------------------------------------------------
print("1. A SECOND CHARACTER KEEPS THE FIRST ONE'S CONTENT ID WHERE IT IS")
reset([30000100, 30000101, 30000102, 30000103])
K = "192.0.2.5:50001"
out = s2c(s2c_20([(1, b"First")]), 5, K)
check(served(out) == [30000100], f"first login pairs charid 1 -> 30000100 ({served(out)})")
create(K, 30000101, b"Second", 5)
# The early char list the bridge asks for after the create ACK, then the
# client's own refetch -- both carry the existing character in slot 0.
out = s2c(s2c_20([(1, b"First"), (2, b"Second")]), 5, K)
check(served(out) == [30000100, 30000101],
      f"post-create list keeps First=30000100 and pairs Second=30000101 ({served(out)})")
check(B._idmap == {"1": 30000100, "2": 30000101}, f"idmap is {B._idmap}")
out = s2c(s2c_20([(1, b"First"), (2, b"Second")]), 5, K)
check(served(out) == [30000100, 30000101], "the refetch serves the same pairing")
check(B._pending_create == {}, "no pending id is left behind to hit a later list")

print("   ...and a THIRD on a two-character account (the middle one used to be POL-0001)")
create(K, 30000102, b"Third", 5)
out = s2c(s2c_20([(1, b"First"), (2, b"Second"), (3, b"Third")]), 5, K)
check(served(out) == [30000100, 30000101, 30000102],
      f"three characters, three stable ids ({served(out)})")

# ---------------------------------------------------------------------------
print("2. TWO CONNECTIONS CREATING AT ONCE DO NOT TRADE IDS")
reset([30000200, 30000201, 30000300, 30000301])
B.pol_content_ids = lambda member_id=None: ({6: [30000200, 30000201],
                                              7: [30000300, 30000301]}[member_id])
KA, KB = "192.0.2.6:50002", "192.0.2.7:50003"
create(KA, 30000200, b"Alpha", 6)
create(KB, 30000300, b"Beta", 7)
outb = s2c(s2c_20([(11, b"Beta")]), 7, KB)     # B's list lands first
outa = s2c(s2c_20([(10, b"Alpha")]), 6, KA)
check(served(outb) == [30000300] and served(outa) == [30000200],
      f"each connection's named id went to its own charid ({served(outa)}, {served(outb)})")

# ---------------------------------------------------------------------------
print("3. A RELAUNCH FROM THE SAME VIEWER STAYS ON ITS OWN MEMBER")
reset([])
now = time.time()


def sessions(**ents):
    json.dump(ents, open(os.environ["POL_AUTH_SESSIONS"], "w"))


sessions(uAAAA={"member_id": 1, "peer_ip": "192.0.2.1", "at": now - 30, "chars_at": now - 20, "viewer_open": True},
         uBBBB={"member_id": 2, "peer_ip": "192.0.2.2", "at": now - 25, "chars_at": now - 15, "viewer_open": True})
check(B.resolve_pol_member("192.0.2.1")[0] == 1, "A's first launch -> member 1")
check(B.resolve_pol_member("192.0.2.2")[0] == 2, "B's first launch -> member 2")
m, how = B.resolve_pol_member("192.0.2.1")
check(m == 1, f"A RELAUNCHES (after a drop) -> member 1, not B ({m}: {how})")
check("deterministic" in how, "...and it is the address match, not a heuristic")

print("   ...and two Viewers behind ONE address are told apart by the claim")
B._claimed_sids.clear()
sessions(uAAAA={"member_id": 1, "peer_ip": "192.0.2.9", "at": now - 30, "chars_at": now - 20, "viewer_open": True},
         uBBBB={"member_id": 2, "peer_ip": "192.0.2.9", "at": now - 25, "chars_at": now - 15, "viewer_open": True})
first = B.resolve_pol_member("192.0.2.9")[0]
second = B.resolve_pol_member("192.0.2.9")[0]
check({first, second} == {1, 2}, f"two launches from one NAT reach two members ({first}, {second})")

# ---------------------------------------------------------------------------
print("4. A REFUSED DELETE RE-PAIRS THE CHARACTER TO THE ID IT HAD")
reset([30000400, 30000401, 30000402])
K = "192.0.2.8:50004"
B._idmap.update({"1": 30000401})          # 30000400 is free and LOWER
pkt = B.rewrite_c2s(c2s(0x14, 30000401), "c->s", 8, K)
check(struct.unpack_from("<I", pkt, 28)[0] == 1, "0x14 delete translated to charid 1")
check("1" not in B._idmap, "the pairing is released on the delete request")
out = s2c(s2c_20([(1, b"Back")]), 8, K)   # LSB refused; the char is back
check(served(out) == [30000401], f"it comes back on 30000401, not the lower free 30000400 ({served(out)})")

# ---------------------------------------------------------------------------
print("5. THE ACCOUNT MAP RECORDS ONLY ACCOUNTS LSB CONFIRMED")
reset([])
B._acctmap.clear()
calls = []


def auth_request(command, username, password, new_password=None):
    calls.append(command)
    raise OSError("connection refused")


B.lsb_auth_request = auth_request
try:
    B.lsb_account_for(42)
    check(False, "an unreachable LSB raises")
except Exception:
    check("42" not in B._acctmap, "an unreachable LSB leaves NO map entry (retried next launch)")

B.lsb_auth_request = lambda *a, **k: {"result": B.LOGIN_ERROR_CREATE_TAKEN}
login, pw = B.lsb_account_for(42)
check("42" in B._acctmap and login == "pol42", "an account LSB already has is recorded")

B._acctmap.clear()
B.lsb_auth_request = lambda *a, **k: {"result": 0x09}
try:
    B.lsb_account_for(43)
    check(False, "a refused create raises")
except RuntimeError:
    check("43" not in B._acctmap, "a refused create leaves no map entry")

print("   ...and a map entry whose account LSB lost heals itself")
B._acctmap["44"] = {"login": "pol44", "created": "x"}
state = {"created": False}


def auth_request2(command, username, password, new_password=None):
    state["created"] = True
    return {"result": B.LOGIN_SUCCESS_CREATE}


def authenticate(username=None, password=None):
    if not state["created"]:
        raise RuntimeError("LSB auth failed: {'result': 2}")
    return 1044, b"\x11" * 16


B.lsb_auth_request = auth_request2
B.lsb_authenticate = authenticate
aid, sh, login = B.lsb_member_session(44)
check(aid == 1044 and login == "pol44", "auth failure -> create -> auth succeeds, no admin step")

# ---------------------------------------------------------------------------
shutil.rmtree(TMP, ignore_errors=True)
if FAILS:
    print(f"\nFAIL: {len(FAILS)} check(s):")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("\nRESULT: the bridge pairs by charid, attributes by address, and records only real accounts")
