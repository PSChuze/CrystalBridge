#!/usr/bin/env python3
"""Provision a POL member's LSB account, and re-home an existing character.

One POL member = one LSB account = one FFXI character list. Before 2026-08-15
the bridge authenticated to LSB as a single shared account, so **every POL
account saw the same characters** -- you could log in as anyone and play
someone else's character. The other half of that bug was POL minting one Content
ID for every member (`accounts.py::_default_content_id` keyed on `member_no`,
which is 0 for the first member of every POL ID); that is fixed separately.

    python tools/ffxi_provision.py list
    python tools/ffxi_provision.py create <member_id>
    python tools/ffxi_provision.py rehome <charid> <member_id>

`create` goes through LSB's own AUTH (`login_cmd::LOGIN_CREATE = 0x20`) so the
password is bcrypted by LSB, never by us, and records the credential in the
bridge's account map -- the password is generated once and cannot be recovered
afterwards, so a lost map means orphaned accounts.

`rehome` moves an existing character onto a member's account. It exists for
characters created before per-member accounts existed, on the shared account.

Run it against the running stack (the tools are not baked into the bridge
image, so mount them for the one command):

    docker compose run --rm --entrypoint python \
        -v "$PWD/tools:/app/tools:ro" bridge tools/ffxi_provision.py list

or from the host with LSB_HOST/LSB_AUTH_PORT pointed at a published AUTH port.
"""
import json
import os
import sys

# `lsb/` beside this tool in the repo, `/app` inside the bridge image -- this is
# run both ways (the container is the only place that can reach LSB's AUTH port
# when it is not published on the host).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "lsb"))
sys.path.append("/app")
import ffxi_bridge as B  # noqa: E402


def _members():
    """POL members with an FFXI Content ID, from accounts.db."""
    import sqlite3
    db = sqlite3.connect(B.ACCOUNTS_DB, timeout=5.0)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA query_only = 1")
        return db.execute(
            "SELECT m.id AS member_id, m.login_name, h.handle_name, hc.content_id "
            "FROM member m JOIN handle h ON h.member_id = m.id "
            "LEFT JOIN handle_content hc ON hc.handle_id = h.id AND hc.content_code = 1 "
            "ORDER BY m.id").fetchall()
    finally:
        db.close()


def cmd_list():
    B.load_acctmap()
    print(f"{'member':>6}  {'login_name':<12} {'handle':<12} {'FFXI content id':<16} LSB account")
    for r in _members():
        ent = B._acctmap.get(str(r["member_id"]))
        print(f"{r['member_id']:>6}  {r['login_name']:<12} {r['handle_name']:<12} "
              f"{str(r['content_id'] or '-'):<16} {ent['login'] if ent else '(none yet)'}")


def cmd_create(member_id):
    B.load_acctmap()
    login, _pw = B.lsb_account_for(int(member_id))
    print(f"member {member_id} -> LSB account {login!r}")
    aid, sh = B.lsb_authenticate(login, _pw)
    print(f"  auth OK: account_id={aid} hash={sh.hex()}")
    return aid


def cmd_rehome(charid, member_id):
    """Move a character onto a member's LSB account.

    Deliberately NOT done through LSB (it has no such operation) -- this is a
    direct UPDATE, which is why it prints before and after and refuses when the
    account does not exist yet.
    """
    aid = cmd_create(member_id)
    print(f"\nrehome charid {charid} -> accid {aid}")
    print("  run this against the LSB database:")
    print(f"    UPDATE chars SET accid = {aid} WHERE charid = {int(charid)};")
    print("  (kept as a printed statement rather than executed: the bridge "
          "container has no MariaDB client, and an accid typo silently hides a "
          "character from its owner.)")


def cmd_selftest():
    """Pin the member-join contract.

    The join decides which POL member a game connection belongs to, and getting
    it wrong is silent and expensive: the character is created on someone else's
    account, the player cannot see it, and the only symptom is POL-0001 much
    later. Two characters were stranded that way on 2026-08-16.

    The contract balances that against the opposite failure, which a first cut
    walked straight into: refusing whenever two Viewers were signed in blocked
    every launch as soon as a second player came online. So -- resolve when the
    answer is knowable; refuse when there is NOTHING to go on; and when two live
    Viewers are indistinguishable, proceed but block character CREATION, because
    a select is protected by POL's own character-table check and a create is not.
    """
    import tempfile
    import time as _t
    now = _t.time()
    path = os.path.join(tempfile.mkdtemp(), "auth-sessions.json")
    B.POL_SESSIONS = path
    fails = []

    def check(name, got, want):
        ok = got == want
        print(f"  {'OK  ' if ok else 'FAIL'} {name}: {got!r}"
              + ("" if ok else f"  (want {want!r})"))
        if not ok:
            fails.append(name)

    def scenario(label, sessions):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sessions, fh)
        B._claimed_sids.clear()
        print(f"  -- {label} --")
        return B.resolve_pol_member("172.18.0.1")

    # 1. One Viewer signed in: that is the answer, whatever else is lying around.
    who, how = scenario("one signed-in Viewer, plus stale sessions", {
        "uLIVE":  {"member_id": 1, "peer_ip": "172.18.0.1", "at": now - 300,
                   "chars_at": now - 300, "viewer_open": True},
        "uSTALE": {"member_id": 7, "peer_ip": "172.18.0.1", "at": now - 10,
                   "chars_at": now - 10},
        "uOLD":   {"member_id": 2, "peer_ip": "172.18.0.1", "at": now - 999999},
    })
    print(f"    launch -> member {who} via {how}")
    check("the signed-in session wins over a FRESHER stale one", who, 1)

    # 2. Two Viewers signed in and both plausibly current. Nothing on FFXI's wire
    #    says which one pressed Play -- so play proceeds and only creation stops.
    who, how = scenario("two signed-in Viewers, both current", {
        "uONE": {"member_id": 7, "peer_ip": "172.18.0.1", "at": now - 20,
                 "viewer_open": True},
        "uTWO": {"member_id": 8, "peer_ip": "172.18.0.1", "at": now - 40,
                 "chars_at": now - 35, "viewer_open": True},
    })
    print(f"    launch -> member {who} via {how}")
    # Two people signed in is the NORMAL state of a working server, and refusing
    # there blocked every launch whenever a second player was online. It also
    # guarded against less than it looked: POL's own character-table check stops
    # a mismatched SELECT (that is what POL-0001 is). Only CREATE is unprotected,
    # so only create is blocked.
    check("two live Viewers still resolve (play must work)", who is not None, True)
    check("...and are flagged so creation is blocked", "AMBIGUOUS" in how, True)

    # 3. Nothing signed in at all -- also a refusal, for the same reason.
    who, how = scenario("nothing signed in", {
        "uSTALE": {"member_id": 7, "peer_ip": "172.18.0.1", "at": now - 10,
                   "chars_at": now - 10},
    })
    print(f"    launch -> {who!r} via {how}")
    check("an unattributable launch is REFUSED, not guessed", who, None)

    # 4. Two signed-in Viewers FAR apart in time are distinguishable: the one in
    #    front of the user is the one that has been doing things.
    who, how = scenario("two signed in, one long idle", {
        "uNOW": {"member_id": 4, "peer_ip": "172.18.0.1", "at": now - 5,
                 "viewer_open": True},
        "uIDLE": {"member_id": 8, "peer_ip": "172.18.0.1",
                  "at": now - (B.AMBIGUOUS_WINDOW + 600), "viewer_open": True},
    })
    print(f"    launch -> member {who} via {how}")
    check("a clearly-active Viewer beats a long-idle one", who, 4)

    # 5. THE REAL-ADDRESS CASE: two users, two machines, a deployment that sees
    #    client addresses. One exact peer_ip match is a fact, not a ranking --
    #    and it is the only discriminator that also covers the PS2, which
    #    cannot run a PC-side shim.
    who, how = scenario("two users, REAL addresses", {
        "uALICE": {"member_id": 7, "peer_ip": "198.51.100.40", "at": now - 5,
                   "viewer_open": True},
        "uBOB":   {"member_id": 16, "peer_ip": "198.51.100.55", "at": now - 4,
                   "viewer_open": True},
    })
    print(f"    launch from 172.18.0.1 -> {who!r} ({how})")
    saved, B_ip = None, "198.51.100.55"
    B._claimed_sids.clear()
    who2, how2 = B.resolve_pol_member(B_ip)
    print(f"    launch from {B_ip} -> member {who2} via {how2}")
    check("an exact address match resolves DETERMINISTICALLY", who2, 16)
    check("...and says so, rather than ranking", "deterministic" in how2, True)

    # 6. THE STAMPED PATH (pol-shim). A shimmed client states its own POL
    #    session, so attribution stops being an inference at all -- this is the
    #    case that fixes two PC clients behind ONE address, which neither the
    #    peer_ip match nor any ranking can do.
    print("  -- pol-shim stamp --")
    import hashlib
    token = b"abcdefghijklmnopqrstuvwxyz012345"
    sid = "u" + hashlib.sha1(token).hexdigest()[:16]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({sid: {"member_id": 5, "peer_ip": "172.18.0.1", "at": now - 900,
                         "viewer_open": True},
                   "uOTHER": {"member_id": 7, "peer_ip": "172.18.0.1",
                              "at": now - 1, "viewer_open": True}}, fh)
    # The packet the shim would send: magic + the first 8 bytes of the digest.
    pkt = bytearray(40)
    pkt[0] = 40
    pkt[4:8] = b"IXFF"
    pkt[8] = 0x26
    pkt[12:16] = B.POLTOKEN_MAGIC
    pkt[16:24] = hashlib.sha1(token).digest()[:8]
    got = B.read_poltoken(bytes(pkt))
    print(f"    stamp decodes to {got}")
    check("the stamp decodes to POL's own session id", got, sid)
    check("...and names the member directly", B.member_for_sid(got), 5)
    # ...even though a DIFFERENT session is far more recently active, which is
    # exactly the situation every heuristic got wrong.
    check("...beating a fresher rival session", B.member_for_sid(got) != 7, True)
    plain = bytearray(40)
    plain[0] = 40
    plain[4:8] = b"IXFF"
    check("an unstamped packet is ignored", B.read_poltoken(bytes(plain)), None)

    print()
    print("RESULT:", "join contract holds" if not fails else f"FAILED: {fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "selftest":
        sys.exit(cmd_selftest())
    if not a or a[0] == "list":
        cmd_list()
    elif a[0] == "create" and len(a) == 2:
        cmd_create(a[1])
    elif a[0] == "rehome" and len(a) == 3:
        cmd_rehome(a[1], a[2])
    else:
        sys.exit(__doc__)
