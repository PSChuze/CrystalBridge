#!/usr/bin/env python3
"""A POL handle must be able to hold SEVERAL FFXI Content IDs -- one per character.

WHAT THIS PINS, AND THE FIELD FAILURE THAT ASKED FOR IT
------------------------------------------------------
FFXI issues one Content ID per CHARACTER. `handle_content` used to be keyed
`(handle_id, content_code)`, which can express exactly one, so a player's second
character got no pairing: `ffxi_bridge.content_id_for` refuses to bind one
Content ID to two charids (a duplicate silently destroys the OTHER character's
world identity, and a Content ID cannot be re-minted without orphaning that
player's local `FINAL FANTASY XI/USER/<hexid>/` files), the character was served
untranslated, it missed POL's 64-slot character table, and FFXI drew **POL-0001**
at char select. For ever, with nothing about creating it looking wrong.

Measured live 2026-08-28 on one account: a single Content ID, held by its
first character; the second character held nothing. Five select attempts, five
world-server pending sessions, zero zone-ins. The same account had already hit
the same ceiling once on 2026-08-26.

The five things below are the ones that can silently come back:

  1. a fresh FFXI account gets its whole set of character slots, all distinct
     and globally unique -- the mint's invariant is not weakened by there being
     more of them;
  2. an account that already exists is TOPPED UP without any existing id moving
     -- the never-re-mint rule (see accounts.allocate_content_id);
  3. moving a title between handles carries EVERY slot. This one is a real trap:
     the old `link_content_to_handle` did DELETE-then-INSERT, which was lossless
     when a game had one id and destroys all but one now;
  4. the wire record's binding overflow -- a handle can hold more Content IDs
     than the client can SHOW, and the ones that overflow must be the extra FFXI
     slots, never another title;
  5. the bridge sees the whole pool, because that is what it offers the client
     as empty character slots.

Run from tools/: `python ffxi_char_slots_test.py`. Exits non-zero on failure.
Needs the OpenLobby core's `services/` (accounts.py, responders.py): set
OPENLOBBY_DIR to a checkout of it, or keep one beside this repository as
../openlobby. Without it the suite SKIPS (exit 77) rather than failing.
"""

import os
import shutil
import sqlite3
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from openlobby_paths import require_services                      # noqa: E402
require_services("ffxi_char_slots_test")

TMP = tempfile.mkdtemp(prefix="ffxi-char-slots-")
os.environ["POL_ACCOUNTS_DB"] = os.path.join(TMP, "accounts.db")
os.environ["POL_DATA_DIR"] = TMP
os.environ["POL_LOG_DIR"] = TMP
os.environ["POL_RESOURCE_DIR"] = os.path.join(TMP, "resources")

import accounts as A                                               # noqa: E402
import responders as R                                             # noqa: E402

FAILED = []


def check(ok, label):
    print(("  OK   " if ok else "  FAIL ") + label)
    if not ok:
        FAILED.append(label)


def fresh_db(name="accounts.db"):
    path = os.path.join(TMP, name)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)
    return A.connect(path)


def ffxi_ids(db, handle_id):
    return [r["content_id"] for r in A.handle_content_list(db, handle_id)
            if int(r["content_code"]) == A.FFXI_CONTENT_CODE]


N = A.FFXI_CHARACTER_SLOTS

# --------------------------------------------------------------------------- #
print("1. A NEW ACCOUNT GETS ITS FFXI CHARACTER SLOTS (want %d)" % N)

db = fresh_db()
A.create_polid(db, "SLOTS1", "pw-account")
mid = A.add_member(db, "SLOTS1", "slots-one", "pw-member")
A.set_handle(db, mid, "Tester")
hid = A.primary_handle_row(db, mid)["id"]
A.grant_content(db, mid, A.FFXI_CONTENT_CODE)
A.link_member_content_to_primary(db, mid)

ids = ffxi_ids(db, hid)
check(len(ids) == N, "the handle holds %d FFXI Content ID(s) (got %d: %s)"
      % (N, len(ids), ids))
check(len(set(ids)) == len(ids), "...all distinct (%s)" % (ids,))
dupes = db.execute(
    "SELECT content_id, COUNT(*) n FROM handle_content WHERE content_id IS NOT NULL"
    " GROUP BY content_id HAVING n > 1").fetchall()
check(not dupes, "no Content ID appears twice anywhere in the DB (%s)"
      % ([dict(r) for r in dupes],))
slots = sorted(int(r["slot"]) for r in A.handle_content_list(db, hid)
               if int(r["content_code"]) == A.FFXI_CONTENT_CODE)
check(slots == list(range(N)), "slots are 0..%d with no gaps (%s)" % (N - 1, slots))

# A title that is NOT FFXI keeps exactly one -- the slots are FFXI's rule, not a
# blanket one. Granting every title four ids would burn the handle's eight
# binding positions on games that only ever need one.
A.grant_content(db, mid, 2)
A.link_member_content_to_primary(db, mid)
tm = [r for r in A.handle_content_list(db, hid) if int(r["content_code"]) == 2]
check(len(tm) == 1, "Tetra Master still gets exactly one (%d)" % len(tm))

# ...and `member_content_id` must still mean slot 0, not "whichever sorted last".
primary_id = A.member_content_id(db, mid, A.FFXI_CONTENT_CODE)
slot0 = [r["content_id"] for r in A.handle_content_list(db, hid)
         if int(r["content_code"]) == A.FFXI_CONTENT_CODE and int(r["slot"]) == 0]
check(primary_id == slot0[0],
      "member_content_id returns slot 0 (%s vs %s)" % (primary_id, slot0[0]))

# --------------------------------------------------------------------------- #
print()
print("2. AN ACCOUNT THAT ALREADY EXISTS IS TOPPED UP, AND NOTHING MOVES")

# Build the PRE-SLOT schema by hand: this is what every account created before
# the slot column existed looks like, and the point of the check is that the id it is
# already serving does not change. A re-mint here costs that player every macro
# they ever wrote.
legacy = os.path.join(TMP, "legacy.db")
if os.path.exists(legacy):
    os.remove(legacy)
raw = sqlite3.connect(legacy)
raw.executescript("""
CREATE TABLE polid (id INTEGER PRIMARY KEY AUTOINCREMENT, polid TEXT UNIQUE,
                    pw_hash TEXT, pw_salt TEXT, created_at TEXT);
CREATE TABLE member (id INTEGER PRIMARY KEY AUTOINCREMENT, polid TEXT,
                     member_no INTEGER DEFAULT 0, login_name TEXT, pw_hash TEXT,
                     pw_salt TEXT, access_level INTEGER DEFAULT 0,
                     status TEXT DEFAULT 'active', created_at TEXT);
CREATE TABLE handle (id INTEGER PRIMARY KEY AUTOINCREMENT, member_id INTEGER,
                     handle_name TEXT, is_primary INTEGER DEFAULT 1,
                     created_at TEXT, client_guid INTEGER DEFAULT 0);
CREATE TABLE handle_content (handle_id INTEGER NOT NULL, content_code INTEGER NOT NULL,
                             content_id TEXT, status TEXT NOT NULL DEFAULT 'active',
                             linked_at TEXT NOT NULL,
                             PRIMARY KEY (handle_id, content_code));
INSERT INTO polid  VALUES (1, 'LEGACY', 'h', 's', '2026-08-01T00:00:00Z');
INSERT INTO member VALUES (1, 'LEGACY', 0, 'LEGACY', 'h', 's', 0, 'active',
                           '2026-08-01T00:00:00Z');
INSERT INTO handle VALUES (1, 1, 'Legacy', 1, '2026-08-01T00:00:00Z', 0);
INSERT INTO handle_content VALUES (1, 1, '30000037', 'active', '2026-08-22T02:13:28Z');
INSERT INTO handle_content VALUES (1, 2, '30000038', 'active', '2026-08-22T02:13:28Z');
""")
raw.commit()
raw.close()

db2 = A.connect(legacy)                       # runs _migrate, i.e. the rebuild
cols = set(r["name"] for r in db2.execute("PRAGMA table_info(handle_content)"))
check("slot" in cols, "the migration added the slot column")

after = ffxi_ids(db2, 1)
check("30000037" in after, "the served FFXI id survived the migration (%s)" % (after,))
row = db2.execute("SELECT slot FROM handle_content WHERE handle_id = 1"
                  " AND content_code = 1 AND content_id = '30000037'").fetchone()
check(row is not None and int(row["slot"]) == 0,
      "...and it is slot 0, i.e. still the handle's FFXI identity")
check(len(after) == N, "...and the handle was topped up to %d (%d)" % (N, len(after)))
tm2 = [r["content_id"] for r in A.handle_content_list(db2, 1)
       if int(r["content_code"]) == 2]
check(tm2 == ["30000038"], "the Tetra Master id was left alone (%s)" % (tm2,))
kept = db2.execute("SELECT COUNT(*) n FROM handle_content_pre_slots").fetchone()["n"]
check(int(kept) == 2, "the pre-migration rows are kept for recovery (%s)" % (kept,))

# Idempotent: running it again must not mint a second set.
again = A.ensure_ffxi_character_slots(db2)
check(again == 0, "a second top-up mints nothing (%s)" % (again,))
check(len(ffxi_ids(db2, 1)) == N, "...and the count is unchanged")

# A handle that does NOT hold FFXI gets nothing -- entitlement is `content`, and
# this must not hand the title to everybody.
db2.execute("INSERT INTO handle VALUES (2, 1, 'NoFFXI', 0, '2026-08-01T00:00:00Z', 0)")
db2.commit()
A.ensure_ffxi_character_slots(db2)
check(not ffxi_ids(db2, 2), "a handle without FFXI is not given any")

# --------------------------------------------------------------------------- #
print()
print("3. MOVING A TITLE BETWEEN HANDLES CARRIES EVERY SLOT")

# THE REGRESSION THIS EXISTS FOR. `link_content_to_handle` used to DELETE the
# code off the sibling handles and re-INSERT one row. With one id per game that
# was lossless. With four it would silently destroy three Content IDs -- and an
# id that has been served cannot be re-minted.
db3 = fresh_db("move.db")
A.create_polid(db3, "MOVE", "pw-account")
mm = A.add_member(db3, "MOVE", "mover", "pw-member")
A.set_handle(db3, mm, "First")
h1 = A.primary_handle_row(db3, mm)["id"]
A.grant_content(db3, mm, A.FFXI_CONTENT_CODE)
A.link_member_content_to_primary(db3, mm)
before_ids = set(ffxi_ids(db3, h1))
check(len(before_ids) == N, "the source handle holds %d (%s)"
      % (N, sorted(before_ids)))

db3.execute("INSERT INTO handle (member_id, handle_name, is_primary, created_at,"
            " client_guid) VALUES (?,?,0,?,0)", (mm, "Second", "2026-09-03T00:00:00Z"))
db3.commit()
h2 = db3.execute("SELECT id FROM handle WHERE handle_name = 'Second'").fetchone()["id"]
A.link_content_to_handle(db3, h2, A.FFXI_CONTENT_CODE)

moved = set(ffxi_ids(db3, h2))
check(moved == before_ids,
      "every Content ID moved, none lost or re-minted (%s)" % (sorted(moved),))
check(not ffxi_ids(db3, h1), "...and none was left behind on the source handle")
moved_slots = sorted(int(r["slot"]) for r in A.handle_content_list(db3, h2)
                     if int(r["content_code"]) == A.FFXI_CONTENT_CODE)
check(moved_slots == list(range(N)),
      "slots renumbered without a gap (%s)" % (moved_slots,))
dupes3 = db3.execute(
    "SELECT content_id, COUNT(*) n FROM handle_content WHERE content_id IS NOT NULL"
    " GROUP BY content_id HAVING n > 1").fetchall()
check(not dupes3, "the move did not duplicate an id (%s)"
      % ([dict(r) for r in dupes3],))

# --------------------------------------------------------------------------- #
print()
print("4. THE WIRE RECORD -- eight bound, the rest present but unbound")

# The handle binding is an 8-byte array at handle_slot+0x20 and the record's
# position field is 3 bits, so only eight of a handle's Content IDs can be BOUND.
# That is not a limit on the 64-slot table the launch gate and FFXI's world
# lookup actually read, so the overflow is served UNBOUND: playable, just absent
# from the profile view's Content ID list.
REC = 104
bound = R._char_record(REC, 0, 0, 0, A.FFXI_CONTENT_CODE, "30000037", bind=True)
unbound = R._char_record(REC, 9, 0, 9, A.FFXI_CONTENT_CODE, "30000099", bind=False)
check(bound[0x04] == 1, "a bound record sets the bind flag (+0x04 = %d)" % bound[0x04])
check(unbound[0x04] == 0, "an unbound record clears it (+0x04 = %d)" % unbound[0x04])
check(unbound[0x06] == 0,
      "...and does not claim a binding position (+0x06 = %d)" % unbound[0x06])
# The half that MUST survive being unbound: the launch gate walks the table for
# the present bit and the CONTENT CODE, and FFXI's lookup for the Content ID.
check(struct.unpack_from("<H", unbound, 0x08)[0] == A.FFXI_CONTENT_CODE,
      "an unbound record still carries its content code (the launch gate's field)")
check(struct.unpack_from("<I", unbound, 0x10)[0] == 30000099,
      "...and still carries the Content ID FFXI's world lookup compares")
check(unbound[0x00] == 9, "...and still claims its own character-table index")

# The ORDERING rule: positions go to every game's slot 0 first. Ordering by
# (content_code, slot) alone would give FFXI's four slots positions 0-3 and push
# three other TITLES out of the profile view -- a visible regression traded for a
# cosmetic one.
links = ([{"content_code": 1, "slot": i, "content_id": "3000010%d" % i}
          for i in range(N)]
         + [{"content_code": c, "slot": 0, "content_id": "300002%02d" % c}
            for c in (2, 3, 4, 10, 11, 14, 15)])
primary = [l for l in links if int(l.get("slot", 0)) == 0]
extra = [l for l in links if int(l.get("slot", 0)) != 0]
order = [(l["content_code"], l["slot"]) for l in primary + extra]
bound_codes = set(c for c, _s in order[:R._CHAR_PER_HANDLE])
check(bound_codes == set([1, 2, 3, 4, 10, 11, 14, 15]),
      "every TITLE keeps a binding position (%s)" % (sorted(bound_codes),))
check(all(c == 1 and s > 0 for c, s in order[R._CHAR_PER_HANDLE:]),
      "only extra FFXI slots overflow (%s)" % (order[R._CHAR_PER_HANDLE:],))

# --------------------------------------------------------------------------- #
print()
print("5. THE BRIDGE SEES THE WHOLE POOL")

# This is the payoff: the bridge offers a member's UNSPENT Content IDs as the
# client's empty character slots (`rewrite_s2c`), and picks one when the client
# creates. Pool of one = the failure this suite exists for.
sys.path.insert(0, os.path.join(HERE, os.pardir, "lsb"))
os.environ["FFXI_IDMAP_FILE"] = os.path.join(TMP, "idmap.json")
import ffxi_bridge as B                                            # noqa: E402
B.ACCOUNTS_DB = os.environ["POL_ACCOUNTS_DB"]
pool = B.pol_content_ids(mid)
check(len(pool) == N,
      "the bridge sees %d FFXI Content ID(s) for the member (%s)" % (N, pool))
check(sorted(pool) == sorted(int(x) for x in ffxi_ids(db, hid)),
      "...and they are exactly the handle's ids")

# The failure it prevents, stated as the bridge states it: with N ids, N-1
# characters already paired still leaves one free for the next create.
B._idmap = dict((str(i + 1), pool[i]) for i in range(N - 1))
free = [c for c in B.pol_content_ids(mid) if c not in set(B._idmap.values())]
check(len(free) == 1,
      "%d characters in, one Content ID still free (%s)" % (N - 1, free))

# --------------------------------------------------------------------------- #
print()
if FAILED:
    print("RESULT: %d FAILURE(S)" % len(FAILED))
    for f in FAILED:
        print("  - " + f)
else:
    print("RESULT: a handle can hold one FFXI Content ID per character")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAILED else 0)
