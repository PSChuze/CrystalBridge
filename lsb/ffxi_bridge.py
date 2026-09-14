"""POL-native FFXI -> LandSandBoat login bridge (session-injecting relay).

WHAT THIS IS
------------
The retail FFXI client, launched from the PlayOnline Viewer, connects to its
lobby host (ffxi00.pol.com -> us) on the VIEW (54001) and DATA (54230) ports and
speaks the plaintext "IXFF" lobby protocol. LandSandBoat's view/data servers
speak that SAME plaintext protocol -- the only thing the retail client does NOT
do is LSB's TLS+JSON auth on 54231 (that is xiloader's job, out of band).

xiloader solves this client-side: it hooks the client's send(), and for every
lobby packet ([4:8]=="IXFF") overwrites the 16-byte identifer at offset 12 with
the sessionHash it got from the TLS auth (xiloader main.cpp Mine_send). LSB's
view/data servers then look that hash up in the per-IP authenticated-session map
(loginHelpers::getHashFromPacket reads data+12, 16 bytes).

This does the SAME THING server-side, so the real POL Viewer boot works with no
client patching:
  1. Do LSB's TLS+JSON auth ourselves (as a mapped LSB account) -> account_id +
     16-byte sessionHash. This registers a session in LSB keyed by (OUR ip, hash).
  2. Listen where the client dials (54001 view, 54230 data), and for each client
     connection open a socket to LSB's real view/data.
  3. Relay bytes both ways. On client->LSB, rewrite [12:28] of every IXFF packet
     to the sessionHash. On LSB->client, pass through.
Because our auth AND our view/data connections to LSB all originate from this
process's IP, LSB sees a consistent IP and accepts the injected session.

THE CONTENT-ID TRANSLATION (the POL-0001 fix)
---------------------------------------------
The retail lobby's `ffxi_id` field **is the PlayOnline Content ID**, and it is a
DIFFERENT number from the world's character id. LSB's own char-list comment says
so without meaning to:

    uint32 contentId = charId;   // "Reusing the character ID as the content ID"
    uint16 charIdMain  = charId & 0xFFFF;        \\ "The character ID is made up
    uint8  charIdExtra = (charId >> 16) & 0xFF;  / of two parts totalling 24 bits"

i.e. `ffxi_id` (32-bit) is the Content ID and `ffxi_id_world` + `ffxi_id_world_tbl`
(24-bit) is the world character id. With xiloader there is no PlayOnline, so LSB
puts the charid in both and nothing notices.

The real POL Viewer DOES notice. It holds its own Content ID for FFXI (the core
stack mints SE-shaped 8-digit serials in `accounts.allocate_content_id`;
accounts from older builds may hold 10-digit computed ids, and both shapes
arrive here as whatever `handle_content` holds -- this file never computes
one), served over the 1:3
`KGetChrList`; after a character is created it reconciles the lobby's char list
against that record and fails when no entry carries its Content ID -- the
"writing character data to PlayOnline" step, POL-0001.

So this bridge translates, which is exactly its job:

    LSB -> client   0x20 char list, 0x0B next-login:  ffxi_id  charid -> ContentID
    client -> LSB   0x07 select, 0x14 delete, 0x28 rename: ffxi_id ContentID -> charid

`ffxi_id_world` / `ffxi_id_world_tbl` are NEVER touched, and that is what makes
this safe for the world handoff: the client builds the world-login packet's
`UniqueNo` (0x00A) from those, not from `ffxi_id`, and LSB's map server looks
`chars.charid` up by `UniqueNo` (map_networking.cpp:247). Rewriting `ffxi_id`
therefore cannot reach the map server.

Every LSB->client lobby packet carries an MD5 over itself with the 16-byte
identifer field zeroed (`md5(pkt, hash, packet_size)` then `copyHashIntoPacket`),
so a rewritten reply is re-signed the same way -- see `resign()`.

One LSB account per POL member; character select and the world handoff are
live-proven. Offline pins: tools/ffxi_bridge_test.py,
ffxi_udp_relay_check.py and the ffxi_idmap_* suites (tools/bridge_run_all.py).

Run on the host for fast iteration:
  python ffxi_bridge.py
Env knobs (defaults target an LSB on 127.0.0.1 at its stock ports):
  LSB_HOST, LSB_AUTH_PORT, LSB_VIEW_PORT, LSB_DATA_PORT
  BRIDGE_VIEW_PORT (54001), BRIDGE_DATA_PORT (54230)
  LSB_ACCOUNT, LSB_PASSWORD  (the LSB account to auth as)
  FFXI_ID_MAP=0             disable the Content-ID translation (old behaviour)
  FFXI_POL_CONTENT_IDS      comma list overriding the ids read from accounts.db
  POL_ACCOUNTS_DB           path to accounts.db (default ../data/accounts.db)
  POL_AUTH_SESSIONS         the core stack's session table (auth-sessions.json)
  FFXI_IDMAP_FILE           where the charid<->ContentID map is persisted
  FFXI_ACCTMAP_FILE         where the member->LSB account map is persisted
  FFXI_ACCT_SECRET          seed the per-member LSB passwords derive from
  FFXI_PKT_DUMP=0           stop writing raw packet captures under FFXI_PKT_DIR
  FFXI_WORLD_CAPTURE=0      stop capturing world UDP traffic (default ON; one
                            JSON line per datagram, payload base64)
  FFXI_WORLD_CAP_DIR        where those captures go (default <pkt dir>/world)
  FFXI_WORLD_CAP_MAX        per-flow datagram ceiling (20000)
  FFXI_WORLD_CAP_BYTES      per-flow byte ceiling (32 MiB)
  FFXI_WORLD_CAP_KEEP       how many capture files to retain (40)
  FFXI_SESSION_KEY_WATCH    seconds between accounts_sessions.session_key
                            samples during a world flow; 0 disables (5)
  FFXI_SESSION_KEY_IDLE     stop watching after this long with no world
                            traffic either way (120)
"""
import base64
import hashlib
import json
import os
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time

LSB_HOST       = os.environ.get("LSB_HOST", "127.0.0.1")
LSB_AUTH_PORT  = int(os.environ.get("LSB_AUTH_PORT", "54231"))
LSB_VIEW_PORT  = int(os.environ.get("LSB_VIEW_PORT", "54001"))
LSB_DATA_PORT  = int(os.environ.get("LSB_DATA_PORT", "54230"))
BRIDGE_VIEW    = int(os.environ.get("BRIDGE_VIEW_PORT", "54001"))
BRIDGE_DATA    = int(os.environ.get("BRIDGE_DATA_PORT", "54230"))
LSB_ACCOUNT    = os.environ.get("LSB_ACCOUNT", "poltest")
LSB_PASSWORD   = os.environ.get("LSB_PASSWORD", "poltest123")
SEARCH_IP      = os.environ.get("SEARCH_IP", "127.0.0.1")  # search/cache server given to client
XILOADER_VER   = [2, 1, 0]

# --- ROUTE BY REPORTED CLIENT VERSION ---------------------------------------
#
# One lobby hostname per world is not available to us: ffxi00 (retail) and
# ffxi015 (the FFXI TEST SERVER, content 0015) both resolve to this box, the
# client dials fixed ports, and the DNS stub answers every redirected name with
# the single stub_ip. So the only thing that distinguishes the two clients on
# the wire is the build they report -- which is exactly enough.
#
# LSB reads it at OFFSET 0x74 of the cmd-0x26 packet and compares only the
# FIRST SIX characters (login/view_session.cpp:346 -- it appends 'xx_x' to both
# sides before comparing). We read the same six and pick a backend.
#
# OFF unless LSB_ALT_VER is set, so a single-world deployment is byte-identical
# in behaviour to before.
#
#   LSB_ALT_VER=201108   LSB_ALT_HOST=lsb-test-connect
#   LSB_ALT_AUTH_PORT / LSB_ALT_VIEW_PORT / LSB_ALT_DATA_PORT
LSB_ALT_VER       = os.environ.get('LSB_ALT_VER', '').strip()
LSB_ALT_HOST      = os.environ.get('LSB_ALT_HOST', '').strip()
LSB_ALT_AUTH_PORT = int(os.environ.get('LSB_ALT_AUTH_PORT', LSB_AUTH_PORT))
LSB_ALT_VIEW_PORT = int(os.environ.get('LSB_ALT_VIEW_PORT', LSB_VIEW_PORT))
LSB_ALT_DATA_PORT = int(os.environ.get('LSB_ALT_DATA_PORT', LSB_DATA_PORT))

# Each client is handled on its own thread, so the chosen backend rides there
# rather than being threaded through get_session/lsb_auth/ensure_data_companion
# by hand. Unset (every other thread, and every deployment without ALT) falls
# back to the primary -- see r_host()/r_auth()/r_data().
_ROUTE = threading.local()

def r_host(): return getattr(_ROUTE, 'host', None) or LSB_HOST
def r_auth(): return getattr(_ROUTE, 'auth', None) or LSB_AUTH_PORT
def r_data(): return getattr(_ROUTE, 'data', None) or LSB_DATA_PORT
def r_name(): return getattr(_ROUTE, 'name', None) or 'primary'

def r_tag():
    """Short, stable id for the routed world -- '' for the primary.

    Used to key ffxi_accounts.json. An LSB account exists only in the instance
    it was created in, so one shared map would have the alt world try to log in
    with accounts that live in the primary and skip creating its own. The
    primary keeps BARE keys so the existing file stays valid.
    """
    return getattr(_ROUTE, 'tag', None) or ''


# Lobby command bytes xiloader recognizes at buffer[8] (main.cpp isLobbyCommand).
LOBBY_CMDS = {0x07, 0x14, 0x1F, 0x21, 0x22, 0x24, 0x26, 0x28, 0x2B}
MAGIC = b"IXFF"

#: `packet_t` = packet_size u32 + terminator u32 ("IXFF") + command u32 +
#: identifer[16]. Every lobby packet's payload therefore starts at 28, which is
#: why LSB reads the char id at offset 28 in 0x07/0x28 and the name at 32/36.
HDR_LEN = 28
#: identifer[16] -- the session hash on client->server, the MD5 on server->client.
HASH_OFF, HASH_LEN = 12, 16
#: `lpkt_chr_info_sub2`: ffxi_id u32, ffxi_id_world u16, worldid u16, status u16,
#: flags u8, ffxi_id_world_tbl u8, character_name[16], world_name[16] = 44, then
#: TC_OPERATION_MAKE = 96. Cross-checked against the wire: the 0x20 reply is
#: 2272B = 28 + 4 + 16*140.
CHR_REC_LEN = 140
#: `lpkt_chr_info2`: characters u32 at 28, then the records.
CHR_LIST_OFF = HDR_LEN + 4

FFXI_ID_MAP  = os.environ.get("FFXI_ID_MAP", "1") == "1"
#: Rewrite `ffxi_id` in the 0x0B WORLD HANDOFF too? **Default off, measured.**
#: The handoff's ffxi_id is what the client carries into the world-login packet
#: (0x00A `UniqueNo`), and LSB's map server looks its PENDING SESSION up by that
#: value -- keyed on the charid the lobby just committed. Feed it a Content ID and
#: every check in `map_networking.cpp` fails as a SILENT `return -1`: no log line,
#: no error to the client, just a ~40s timeout and a bounce back to the title
#: screen (which FFXI reports as POL-0001). Measured 2026-08-13: with this ON the
#: map logged `Creating pending session for character id 1` and then nothing.
#: An earlier reading of LSB's "24-bit charid" comment said the client takes
#: UniqueNo from `ffxi_id_world`; the client's behaviour says otherwise.
#: The POL reconciliation does not need this -- it happens on the 1:3 GET right
#: after the create, off the 0x20 char list.
MAP_HANDOFF  = os.environ.get("FFXI_ID_MAP_HANDOFF", "0") == "1"

#: Make the WORLD ID consistent across the three packets that carry it. LSB tells
#: the client three different things, and its own source flags one of them:
#:
#:   0x23 world list  world_name[0].no = 0x20   "Setup world id 0x20"
#:   0x20 char list   worldid          = 0      "Use when multiple worlds are supported"
#:   0x0B handoff     server_id = (charid>>16)&0xFF = 0
#:                                    "TODO: Looks wrong? shouldn't this be a server index?"
#:
#: So the client is told its character lives on world 0 and to go to server 0,
#: while the only world in the list is 0x20. xiloader never reads any of it. The
#: real POL client evidently does: with all three as LSB sends them, it takes the
#: 0x0B and then **never sends the world-login UDP at all** (measured 2026-08-14
#: through the bridge's UDP relay -- zero datagrams, and the relay is proven live
#: by a probe), and raises POL-0001.
#:
#: Neither field reaches the map server -- it reads only `UniqueNo` out of the
#: client's own 0x00A -- so aligning them cannot affect the world session.
WORLD_ID_FIX = os.environ.get("FFXI_WORLD_ID_FIX", "1") == "1"
#: Learned from the 0x23 world list as it passes; this is LSB's hardcoded value
#: and the fallback for a char list requested before the world list (the client
#: asks 0x1F before 0x24).
_world_id = int(os.environ.get("FFXI_WORLD_ID", "0x20"), 0)
#: `lpkt_next_login`: ffxi_id(28) ffxi_id_world(32) character_name[16](36)
#: server_id(52) server_ip(56) server_port(60) cache_ip(64) cache_port(68) = 72B.
NEXT_LOGIN_SERVER_ID = HDR_LEN + 24
#: `lpkt_chr_info_sub2`: ffxi_id(+0) ffxi_id_world(+4,u16) worldid(+6,u16) ...
CHR_REC_WORLDID = 6

#: KEY: **THE 0x20 RECORD IS ALSO POL'S CONTENT PROFILE, FIELD FOR FIELD.**
#:
#: `PlayOnlineViewer/data/db/prof_001.pib` declares FFXI's profile as
#: Name / World Name / Nation / Current Area / Job / Job Level / Race, and every
#: one of those is already in the char-list record LSB sends -- with the SAME
#: numbering, because both ends are SE's:
#:
#:     prof_001 enum            LSB `data_session.cpp`        record offset
#:     Nation 0/1/2             `chars.nation`  -> town_no    +0x32
#:     Current Area = ZoneId    `zone`          -> zone_no    +0x48 (low byte)
#:                                              + zone_no2    +0x4F (bit 8)
#:     Job 1..20                MainJob         -> mjob_no    +0x2E
#:     Job Level                lvlMainJob      -> mjob_level +0x49
#:     Race 1..8                `chars.race`    -> mon_no     +0x2C
#:     World Name               the server name -> world_name +0x1C
#:
#: WARNING: **THE ZONE IS NINE BITS.** `data_session.cpp:207` splits it -- `zone_no` is
#: the low byte and `zone_no2` is `(zone >> 8) & 1` -- so reading `zone_no`
#: alone silently renames every zone above 255 (Al Zahbi onwards) to whatever
#: sits 256 rows lower in the enum. Reassembled here, once.
#:
#: The offsets are not a guess: `lpkt_chr_info_sub2` is 44 bytes of header plus
#: a 96-byte `TC_OPERATION_MAKE` whose natural alignment sums to exactly 96, and
#: 44 + 96 = the 140 CHR_REC_LEN the wire already confirms.
CHR_REC_WORLDNAME = 0x1C            # char[16]
CHR_REC_RACE      = 0x2C            # mon_no      u16 (TC_OPERATION_MAKE +0)
CHR_REC_JOB       = 0x2E            # mjob_no     u8  (+2)
CHR_REC_NATION    = 0x32            # town_no     u8  (+6)
CHR_REC_ZONE      = 0x48            # zone_no     u8  (+28)
CHR_REC_JOBLEVEL  = 0x49            # mjob_level  u8  (+29)
CHR_REC_ZONE_HI   = 0x4F            # zone_no2    u8  (+35), bit 8 of the zone
#: `lpkt_world_list`: sumofworld u32 at 28, then lpkt_world_name{no u32, name[16]}.
WORLD_LIST_FIRST_NO = HDR_LEN + 4
PKT_DUMP     = os.environ.get("FFXI_PKT_DUMP", "1") == "1"
_HERE        = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DB  = os.environ.get("POL_ACCOUNTS_DB",
                              os.path.join(_HERE, os.pardir, "data", "accounts.db"))
IDMAP_FILE   = os.environ.get("FFXI_IDMAP_FILE", os.path.join(_HERE, "ffxi_idmap.json"))
PKT_DIR      = os.environ.get("FFXI_PKT_DIR",
                              os.path.join(_HERE, os.pardir, "logs", "lsb", "pkt"))


def log(tag, msg):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def hexdump(b, limit=64):
    b = b[:limit]
    return " ".join(f"{x:02x}" for x in b)


# ---------------------------------------------------------------------------
# PlayOnline Content ID <-> LSB charid
#
# POL's side of the pairing comes from accounts.db: every `handle_content` row
# with content_code 1 is one FFXI Content ID, i.e. one character slot the member
# is entitled to. LSB's side is the charid it invents. The map is persisted so a
# character keeps the same Content ID across bridge restarts -- the Viewer caches
# the pairing locally, so a churning map would look like the character moved to a
# different Content ID.
# ---------------------------------------------------------------------------
_idmap_lock = threading.Lock()
_idmap = {}          # str(charid) -> int Content ID
_charnames = {}      # str(charid) -> FFXI character name, as the lobby reports it
#: str(charid) -> the WORLD IDENTITY DWORD the POL character table must carry for
#: this character, i.e. `charIdMain | worldid<<16 | charIdExtra<<24` exactly as
#: the client will read it back out of the 0x20 record. See `_world_field()`.
_worldfields = {}
#: str(charid) -> `{world/nation/zone/job/joblevel/race}` off the 0x20 record --
#: the POL CONTENT PROFILE's tail (see CHR_REC_RACE and friends). The lobby
#: cannot read these itself: LSB's `chars` table is behind the map server's
#: MySQL and `responders.py` has no route to it, so the bridge -- which sees the
#: record on its way past -- is the only place the join can be made, exactly as
#: it is for the character NAME.
_charfields = {}
_pol_content_ids = []


def pol_content_ids(member_id=None):
    """FFXI Content IDs available to ONE POL member (all of them if unknown).

    Scoping this by member is half of the isolation fix. The pool is what an
    empty character slot is offered, so a global pool lets member B's new
    character be created against member A's Content ID -- and a Content ID
    belongs to exactly one handle in POL (POL-7169/7187/5326), which is
    unrecoverable without a re-mint. The other half is that the LSB account is
    per member too, so the char list itself differs; both are required.
    """
    if member_id is None:
        return load_pol_content_ids()
    try:
        db = sqlite3.connect(ACCOUNTS_DB, timeout=5.0)
        try:
            db.execute("PRAGMA query_only = 1")
            rows = db.execute(
                "SELECT hc.content_id FROM handle_content hc "
                "JOIN handle h ON h.id = hc.handle_id "
                "WHERE h.member_id = ? AND hc.content_code = 1 "
                "AND hc.status = 'active'", (int(member_id),)).fetchall()
        finally:
            db.close()
    except Exception as exc:
        log("idmap", f"accounts.db read failed for member {member_id} ({exc!r})")
        return []
    out = []
    for (cid,) in rows:
        try:
            out.append(int(str(cid).strip()))
        except (TypeError, ValueError):
            continue
    return sorted(out)


def load_pol_content_ids():
    """Every FFXI (content code 1) Content ID this POL server issues, ascending.

    Server-wide; use `pol_content_ids(member_id)` for anything that ALLOCATES.
    """
    env = os.environ.get("FFXI_POL_CONTENT_IDS", "").strip()
    if env:
        return [int(x) for x in env.replace(";", ",").split(",") if x.strip()]
    # NOT `mode=ro`: accounts.db is in WAL, and a read-only handle cannot create
    # the -shm index a WAL reader needs, so it fails with "attempt to write a
    # readonly database". A normal handle with `query_only` is the supported way
    # to read a WAL database without being able to modify it -- which matters
    # here, because this file has been truncated once before by careless writers
    # over a bind mount.
    rows = []
    try:
        db = sqlite3.connect(ACCOUNTS_DB, timeout=5.0)
        try:
            db.execute("PRAGMA query_only = 1")
            rows = db.execute(
                "SELECT DISTINCT content_id FROM handle_content "
                "WHERE content_code = 1 AND status = 'active'").fetchall()
        finally:
            db.close()
    except Exception as exc:
        log("idmap", f"accounts.db read failed ({exc!r}); no Content IDs known")
        return []
    out = []
    for (cid,) in rows:
        try:
            out.append(int(str(cid).strip()))
        except (TypeError, ValueError):
            continue
    return sorted(out)


def load_idmap():
    """Read the persisted map.

    Two on-disk shapes are accepted. The original was a flat
    `{"<charid>": <ContentID>}`; the current one is
    `{"<charid>": {"content_id": N, "name": "Alice", "seen": "<iso>"}}`, which also
    carries the FFXI CHARACTER NAME -- the missing half of the POL identity
    chain (character name -> Content ID -> handle). Old files still load.
    """
    global _idmap, _charnames, _charfields
    _idmap, _charnames, _charfields = {}, {}, {}
    try:
        with open(IDMAP_FILE, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        # A missing file is legitimate on a brand-new stack and a BUG on a
        # misconfigured one (wrong FFXI_IDMAP_FILE / wrong mount) -- and the
        # two used to be indistinguishable because this branch was silent.
        # Starting empty on a misconfigured stack RE-ALLOCATES Content IDs in
        # whatever order the next 0x20 arrives, permuting pairings the Viewer
        # has cached (= POL-0001). Say so once, loudly, like responders does.
        log("idmap", f"{IDMAP_FILE} does not exist -- starting with an EMPTY "
                     f"map. Correct on first boot; if characters exist, this "
                     f"path is WRONG and pairings will be re-dealt.")
        return
    except Exception as exc:
        log("idmap", f"{IDMAP_FILE} unreadable ({exc!r}); starting empty")
        return
    global _worldfields
    _worldfields = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            _idmap[str(k)] = int(v["content_id"])
            if v.get("name"):
                _charnames[str(k)] = v["name"]
            if v.get("world_field"):
                _worldfields[str(k)] = int(v["world_field"])
            if isinstance(v.get("profile"), dict):
                _charfields[str(k)] = dict(v["profile"])
        else:
            _idmap[str(k)] = int(v)


def save_idmap():
    try:
        out = {k: {"content_id": v,
                   "name": _charnames.get(k, ""),
                   "world_field": _worldfields.get(k, 0),
                   # WARNING: OMITTED, not written empty, for a charid whose 0x20 has
                   # not been seen: `{}` and "never seen" have to stay
                   # distinguishable, or the lobby cannot tell an unread
                   # character from one genuinely at Job Level 0.
                   **({"profile": _charfields[k]} if _charfields.get(k) else {}),
                   "seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
               for k, v in _idmap.items()}
        # tmp + os.replace, like save_acctmap below. The old truncate-in-place
        # write raced responders' `_ffxi_world_fields()` mtime poll in the
        # OTHER container: a read landing in the truncate window parsed `{}`,
        # world_field came back 0, and 0 at record +0x0C is POL-0001. The
        # writer bursts right after a character create -- exactly when the
        # client re-fetches 1:3 -- so the race was synchronized by design.
        tmp = IDMAP_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1, sort_keys=True)
        os.replace(tmp, IDMAP_FILE)
    except Exception as exc:
        log("idmap", f"could not persist {IDMAP_FILE}: {exc!r}")


def note_char_name(charid, name):
    """Record the FFXI character name the lobby reports for a charid.

    This is the ONLY place the name and the PlayOnline Content ID are ever seen
    together: LSB knows the name but nothing about PlayOnline, and the POL server
    knows the Content ID but has never been told what the character is called.
    The bridge sits between them, so it is where the join has to be made.
    """
    name = (name or "").strip()
    if not name or name == "\x20":
        return
    key = str(charid)
    with _idmap_lock:
        if _charnames.get(key) == name:
            return
        _charnames[key] = name
        if key in _idmap:
            save_idmap()
            log("idmap", f"charid {charid} is character {name!r} "
                         f"(Content ID {_idmap[key]})")


def note_char_fields(charid, fields):
    """Record the PROFILE TAIL this character's 0x20 record carries.

    Same shape and the same reason as `note_char_name`: POL's per-Content-ID
    profile (lobby `05:04`, `prof_001.pib`) asks for World Name / Nation /
    Current Area / Job / Job Level / Race, and the lobby holds NONE of them --
    it has the Content ID and nothing else about the character. LSB holds all
    six, in its own `chars` row, behind a MySQL the lobby container has no route
    to. The bridge sees them go past on every char list.

    So this writes them where `responders._content_game_fields` can read them,
    and it writes only what LSB actually said. A character whose list has not
    been seen since the bridge last started has no entry at all, and the profile
    leaves those fields unset -- which is what the Viewer draws for a field the
    player has not filled in. Nothing here is derived or defaulted.

    WARNING: Called for every slot of every 0x20, i.e. a few times per login. It only
    persists when a value actually MOVED, because `save_idmap` rewrites the
    whole file and responders polls its mtime.
    """
    key = str(charid)
    fields = {k: v for k, v in (fields or {}).items() if v not in (None, "")}
    if not fields:
        return
    with _idmap_lock:
        if _charfields.get(key) == fields:
            return
        was = _charfields.get(key) or {}
        _charfields[key] = fields
        if key in _idmap:
            save_idmap()
            moved = ", ".join(f"{k}={fields[k]!r}" for k in sorted(fields)
                              if was.get(k) != fields[k])
            log("idmap", f"charid {charid}: profile fields {moved} "
                         f"(POL 05:04 content profile for Content ID "
                         f"{_idmap[key]})")


def pack_world_field(main, worldid, tbl):
    """`table[+0x04]`, transcribed instruction-for-instruction from FUN_100FFE00.

    Written the client's way rather than the obvious way on purpose: the shifts
    OVERLAP (worldid's high byte lands on the same bits as `charIdExtra`), so a
    tidied-up `worldid<<16 | tbl<<24 | main` would differ from the client for any
    world id above 0xFF. Keep the arithmetic, not the intent.
    """
    id24 = ((tbl & 0xFF) << 16) | (main & 0xFFFF)
    return (((((worldid & 0xFFFF) << 8) | (id24 & 0xFFFF0000)) << 8)
            | (id24 & 0xFFFF)) & 0xFFFFFFFF


def note_world_field(charid, world_field):
    """Record the WORLD IDENTITY DWORD this character's 0x20 record carries.

    **This is the value POL's own character table has to repeat**, and getting it
    wrong is the whole of POL-0001's second half. FFXI does not take the world
    address from the `0x0B` handoff and run with it: at char-select sub-state 14
    (`FFXiMain FUN_100FE32F` -> `FUN_100FFDB0` -> `FUN_100FFE00`) it walks
    PlayOnline's **64-entry character table** -- polcore's dispatch slot +0x2C4,
    whose only writer is our lobby `1:3` -- looking for the entry that describes
    the character it just picked, and aborts the world connect when no slot
    matches (state 3 -> 203).

    The lookup takes three values straight out of the `0x20` char-list record it
    was sent (that record is copied verbatim into the world context: same
    140-byte stride, `character_name` and `world_name` and the 96-byte
    `TC_OPERATION_MAKE` all land where the accessors read them) and requires:

        table[+0x00] & 1          present
        table[+0x02] == 1         content code = FFXI
        table[+0x08] == ffxi_id   the POL Content ID  (we already serve this)
        table[+0x0C] == 0         Content ID high
        table[+0x04] == charIdMain | worldid<<16 | charIdExtra<<24

    That last packing is not a guess -- it is what `FUN_100FFE00` computes:

        edx = ((worldid & 0xFFFF) << 8 | (id24 & 0xFFFF0000)) << 8 | (id24 & 0xFFFF)

    with `id24 = ffxi_id_world_tbl<<16 | ffxi_id_world`, which is the same
    little-endian {u16 charIdMain, u8 worldid, u8 charIdExtra} record LSB itself
    builds for xiloader in `data_session.cpp:274` -- two independent readings of
    one layout.

    Recording it HERE rather than recomputing it server-side is deliberate: the
    bridge is the only party that knows what the client was actually told, after
    `WORLD_ID_FIX` has had its say. A server-side reconstruction would have to
    track that flag and would silently disagree the day it changes.
    """
    key = str(charid)
    with _idmap_lock:
        if _worldfields.get(key) == world_field:
            return
        _worldfields[key] = int(world_field)
        if key in _idmap:
            save_idmap()
            log("idmap", f"charid {charid}: world field 0x{world_field:08X} "
                         f"(POL 1:3 table[+0x04] for Content ID {_idmap[key]})")


def content_id_for(charid, prefer=None, member_id=None):
    """Content ID for an LSB charid, allocating one on first sight.

    `prefer` is the Content ID the CLIENT itself named (it puts the one it
    allocated in the create request), which beats our own allocation order --
    the client is the authority on which of its Content IDs it just spent.
    """
    if not charid:
        return None
    key = str(charid)
    with _idmap_lock:
        if key in _idmap:
            # A BOUND ID NEVER MOVES. Until 2026-09-04 this function would REBIND an
            # already-paired charid whenever `prefer` differed, and `prefer` was
            # whatever the client named on its last create -- which the caller handed
            # to the FIRST non-empty slot of the next 0x20, i.e. the member's OLDEST
            # character, not the new one. Creating a second character therefore moved
            # the first character onto the new id, got the new character refused as a
            # duplicate, and on the client's own refetch handed it the freed old id:
            # the two characters SWAPPED Content IDs. The client keeps a character's
            # macros and settings under `USER/<hexid>/`, so a swap loses both
            # players' files, and the swap is silent. Offline-proven in
            # tools/ffxi_bridge_test.py; never seen live only because no account
            # had created a second character since that became possible.
            if prefer and _idmap[key] != int(prefer):
                log("idmap", f"charid {charid} is already Content ID {_idmap[key]}; "
                             f"the client's named id {prefer} is for a NEW character, "
                             f"not this one -- keeping {_idmap[key]}")
            _released_ids.pop(key, None)
            return _idmap[key]
        if prefer:
            # THE CLIENT IS THE AUTHORITY ON WHICH OF **ITS** IDS IT SPENT -- NOT ON
            # WHETHER IT HAD ONE TO SPEND.
            #
            # This branch used to write `prefer` unconditionally, while the allocation
            # branch below carefully refused to hand out an id already in `used`. So
            # the one path a real client actually takes was the one with no check, and
            # a Content ID could be bound to two charids at once.
            #
            # That is not hypothetical: two charids on one LSB account were found
            # holding the same Content ID (2026-08-26). It happens
            # because the client will happily create a character it has no entitlement
            # for -- an empty slot left at ffxi_id 0 does NOT read as "unavailable" to
            # it, which this file asserted in a comment and nobody had tested -- and
            # having only ever been issued one Content ID, it names that one again.
            #
            # The damage is silent and lands on the OTHER character: _ffxi_world_fields
            # in responders.py is keyed by Content ID, so one charid's world identity
            # overwrites the other's, and the loser gets POL-0001 at char select for
            # ever. A Content ID belongs to exactly one handle in POL
            # (POL-7169/7187/5326) and is unrecoverable without a re-mint, so a
            # duplicate is worth refusing even at the cost of an unpaired character.
            other = None
            for k, v in _idmap.items():
                if v == int(prefer) and k != key:
                    other = k
                    break
            if other is not None:
                log("idmap", f"charid {charid}: client named Content ID {prefer}, but "
                             f"charid {other} already holds it -- REFUSED. The client "
                             f"created a character it has no free Content ID for; this "
                             f"one stays unpaired rather than corrupting charid {other}'s "
                             f"world identity. A handle holds "
                             f"POL_FFXI_CHARACTER_SLOTS Content IDs, so seeing this "
                             f"means the pool really is exhausted: raise that, or "
                             f"delete one of the two characters.")
                return None
            _idmap[key] = int(prefer)
            _released_ids.pop(key, None)
            save_idmap()
            log("idmap", f"charid {charid} -> Content ID {prefer} (named by the client)")
            return int(prefer)
        used = set(_idmap.values())
        free = [c for c in pol_content_ids(member_id) if c not in used]
        # A character that comes back after a delete we already released (LSB
        # refused it: deletion disabled, wrong account, ...) takes the id it HAD,
        # not the lowest free one -- same never-move rule as above.
        back = _released_ids.get(key)
        if back is not None and back in free:
            free = [back] + [c for c in free if c != back]
        if not free:
            log("idmap", f"charid {charid}: NO FREE FFXI Content ID "
                         f"(POL issues {pol_content_ids(member_id) or 'none'}, all taken by {sorted(used)}); "
                         f"passing the charid through untranslated -- this "
                         f"character will draw POL-0001 at char select. POL now "
                         f"issues POL_FFXI_CHARACTER_SLOTS ids per handle "
                         f"(accounts.ensure_ffxi_character_slots tops an existing "
                         f"handle up); raise it, or delete a character to free one")
            return None
        _idmap[key] = free[0]
        _released_ids.pop(key, None)
        save_idmap()
        log("idmap", f"charid {charid} -> Content ID {free[0]} "
                     f"({'re-paired after a failed delete' if free[0] == back else 'allocated'})")
        return free[0]


#: str(charid) -> the Content ID it held when `release_charid` dropped it. The
#: release happens on the client's 0x14 BEFORE LSB rules on the delete, so a
#: refused delete brings the character back in the next 0x20; this lets it
#: re-pair to the same id instead of the lowest free one.
_released_ids = {}


def release_charid(charid, why=""):
    """Drop a charid's pairing so its Content ID returns to the member's pool."""
    key = str(charid)
    with _idmap_lock:
        cid = _idmap.pop(key, None)
        _charnames.pop(key, None)
        _worldfields.pop(key, None)
        if cid is None:
            return None
        _released_ids[key] = cid
        save_idmap()
    log("idmap", f"charid {charid} released Content ID {cid}"
                 + (f" -- {why}" if why else ""))
    return cid


def charid_for(content_id):
    """Reverse lookup. Returns None for a value we never handed out, which is
    the right answer for a client that sent a real charid (nothing to undo)."""
    if not content_id:
        return None
    with _idmap_lock:
        for k, v in _idmap.items():
            if v == content_id:
                return int(k)
    return None


def resign(pkt):
    """Re-apply LSB's packet MD5 after a rewrite.

    LSB builds every lobby reply by zeroing `identifer`, hashing the whole packet
    and copying the digest into that field (`md5(pkt, hash, size)` +
    `copyHashIntoPacket`). Reproduce exactly that, over the framed length.
    """
    p = bytearray(pkt)
    p[HASH_OFF:HASH_OFF + HASH_LEN] = b"\0" * HASH_LEN
    p[HASH_OFF:HASH_OFF + HASH_LEN] = hashlib.md5(bytes(p)).digest()
    return bytes(p)


# ---------------------------------------------------------------------------
# WHICH POL MEMBER IS THIS?  (the multi-tenant problem)
#
# Every POL account used to land on the SAME FFXI character, for two independent
# reasons -- POL minted one Content ID for everybody (fixed in accounts.py), and
# the bridge authenticated to LSB as ONE shared account, so the character list
# came back identical no matter who asked.
#
# **The FFXI lobby stream carries no POL identity.** `0x26` is version and
# expansions, `0x1F` is a bare poke, and the first packet naming a Content ID is
# `0x07` -- the character SELECT, which is far too late: LSB has already built
# the list by then. So the identity cannot be read off the wire, and it has to
# come from POL.
#
# POL publishes it already: `auth-sessions.json`, written by the core stack's
# auth service, maps a session token to `{member_id, peer_ip, at}`. That file
# is on the data volume this container already mounts for accounts.db.
#
# Matching rule, in order:
#   1. exact `peer_ip` match, most recent -- correct wherever the services see
#      real client addresses (host networking, or clients arriving from
#      distinct addresses);
#   2. most recent session overall, with a LOUD log line -- behind Docker's
#      bridge network every client arrives as the gateway address (POL and
#      this container both see 172.18.0.1), so rule 1 can never fire. This is
#      right for sequential testing and WRONG for two clients at once; the log
#      line is there so nobody debugs a mixed-up character list for an hour.
# ---------------------------------------------------------------------------
POL_SESSIONS = os.environ.get("POL_AUTH_SESSIONS",
                              os.path.join(_HERE, os.pardir, "data", "auth-sessions.json"))
#: How stale a POL session may be and still be taken as "the member who just
#: pressed Play". A launch follows its login by seconds; hours later it is a
#: guess, and a wrong guess hands someone another player's characters.
POL_SESSION_MAX_AGE = float(os.environ.get("POL_SESSION_MAX_AGE", "43200"))


#: Session ids already handed to an FFXI connection. A claim is a TIE-BREAKER
#: between sessions that cannot otherwise be told apart (same address): with two
#: Viewers behind one NAT, the second launch takes the session not yet claimed.
#: It is NOT a reason to rank a session below other members' -- a POL session
#: launches FFXI as often as the game drops (every FFXI-3001 is a relaunch from
#: the same signed-in Viewer), and until 2026-09-04 that relaunch found its own
#: session claimed, sorted last, and was handed whichever OTHER member was
#: signed in. Offline-proven in tools/ffxi_bridge_test.py.
_claimed_sids = {}
_claimed_lock = threading.Lock()
#: How long a claim is held. Long enough to cover a whole play session (the VIEW
#: connection closes at the world handoff, but the sid must not be re-handed to
#: a different client while the first is playing).
CLAIM_TTL = float(os.environ.get("FFXI_CLAIM_TTL", "43200"))
#: Refuse a launch we cannot attribute to a SIGNED-IN POL session, instead of
#: guessing. Default ON: a wrong guess auto-creates an LSB account for the wrong
#: member, spends one of THEIR Content IDs on a character they never see, and
#: ends in POL-0001. A refusal costs one relogin.
REQUIRE_SIGNED_IN = os.environ.get("FFXI_REQUIRE_SIGNED_IN", "1") == "1"
#: Two signed-in POL sessions whose last activity is within this many seconds of
#: each other are treated as indistinguishable, and the launch is refused rather
#: than attributed to a guess. Generous by default: a Viewer left signed in on a
#: second account is the normal case here, and misfiling a character into it is
#: far worse than one relaunch.
AMBIGUOUS_WINDOW = float(os.environ.get("FFXI_AMBIGUOUS_WINDOW", "900"))
#: Appended to the resolution reason when two Viewers could not be told apart.
#: Carried per CONNECTION from there -- an earlier version kept a process-wide
#: set of "ambiguous members", which was never emptied, so one ambiguous launch
#: barred that member from creating a character for the life of the bridge, alone
#: or not. Ambiguity is a property of ONE attribution, not of a member.
AMBIGUOUS_MARK = "[AMBIGUOUS: creation blocked]"


def resolve_pol_member(client_ip):
    """(member_id, how) for the POL member behind this FFXI connection.

    **The join key is POL's SESSION ID, not the peer address**, and that is not a
    style preference -- see the `JOIN KEY` note over `_SESSIONS` in
    responders.py. POL keyed identity on the client IP until 2026-08-13 and it
    was the worst bug in that file: under a bridge-networked compose every
    client arrives through the Docker gateway, so 5,328 auth connections shared
    ONE address and
    the second player was served the first's account. POL's fix was to identify
    a launch by the client's own per-launch `USER` token (`_sid_for_user_token`).
    An address is a hint for ORDERING candidates and nothing else.

    Ranking, best first:
      1. **`viewer_open` -- the session is SIGNED IN right now.** POL sets this
         on the auth hop that holds the socket for the whole session and clears
         it on disconnect, so it is the one signal that cannot be beaten by a
         stale session. It had to be added because recency alone GUESSED WRONG
         in the field (2026-08-15): a previous account's session was 47s fresher
         than the signed-in one at the moment FFXI dialled, so the launch got the
         wrong member's LSB account -- POL-0001, no character, and the player's
         own character name reading as "already taken".
      2. then a recent `chars_at` (the `1:3` fetch), then recency of activity.
    Within any tier a matching `peer_ip` breaks ties -- a host-networked
    deployment sees real addresses, so it is informative there, and harmless
    behind NAT.
    """
    try:
        with open(POL_SESSIONS, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:
        log("member", f"cannot read {POL_SESSIONS} ({exc!r}); no member context")
        return None, "unreadable"
    now = time.time()
    with _claimed_lock:
        for sid in [s for s, t in _claimed_sids.items() if now - t > CLAIM_TTL]:
            del _claimed_sids[sid]
        claimed = set(_claimed_sids)
    cands = []
    for sid, ent in (raw.items() if isinstance(raw, dict) else []):
        if not isinstance(ent, dict) or not ent.get("member_id"):
            continue
        at = float(ent.get("at") or 0)
        if now - at > POL_SESSION_MAX_AGE:
            continue
        chars_at = float(ent.get("chars_at") or 0)
        peer = ent.get("peer_ip") or ""
        signed_in = bool(ent.get("viewer_open"))
        # sort key: unclaimed, SIGNED IN, launched-recently, active-recently, same-IP
        cands.append(((sid in claimed), (not signed_in), -chars_at, -at,
                      peer != client_ip, sid, int(ent["member_id"]), chars_at,
                      signed_in))
    if not cands:
        return None, "no live POL session"
    cands.sort()

    # THE ADDRESS, WHEN IT ACTUALLY DISCRIMINATES, IS THE ANSWER.
    #
    # `responders.py`'s JOIN KEY note is right that an address must never be the
    # join key -- under NAT every client shares one, which is how player two got
    # served player one's account. But the converse is also true and was being
    # wasted here: when exactly ONE signed-in session is dialling from this
    # client's address, that is not a guess, it is a fact, and it needs no
    # heuristic behind it.
    #
    # This is what makes the whole problem disappear on a deployment that sees
    # real source addresses, for EVERY client including the PS2 -- which cannot
    # run a PC-side session stamp, so no client-side fingerprint could ever
    # cover it. Behind Docker's bridge network both sides see the gateway
    # address (POL sees 172.18.0.1, the bridge 172.18.0.1), so this can never
    # fire there, and the heuristics below are the fallback -- scaffolding for
    # single-machine testing, not the design.
    signed_exact = [c for c in cands if c[1] is False and c[4] is False]   # signed in, ip matches
    pick = None
    if len(signed_exact) == 1:
        # Claimed or not: ONE signed-in session at this address is this launch.
        # A relaunch after a drop is the same session dialling again.
        pick, how_ip = signed_exact[0], "matched exactly one session"
    elif len(signed_exact) > 1:
        # Two Viewers behind one NAT. The claim is what tells them apart: the
        # launch that has not happened yet belongs to the session not yet claimed.
        unclaimed = [c for c in signed_exact if not c[0]]
        if len(unclaimed) == 1:
            pick, how_ip = unclaimed[0], (f"matched {len(signed_exact)} sessions, "
                                          f"exactly one not yet launched")
    if pick is not None:
        with _claimed_lock:
            _claimed_sids[pick[5]] = now
        return pick[6], (f"session {pick[5]}, SIGNED IN, peer_ip {client_ip} "
                         f"{how_ip} -- deterministic")
    # AMBIGUITY IS A REFUSAL, NOT A COIN FLIP.
    #
    # With two Viewers signed in there is nothing on the wire that says which one
    # pressed Play -- and picking wrong is expensive and SILENT: the character
    # gets created on the other account, the player cannot see it, and the only
    # symptom is POL-0001 much later. That is exactly how two characters
    # ended up on accounts that never asked for them (2026-08-16).
    #
    # So when the top two candidates are both plausibly current, stop. A refusal
    # is one relaunch with the other Viewer closed; a wrong guess is a character
    # stranded on someone else's account and a confusing error an hour later.
    live = [c for c in cands if c[1] is False and c[0] is False]   # signed in, unclaimed
    ambiguous = False
    if len(live) > 1:
        gap = abs(live[0][3] - live[1][3])       # difference of -at, i.e. seconds
        if gap < AMBIGUOUS_WINDOW:
            # AMBIGUOUS, BUT NOT FATAL -- and refusing here was a bad trade.
            #
            # Two people signed in at once is the NORMAL state of a working
            # server, and nothing on FFXI's wire says which Viewer launched (the
            # `0x26` "setup" packet is version and expansions; its only
            # high-entropy field is uninitialised client memory, FFXiMain
            # pointers and all). Refusing therefore blocked every launch whenever
            # a second player was online, which is far worse than the failure it
            # was guarding against.
            #
            # And it was guarding against less than I thought: **POL itself stops
            # the serious case.** Selecting a character requires a matching entry
            # in POL's own 64-slot character table, so a player handed the wrong
            # account's list cannot enter someone else's character -- they get
            # POL-0001. What is NOT protected is CREATE, which never consults
            # that table; that is how two characters were misfiled on
            # 2026-08-16. So: proceed, and gate the create instead.
            ambiguous = True
            log("member", f"AMBIGUOUS: {len(live)} signed-in POL sessions "
                          f"(members {live[0][6]} and {live[1][6]}) active within "
                          f"{gap:.0f}s, and FFXI's wire names nobody. Proceeding "
                          f"with member {live[0][6]} -- selecting an existing "
                          f"character is safe (POL's own table check refuses a "
                          f"mismatch), but CHARACTER CREATION is blocked while "
                          f"this is ambiguous.")
    was_claimed, _, _, _, _, sid, mid, chars_at, signed_in = cands[0]
    with _claimed_lock:
        _claimed_sids[sid] = now
    how = (f"session {sid}, {'SIGNED IN' if signed_in else 'not signed in'}, "
           + (f"1:3 fetched {now - chars_at:.0f}s ago" if chars_at else "no 1:3 seen")
           + (" " + AMBIGUOUS_MARK if ambiguous else ""))
    if not signed_in:
        log("member", f"the chosen POL session {sid} (member {mid}) is NOT marked "
                      f"signed in. Either POL has not served this Viewer's login "
                      f"since `viewer_open` was added, or the launch is riding a "
                      f"stale session -- which is how the wrong member's "
                      f"characters get served.")
        if REQUIRE_SIGNED_IN:
            # REFUSE rather than guess. Guessing is not free: a wrong member gets
            # an LSB account auto-created, spends one of that member's Content
            # IDs on a character they cannot see, and ends in POL-0001 -- which
            # is what happened twice on 2026-08-15 before this existed. Refusing
            # costs one relogin and damages nothing.
            log("member", "REFUSING the launch (FFXI_REQUIRE_SIGNED_IN=1). Sign "
                          "out of the PlayOnline Viewer and sign back in so POL "
                          "stamps the session, then launch again.")
            return None, "no signed-in POL session"
    if was_claimed:
        log("member", f"every POL session is already claimed; re-using {sid} "
                      f"(member {mid}). Two clients on one POL session is not a "
                      f"thing -- expect a crossed character list.")
        how += " (RE-USED)"
    return mid, how


# ---------------------------------------------------------------------------
# POL member  ->  LSB account
#
# One LSB account per POL member, auto-provisioned on first launch through LSB's
# own AUTH create (`login_cmd::LOGIN_CREATE = 0x20`), so the password is bcrypted
# by LSB rather than by us. The map is persisted because the password is
# generated once and there is no way to recover it afterwards.
# ---------------------------------------------------------------------------
ACCTMAP_FILE = os.environ.get("FFXI_ACCTMAP_FILE",
                              os.path.join(_HERE, "ffxi_accounts.json"))
#: Secret the per-member LSB password is DERIVED from. Deriving beats storing:
#: nothing has to be persisted, a lost map costs nothing, and the file left
#: behind carries no credential. Set it once and never rotate casually -- every
#: LSB password changes with it (recoverable, but it needs a LOGIN_CHANGE_PASSWORD
#: sweep). The default is only viable because LSB is not reachable off this host.
#:
#: **Why not the member's own PlayOnline password?** Three reasons, any one
#: sufficient. (1) We do not have it: `member.pw_hash`/`pw_salt` are a salted
#: hash, and POL's login does not even verify the password today -- the NICK
#: token is per-HANDLE, not per-password, so the plaintext may never cross the
#: wire in a recoverable form at all. (2) It would copy a user's password into a
#: third-party service's account table, and the bridge would have to hold the
#: plaintext at launch time to do it. (3) There is no benefit: nobody ever types
#: this password. The LSB account is machine-to-machine plumbing the player
#: never sees, so a derived random secret is strictly better than a shared one.
ACCT_SECRET = os.environ.get("FFXI_ACCT_SECRET", "")


def derive_lsb_password(member_id):
    """The LSB password for a POL member. Deterministic, never stored."""
    seed = ACCT_SECRET or f"pol-bridge-local:{ACCOUNTS_DB}"
    mac = hashlib.sha256(f"{seed}\x00lsb-account\x00{int(member_id)}".encode()).digest()
    # base64url without padding: LSB stores a bcrypt hash, but keep it to
    # characters that survive a JSON round trip and any shell that touches it.
    import base64
    return base64.urlsafe_b64encode(mac)[:24].decode()
#: LSB's `login_result` codes (auth_session.h) as they come back in `result`.
LOGIN_SUCCESS_CREATE      = 0x03
LOGIN_ERROR_CREATE_TAKEN  = 0x04
#: No seed: EVERY member gets its own account, member 1 included. The shared
#: LSB_ACCOUNT keeps existing (it is what the startup smoke-test auth uses) but
#: no member maps to it, so nothing lands there by default. A character that
#: was created on the shared account can be moved with
#: `tools/ffxi_provision.py rehome`.
ACCTMAP_SEED = {}
_acctmap = {}
_acctmap_lock = threading.Lock()


def load_acctmap():
    global _acctmap
    try:
        with open(ACCTMAP_FILE, "r", encoding="utf-8") as fh:
            _acctmap = json.load(fh)
    except FileNotFoundError:
        _acctmap = dict(ACCTMAP_SEED)
        save_acctmap()
    except Exception as exc:
        log("acct", f"{ACCTMAP_FILE} unreadable ({exc!r}); starting from the seed")
        _acctmap = dict(ACCTMAP_SEED)


def save_acctmap():
    try:
        tmp = ACCTMAP_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_acctmap, fh, indent=1, sort_keys=True)
        os.replace(tmp, ACCTMAP_FILE)
    except Exception as exc:
        log("acct", f"could not persist {ACCTMAP_FILE}: {exc!r}")


def lsb_account_for(member_id):
    """(login, password) for a POL member, creating the LSB account if needed.

    The password is DERIVED, not stored, so the map file is a record of which
    accounts exist rather than a credential store -- see `derive_lsb_password`.
    """
    tag = r_tag()
    key = f"{tag}:{member_id}" if tag else str(member_id)
    login = f"pol{member_id}"[:16]              # accounts.login is varchar(16)
    password = derive_lsb_password(member_id)
    with _acctmap_lock:
        if key in _acctmap:
            return _acctmap[key]["login"], password
    # Create FIRST, record SECOND. The map used to be written before the create
    # was attempted, so a create that never reached LSB (bridge up before
    # `connect`, LSB restarting) left a map entry for an account that did not
    # exist -- and every later launch trusted the entry, skipped the create, and
    # failed auth for that member for good (until the map was deleted by hand,
    # or until a redeploy discarded a map that lived inside the image).
    reply = lsb_auth_request(0x20, login, password)          # LOGIN_CREATE; raises if unreachable
    result = reply.get("result") if isinstance(reply, dict) else None
    if result == LOGIN_SUCCESS_CREATE:
        log("acct", f"POL member {member_id} -> new LSB account {login!r}")
    elif result == LOGIN_ERROR_CREATE_TAKEN:
        # Not an error: the map was lost while LSB kept the account (the password
        # is derived, so nothing else is needed).
        log("acct", f"POL member {member_id}: LSB account {login!r} already exists; recorded")
    else:
        raise RuntimeError(f"LSB refused to create account {login!r} for member "
                           f"{member_id}: {reply}")
    with _acctmap_lock:
        _acctmap[key] = {"login": login,
                         "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        save_acctmap()
    return login, password


def lsb_member_session(member_id):
    """(account_id, session_hash, login) for a POL member, healing a map entry
    whose account LSB does not have (a create that failed before 2026-09-04, or
    an LSB database that was reset under a surviving map)."""
    login, password = lsb_account_for(member_id)
    try:
        acct_id, sh = lsb_authenticate(login, password)
        return acct_id, sh, login
    except RuntimeError as first:
        try:
            reply = lsb_auth_request(0x20, login, password)
        except Exception:
            raise first
        if isinstance(reply, dict) and reply.get("result") == LOGIN_SUCCESS_CREATE:
            log("acct", f"POL member {member_id}: the map named {login!r} but LSB had "
                        f"no such account -- created it now and retrying the login")
            acct_id, sh = lsb_authenticate(login, password)
            return acct_id, sh, login
        raise first


def lsb_auth_request(command, username, password, new_password=None):
    """One LSB AUTH (54231, TLS + JSON) round trip.

    `new_password` is only read by `LOGIN_CHANGE_PASSWORD` (0x30), which LSB
    reads from the `new_password` field (auth_session.cpp:155).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((r_host(), r_auth()), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=r_host())
    req = {"command": command, "username": username,
           "password": password, "version": XILOADER_VER}
    if new_password is not None:
        req["new_password"] = new_password
    s.sendall(json.dumps(req).encode())
    data = s.recv(4096).rstrip(b"\x00")
    s.close()
    return json.loads(data.decode(errors="replace"))


def lsb_authenticate(username=None, password=None):
    """Do LSB's TLS+JSON auth and return (account_id, 16-byte session_hash)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((r_host(), r_auth()), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=r_host())
    req = {"command": 0x10, "username": username or LSB_ACCOUNT,
           "password": password or LSB_PASSWORD, "version": XILOADER_VER}
    s.sendall(json.dumps(req).encode())
    data = s.recv(4096).rstrip(b"\x00")
    s.close()
    reply = json.loads(data.decode(errors="replace"))
    if "account_id" not in reply or "session_hash" not in reply:
        raise RuntimeError(f"LSB auth failed: {reply}")
    sh = reply["session_hash"]
    session_hash = bytes(sh) if isinstance(sh, list) else sh.encode("latin1")
    if len(session_hash) != 16:
        raise RuntimeError(f"session_hash not 16 bytes: {sh!r}")
    return reply["account_id"], session_hash


# Cache the (account_id, hash) per client IP so a client's VIEW and DATA
# channels share ONE LSB session (xiloader does one auth per launch and injects
# the same hash into both). TTL lets a fresh login re-auth.
_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()
_SESSION_TTL = 300.0


def peek_client_version(client, timeout=3.0):
    """The six version characters the client reports, without eating the packet.

    Same MSG_PEEK trick as peek_pol_session below, and for the same reason: the
    backend has to be chosen before a byte is relayed, but the build only
    arrives with the client's first packet. Leaving it in the kernel buffer
    means the relay reads it normally afterwards and nothing downstream has to
    know this happened.

    Layout, from LSB's own reader (login/view_session.cpp case 0x26): the six
    characters at offset 0x74. LSB compares only those six -- it appends 'xx_x'
    to both sides -- so six is all a routing decision can use, and all we read.

    Returns None if the first packet is not a 0x26, is too short, or does not
    arrive in time. Every one of those means 'route to the primary', which is
    the pre-existing behaviour.
    """
    NEED = 0x7A                      # through the end of the six chars at 0x74
    try:
        client.settimeout(timeout)
        buf = b''
        deadline = time.time() + timeout
        while len(buf) < NEED and time.time() < deadline:
            try:
                buf = client.recv(256, socket.MSG_PEEK)
            except socket.timeout:
                break
            if not buf:
                return None
            if len(buf) < NEED:
                time.sleep(0.02)   # PEEK re-reads from the start; just wait for more
        if len(buf) < NEED:
            return None
        if buf[4:8] != b'IXFF':
            return None
        if buf[8] != 0x26:
            return None
        v = buf[0x74:0x7A]
        try:
            v = v.decode('ascii')
        except UnicodeDecodeError:
            return None
        return v if v.isprintable() else None
    except Exception:
        return None
    finally:
        try:
            client.settimeout(None)
        except Exception:
            pass


def peek_pol_session(client, timeout=3.0):
    """The POL session id stamped in the client's FIRST packet, without eating it.

    The LSB account has to be chosen before a single byte is relayed, but the
    stamp only arrives with the first packet -- so we look at it with MSG_PEEK
    and leave it in the kernel buffer for the relay to read normally. The
    alternative was restructuring the relay to read-then-connect, which would
    have put the client's first packet in a Python buffer where every later
    reader would have to know about it.

    A client with no shim (or an old one, or the PS2 Viewer) simply has no magic
    here, and the caller falls back to the address match and then the heuristics.
    """
    old = client.gettimeout()
    try:
        client.settimeout(timeout)
        data = client.recv(4096, socket.MSG_PEEK)
    except Exception:
        return None
    finally:
        try:
            client.settimeout(old)
        except Exception:
            pass
    if not data:
        return None
    return read_poltoken(bytes(data))


_FIRSTBYTE_LOG = {}          # ip -> last time we logged a no-bytes drop
_FIRSTBYTE_LOG_EVERY = 600.0


def wait_first_bytes(client, chan, addr, timeout=None):
    """Gate LSB auth on the client actually SAYING something.

    The old flow authenticated on accept(): pick a POL session for the IP,
    run a full LSB auth, claim the session -- all before the peer sent one
    byte. A monitoring probe on the host (127.0.0.1) connecting to 54001/54230
    every ~60s therefore burned 12,526 real LSB auths in 3 days, cycling
    through every LSB account and claiming real players' POL sessions
    ("every POL session is already claimed ... expect a crossed character
    list"). A refused/claimed session at a real launch is the POL-0001 shape.

    Every protocol on these ports is client-speaks-first (VIEW: the 0x26 the
    version peek reads; DATA: the 0xFE+hash registration we ourselves send
    when acting as the client), so a peer that closes or stays silent for
    `timeout` was never a game client. Returns True when bytes are waiting
    (left in the kernel buffer via MSG_PEEK); False means drop without auth.

    FFXI_AUTH_ON_ACCEPT=1 restores the old behaviour.
    """
    if os.environ.get("FFXI_AUTH_ON_ACCEPT", "").strip() == "1":
        return True
    if timeout is None:
        try:
            timeout = float(os.environ.get("FFXI_FIRST_BYTES_TIMEOUT", "") or 8.0)
        except ValueError:
            timeout = 8.0
    old = client.gettimeout()
    try:
        client.settimeout(timeout)
        data = client.recv(1, socket.MSG_PEEK)
    except Exception:
        data = b''
    finally:
        try:
            client.settimeout(old)
        except Exception:
            pass
    if data:
        return True
    now = time.time()
    ip = addr[0]
    if now - _FIRSTBYTE_LOG.get(ip, 0.0) > _FIRSTBYTE_LOG_EVERY:
        _FIRSTBYTE_LOG[ip] = now
        log(chan, f"client {addr} sent no bytes within {timeout:.0f}s -- "
                  f"probe or dead peer; dropped WITHOUT LSB auth "
                  f"(repeats from this IP muted {_FIRSTBYTE_LOG_EVERY:.0f}s)")
    return False


def get_session(client_ip, stamped_member=None, stamped_sid=None):
    """(account_id, session_hash, member_id) for a connecting FFXI client.

    Auth fresh per view connection. Caching risked handing back a hash whose LSB
    session had already been consumed, and a launch only makes one view
    connection anyway, so there is nothing to share. The data companion is
    (re)registered with whatever hash this returns -- see ensure_data_companion.

    The LSB account is now chosen by POL MEMBER, which is what keeps one
    member's characters out of another's list. With no member context we fall
    back to the shared account rather than refusing the launch -- that is the
    pre-2026-08-15 behaviour, and it is logged.
    """
    if stamped_member is not None:
        # THE STAMPED PATH: no inference at all. pol-shim saw this launch's own
        # `USER` token and the FFXI socket in one process, so it can state which
        # POL session opened it rather than leaving us to rank candidates.
        acct_id, sh, login = lsb_member_session(stamped_member)
        log("member", f"{client_ip} is POL member {stamped_member} -- STAMPED by "
                      f"pol-shim ({stamped_sid}), no guessing -> LSB account "
                      f"{login!r} (id {acct_id})")
        return acct_id, sh, stamped_member, False
    member_id, how = resolve_pol_member(client_ip)
    if member_id is None:
        if REQUIRE_SIGNED_IN:
            # Refusing is the safe failure: nothing is created, nothing is spent,
            # and the remedy is one relogin. Falling through to the shared account
            # would silently drop this launch back into the pre-isolation world
            # where every POL account sees the same characters.
            raise RuntimeError(
                f"no signed-in POL session for {client_ip} ({how}); refusing the "
                f"launch. Sign out of the PlayOnline Viewer and back in, then "
                f"launch FFXI again. Set FFXI_REQUIRE_SIGNED_IN=0 to fall back to "
                f"the shared account instead (characters will NOT be isolated).")
        log("member", f"{client_ip}: no POL member ({how}); using the shared "
                      f"account {LSB_ACCOUNT!r} -- characters will NOT be isolated")
        acct_id, sh = lsb_authenticate()
        return acct_id, sh, None, False
    acct_id, sh, login = lsb_member_session(member_id)
    log("member", f"{client_ip} is POL member {member_id} ({how}) "
                  f"-> LSB account {login!r} (id {acct_id})")
    return acct_id, sh, member_id, AMBIGUOUS_MARK in how


#: A client-side shim can stamp the PlayOnline session id into the lobby
#: packet's `identifer` field, which we overwrite on the way to LSB anyway. Four
#: bytes of magic so an untagged client is never mistaken for a tagged one, then
#: the first eight bytes of sha1(USER token), which is exactly what POL hashes
#: its session id from (`_sid_for_user_token` = "u" + that, in hex).
POLTOKEN_MAGIC = b"POLS"


def read_poltoken(pkt):
    """The POL session id a shimmed client stamped into this packet, or None.

    This is the ONLY attribution here that is not an inference. Everything else
    ranks candidates by address, recency or a signed-in flag, and all three have
    put a player on someone else's account in the field. A stamped packet says
    which session launched, so there is nothing to rank.
    """
    if len(pkt) < HDR_LEN or pkt[HASH_OFF:HASH_OFF + 4] != POLTOKEN_MAGIC:
        return None
    return "u" + pkt[HASH_OFF + 4:HASH_OFF + 12].hex()


def member_for_sid(sid):
    """POL member behind a session id, straight from POL's own session table."""
    try:
        with open(POL_SESSIONS, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return None
    ent = raw.get(sid) if isinstance(raw, dict) else None
    if isinstance(ent, dict) and ent.get("member_id"):
        return int(ent["member_id"])
    return None


def inject_hash(buf, session_hash):
    """Rewrite [12:28] with session_hash on IXFF lobby packets (xiloader parity).

    Frames by the leading LE u32 length when it looks like an IXFF packet; falls
    back to a whole-chunk check so a single-packet-per-recv client still works.
    """
    out = bytearray(buf)
    i = 0
    n = len(out)
    touched = 0
    while i + 12 <= n:
        # IXFF length-prefixed packet: [0:4]=size, [4:8]="IXFF"
        if out[i + 4:i + 8] == MAGIC:
            size = struct.unpack_from("<I", out, i)[0]
            if size < 12 or i + size > n:
                # incomplete/again odd; rewrite what we can and stop
                if i + 28 <= n and out[i + 8] in LOBBY_CMDS:
                    out[i + 12:i + 28] = session_hash
                    touched += 1
                break
            if out[i + 8] in LOBBY_CMDS and i + 28 <= n:
                out[i + 12:i + 28] = session_hash
                touched += 1
            i += size
        else:
            break
    return bytes(out), touched


#: Client->server commands whose payload opens with `ffxi_id` at offset 28.
#: 0x07 select and 0x14 delete are read there by LSB itself; 0x28 rename is
#: documented in view_session as "Character ID is sent at offset 28".
C2S_ID_AT_28 = {0x07, 0x14, 0x28}
#: `0x14` is the character DELETE. It frees the Content ID it names.
C2S_DELETE = 0x14
#: The two create-flow commands. LSB ignores whatever id they carry (it invents a
#: charid), but the client puts the Content ID it is spending in the same slot, so
#: this is where the authoritative pairing comes from.
C2S_CREATE = {0x21, 0x22}
#: `0x21` is the one that actually COMMITS the character (0x22 only checks the
#: name), so it is where the charid comes into existence and where the bridge
#: has to start racing -- see `request_charlist_refresh`.
C2S_CREATE_COMMIT = 0x21
#: LSB's ACK for the commit (`view_session.cpp` case 0x21 writes result 0x03).
C2S_CREATE_ACK = 0x03

_pkt_seq = 0
_pkt_seq_lock = threading.Lock()


def dump_packet(label, pkt):
    """Persist one framed lobby packet. The bridge log only ever carried the
    first 16 bytes, which is why the create request's fields were never read."""
    if not PKT_DUMP:
        return
    global _pkt_seq
    with _pkt_seq_lock:
        _pkt_seq += 1
        seq = _pkt_seq
    try:
        os.makedirs(PKT_DIR, exist_ok=True)
        cmd = pkt[8] if len(pkt) > 8 else 0xFF
        tag = label.replace(" ", "").replace(">", "2")
        with open(os.path.join(PKT_DIR, f"{seq:05d}-{tag}-cmd{cmd:02x}.bin"), "wb") as fh:
            fh.write(pkt)
    except Exception as exc:
        log(label, f"packet dump failed: {exc!r}")


def take_packet(buf):
    """Pop one complete IXFF packet off `buf`.

    Returns the packet bytes, None if more data is needed, or False if the buffer
    is not IXFF framing at all -- in which case the caller forwards it verbatim,
    so an unrecognised stream is relayed rather than stalled.
    """
    if len(buf) < 8:
        return None                     # too short to even check the magic
    if buf[4:8] != MAGIC:
        return False
    if len(buf) < 12:
        return None
    size = struct.unpack_from("<I", buf, 0)[0]
    if size < HDR_LEN or size > 0x10000:
        return False
    if len(buf) < size:
        return None
    pkt = bytes(buf[:size])
    del buf[:size]
    return pkt


#: Set while we are waiting for a char list WE asked for. The client did not
#: request it, so the reply must be swallowed rather than forwarded.
_swallow_charlist = {}
#: connection key -> LSB account id, for requests we originate.
_ACCT_IDS = {}
#: connection key -> when we saw the create COMMIT. The early char-list fetch fires on
#: LSB's ACK of it, never on the client's request: `rewrite_c2s` runs before the
#: packet is forwarded, so asking at that point would race LSB's own commit and
#: come back with a list that does not contain the new character.
_create_pending = {}

_swallow_lock = threading.Lock()
#: Give up swallowing after this long, so a lost/never-sent reply cannot make us
#: eat the client's own next char list.
SWALLOW_TTL = 10.0


def request_charlist_refresh(ckey, label):
    """Ask LSB for the character list on the DATA channel, for ourselves.

    Sends the same `0xA1` the client's `0x1F` would have triggered. LSB answers
    by writing a `0x20` to this client's VIEW socket, which reaches us first
    because we are the relay -- we parse it for the new charid and drop it.
    """
    with _DATA_LOCK:
        ent = _DATA_COMPANIONS.get(ckey)
    if ent is None:
        log("DATA-COMP", f"cannot pre-fetch the char list for {ckey}: "
                         f"no data companion")
        return
    sock, _sh = ent
    ip = ckey
    with _swallow_lock:
        _swallow_charlist[ip] = time.time()
    try:
        sock.sendall(build_data_request(0xA1, _ACCT_IDS.get(ip, 0), _sh))
        log("DATA-COMP", f"  -> sent 0xA1 EARLY for {ip} (racing the client's POL "
                        f"1:3 refetch, so the new charid is known before POL is asked)")
    except Exception as exc:
        with _swallow_lock:
            _swallow_charlist.pop(ip, None)
        log("DATA-COMP", f"early 0xA1 failed: {exc!r}")


def should_swallow_charlist(ckey):
    """True once, for a char list this bridge asked for."""
    with _swallow_lock:
        at = _swallow_charlist.get(ckey)
        if at is None:
            return False
        del _swallow_charlist[ckey]
        return (time.time() - at) <= SWALLOW_TTL


def rewrite_c2s(pkt, label, member_id=None, ckey=None, ambiguous=False):
    """Client -> LSB: turn a POL Content ID back into the LSB charid."""
    cmd = pkt[8]
    if cmd in C2S_CREATE and ambiguous:
        # BLOCK THE CREATE, allow everything else. A select is protected by POL's
        # own character-table check (a mismatch surfaces as POL-0001 rather than
        # entering someone else's character); a create is not, and would silently
        # land on whichever account we guessed. Dropping the connection is a
        # blunt refusal, but it happens BEFORE anything is written, which is the
        # whole point.
        log(label, f"  cmd 0x{cmd:02x}: REFUSING character creation -- this "
                   f"launch could not be attributed to one POL session (two "
                   f"Viewers signed in). Sign out of the other Viewer, then "
                   f"create. Playing an existing character is unaffected.")
        raise RuntimeError("character creation blocked: ambiguous POL session")
    if cmd in C2S_CREATE:
        # Record only -- there is nothing to translate, because LSB does not read
        # the id on the create path. The charid it is about to mint is unknown
        # here, so the pairing is completed when the new char shows up in 0x20.
        named = struct.unpack_from("<I", pkt, HDR_LEN)[0]
        if named and ckey:
            # ONE pending id per CONNECTION, latest wins. 0x22 (name check) and
            # 0x21 (commit) both carry it, and a rejected name is re-sent, so a
            # list grew one entry per packet and the extras were consumed by the
            # WRONG slots of the next 0x20 (see content_id_for). A dict keyed by
            # connection also stops two clients creating at once from trading ids.
            with _idmap_lock:
                _pending_create[ckey] = named
            log(label, f"  cmd 0x{cmd:02x}: client named Content ID {named} for the new character")
        if cmd == C2S_CREATE_COMMIT:
            # RACE THE CLIENT TO POL. Measured 2026-08-16: after a create the
            # client re-fetches POL's `1:3` about SIX seconds later, and only
            # asks FFXI for the new character list about EIGHT seconds later --
            # so POL is asked first, and at that moment nothing outside LSB knows
            # the charid the create just minted. POL therefore serves a character
            # table with no world identity for the new character, FFXI's lookup
            # misses, and the player gets POL-0001 on a character that was
            # created perfectly.
            #
            # Retail has no such race: PlayOnline ISSUES the Content ID and SE's
            # lobby is the same backend, so POL already knows. Our split puts the
            # knowledge in LSB, and the bridge is the only thing that sees both.
            #
            # So ask LSB ourselves, immediately, instead of waiting for the
            # client to. `request_charlist_refresh` pokes the data channel and
            # SWALLOWS the char list that comes back -- the client never asked
            # for it and must not see it -- purely to learn the pairing in time.
            if ckey:
                with _swallow_lock:
                    _create_pending[ckey] = time.time()
        return pkt
    if cmd not in C2S_ID_AT_28 or len(pkt) < HDR_LEN + 4:
        return pkt
    val = struct.unpack_from("<I", pkt, HDR_LEN)[0]
    cid = charid_for(val)
    if cid is None:
        return pkt
    out = bytearray(pkt)
    struct.pack_into("<I", out, HDR_LEN, cid)
    log(label, f"  cmd 0x{cmd:02x}: ffxi_id {val} (Content ID) -> {cid} (charid)")
    if cmd == C2S_DELETE:
        # RELEASE THE CONTENT ID. Deleting a character used to leave its pairing
        # in the map forever, so the id stayed "spent": POL issues exactly one
        # FFXI Content ID per member (handle_content's PK is (handle_id,
        # content_code)), so after one delete the member had NO free id, the next
        # character was passed through untranslated, and the client got a raw
        # charid that POL's character table knows nothing about -- POL-0001, from
        # a delete that looked like it had worked.
        #
        # Safe if the delete then fails: the character reappears in the next 0x20
        # and is paired again, drawing the same id back out of the member's pool.
        release_charid(cid, why=f"deleted (cmd 0x{cmd:02x})")
    return bytes(out)


def rewrite_s2c(pkt, label, member_id=None, ckey=None):
    """LSB -> client: put the POL Content ID in `ffxi_id`, leaving the world id.

    `ckey` names the client connection, so the id it named on its create goes
    to the charid that is NEW to the map in this list and to nothing else."""
    global _world_id
    cmd = pkt[8]
    out = bytearray(pkt)
    changed = False
    if cmd == 0x23 and len(pkt) >= WORLD_LIST_FIRST_NO + 4:
        # Learn the world id from the authority rather than assuming LSB's
        # hardcoded 0x20 -- if that ever becomes configurable, this follows it.
        seen = struct.unpack_from("<I", pkt, WORLD_LIST_FIRST_NO)[0]
        if seen and seen != _world_id:
            log(label, f"  0x23 world list: world id is 0x{seen:02X} "
                       f"(was using 0x{_world_id:02X})")
            _world_id = seen
    if cmd == 0x20 and len(pkt) >= CHR_LIST_OFF:
        count = struct.unpack_from("<I", pkt, HDR_LEN)[0]
        slots = range(min(count, (len(pkt) - CHR_LIST_OFF) // CHR_REC_LEN))
        empty = []
        for i in slots:
            off = CHR_LIST_OFF + i * CHR_REC_LEN
            charid = struct.unpack_from("<I", pkt, off)[0]
            if not charid:
                empty.append((i, off))
                continue
            with _idmap_lock:
                # The named id is for the character that does not have a pairing
                # yet. An already-paired slot must not consume it -- that is how
                # a second character used to swap ids with the first.
                prefer = (_pending_create.pop(ckey, None)
                          if ckey and str(charid) not in _idmap else None)
            cid = content_id_for(charid, prefer=prefer, member_id=member_id)
            name = bytes(pkt[off + 12:off + 28]).split(b"\0")[0].decode("latin1")
            note_char_name(charid, name)
            if WORLD_ID_FIX and struct.unpack_from("<H", pkt, off + CHR_REC_WORLDID)[0] != _world_id:
                struct.pack_into("<H", out, off + CHR_REC_WORLDID, _world_id)
                changed = True
                log(label, f"  0x20 slot {i}: worldid 0 -> 0x{_world_id:02X} "
                           f"(matching the world list)")
            # Read the identity fields back out of `out`, i.e. AFTER the worldid
            # fix -- what the client is told, not what LSB said.
            main = struct.unpack_from("<H", out, off + 4)[0]
            worldid = struct.unpack_from("<H", out, off + CHR_REC_WORLDID)[0]
            tbl = out[off + 11]
            note_world_field(charid, pack_world_field(main, worldid, tbl))
            # THE PROFILE TAIL, from the same record, for POL's 05:04. Read out
            # of `out` for the same reason the world field is: what the client
            # was told. The zone is reassembled from its two halves -- see
            # CHR_REC_ZONE_HI, which is the difference between "Al Zahbi" and a
            # zone 256 rows down the enum.
            note_char_fields(charid, {
                "world": bytes(out[off + CHR_REC_WORLDNAME:
                                   off + CHR_REC_WORLDNAME + 16]
                               ).split(b"\0")[0].decode("latin1").strip(),
                "nation": out[off + CHR_REC_NATION],
                "zone": out[off + CHR_REC_ZONE]
                        | ((out[off + CHR_REC_ZONE_HI] & 1) << 8),
                "job": out[off + CHR_REC_JOB],
                "joblevel": out[off + CHR_REC_JOBLEVEL],
                "race": struct.unpack_from("<H", out, off + CHR_REC_RACE)[0],
            })
            if cid is None:
                continue
            struct.pack_into("<I", out, off, cid)
            changed = True
            log(label, f"  0x20 slot {i}: {name!r} charid {charid} -> ffxi_id {cid}")
        # An EMPTY slot is where the client creates, and in retail it carries the
        # unused Content ID that the new character will be registered against --
        # LSB has none to put there and sends 0. Handing the client a real free
        # Content ID is what lets it name one on the create request, which is the
        # pairing `rewrite_c2s` then records. Slots past our entitlement keep the
        # 0 LSB sent, which reads as "not available".
        with _idmap_lock:
            taken = set(_idmap.values())
        free = [c for c in pol_content_ids(member_id) if c not in taken]
        for (i, off), cid in zip(empty, free):
            struct.pack_into("<I", out, off, cid)
            changed = True
            log(label, f"  0x20 slot {i}: EMPTY -> free Content ID {cid}")
        if len(empty) > len(free):
            log(label, f"  0x20: {len(empty) - len(free)} empty slot(s) left at ffxi_id 0 "
                       f"-- POL issues {len(pol_content_ids(member_id))} FFXI Content ID(s), "
                       f"{len(taken)} already spent")
    elif cmd == 0x0B and len(pkt) >= HDR_LEN + 8 + 16:
        # The handoff names the character that is entering the world, so it is
        # the authoritative moment to bind name <-> Content ID.
        charid = struct.unpack_from("<I", pkt, HDR_LEN)[0]
        note_char_name(charid, bytes(pkt[HDR_LEN + 8:HDR_LEN + 24])
                       .split(b"\0")[0].decode("latin1"))
        if WORLD_ID_FIX and len(pkt) >= NEXT_LOGIN_SERVER_ID + 4:
            was = struct.unpack_from("<I", pkt, NEXT_LOGIN_SERVER_ID)[0]
            if was != _world_id:
                struct.pack_into("<I", out, NEXT_LOGIN_SERVER_ID, _world_id)
                changed = True
                log(label, f"  0x0B handoff: server_id {was} -> 0x{_world_id:02X} "
                           f"(matching the world list)")
        # The ffxi_id REWRITE is off by default -- see MAP_HANDOFF. Rewriting that
        # field breaks the world login.
        cid = content_id_for(charid) if MAP_HANDOFF else None
        if cid is not None:
            struct.pack_into("<I", out, HDR_LEN, cid)
            changed = True
            log(label, f"  0x0B handoff: ffxi_id {charid} -> {cid} "
                       f"(ffxi_id_world left at {struct.unpack_from('<I', pkt, HDR_LEN + 4)[0]})")
    if not changed:
        return pkt
    return resign(bytes(out))


#: connection key -> the Content ID the client named on its create request,
#: waiting to be paired with the charid LSB mints for it (which only appears in
#: the next 0x20). One per connection: see rewrite_c2s.
_pending_create = {}


def pump(src, dst, rewrite, session_hash, label, member_id=None, ckey=None,
         ambiguous=False):
    """Relay one direction, framing the IXFF stream so packets can be rewritten.

    Framing (rather than the old per-recv chunking) is what makes the Content-ID
    translation possible at all: a rewrite has to know where each packet starts
    and how long it is, both to find `ffxi_id` and to re-sign. Anything that does
    not parse as IXFF is forwarded verbatim.
    """
    buf = bytearray()
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            buf += data
            out = bytearray()
            while buf:
                pkt = take_packet(buf)
                if pkt is None:
                    break                       # partial: wait for the rest
                if pkt is False:                # not our framing: pass it on
                    log(label, f"{len(buf)}B non-IXFF, forwarded verbatim {hexdump(buf, 16)}")
                    out += bytes(buf)
                    buf.clear()
                    break
                # Dump the packet AS RECEIVED, before any rewrite -- and again
                # after, if we changed it, so the captures show both sides of the
                # translation rather than silently the pre-rewrite bytes.
                dump_packet(label, pkt)
                cmd, orig = pkt[8], pkt
                if rewrite:
                    if FFXI_ID_MAP:
                        pkt = rewrite_c2s(pkt, label, member_id, ckey, ambiguous)
                    pkt, touched = inject_hash(pkt, session_hash)
                    log(label, f"{len(pkt)}B cmd=0x{cmd:02x} "
                               f"{'hash injected' if touched else 'passthrough'} {hexdump(pkt, 16)}")
                else:
                    if FFXI_ID_MAP:
                        pkt = rewrite_s2c(pkt, label, member_id, ckey)
                    if pkt != orig:
                        dump_packet(label + "-rewritten", pkt)
                    if cmd == C2S_CREATE_ACK and ckey:
                        with _swallow_lock:
                            pend = _create_pending.pop(ckey, None)
                        if pend is not None:
                            request_charlist_refresh(ckey, label)
                    if cmd == 0x20 and ckey and should_swallow_charlist(ckey):
                        # OUR char list, not the client's -- it never asked, so
                        # forwarding it would inject an unsolicited packet into a
                        # client sitting on the create screen. rewrite_s2c has
                        # already done the only thing we wanted: recorded the new
                        # charid -> Content ID pairing and its world field, in
                        # time for the POL `1:3` the client is about to make.
                        log(label, f"{len(pkt)}B cmd=0x20 SWALLOWED (the early "
                                   f"char list we asked for; pairing recorded)")
                        continue
                    log(label, f"{len(pkt)}B cmd=0x{cmd:02x} s->c {hexdump(pkt, 16)}")
                out += pkt
            if out:
                dst.sendall(bytes(out))
    except Exception as e:
        log(label, f"pump ended: {e}")
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


# Per-CONNECTION companion DATA connection to LSB (keyed "ip:port" of the
# client's VIEW socket -- it was keyed by IP alone until 2026-09-04, so two
# players behind one router replaced each other's LSB data session and the
# first one's next 0x1F drew FFXI-3332). The real POL client never
# opens LSB's data channel (54230) -- it uses the POL lobby (51220) instead --
# but LSB's view_session 0x1F handler ("Acquiring Player Data") requires a
# session.data_session to exist or it errors COULD_NOT_CONNECT (= FFXI-3332).
# So the bridge opens+registers the data channel itself, exactly like xiloader's
# FFXiServer does (send 0xFE + hash to register), and logs what LSB sends there
# (the character-list/profile data we will need to route to the client via the
# POL lobby). This is the xiloader data-channel role, played server-side.
_DATA_COMPANIONS = {}       # connection key -> (socket, session_hash)
_VIEW_SOCKETS = {}          # connection key -> the client's live VIEW socket
_DATA_LOCK = threading.Lock()
# DISPROVEN 2026-08-13: forwarding LSB's data-channel bytes to the client's VIEW
# socket makes the client force-close (WinError 10054) -> FFXI-3101. The client
# will not accept data-channel responses over view. The FFXI data/profile channel
# is the POL lobby (51220), a separate transport. Kept off by default; the flag
# remains only for re-testing.
FORWARD_DATA_TO_VIEW = os.environ.get("FORWARD_DATA_TO_VIEW", "0") == "1"


#: xiloader's `0xA2` payload, VERBATIM (`network.cpp`, case 0x0002/0x0015). It is
#: a hardcoded 25-byte constant and **it is not a request -- it is the WORLD
#: SESSION KEY**, which is why it must not be built like the other commands:
#:
#:     data_session.cpp case 0xA2:
#:         uint8 key3[20] = {};
#:         memcpy(key3, buffer_.data() + 1, sizeof(key3));   <-- bytes 1..20
#:         INSERT INTO accounts_sessions(..., session_key, ...) VALUES(..., key3, ..)
#:
#: and the map then loads that row into `PSession->blowfish.key` and deciphers
#: every world packet with it (map_networking.cpp:282-302). So bytes 1..16 are
#: the Blowfish key material -- ZERO, the same zero key the client is using --
#: and bytes 17..20 are the counter seed LSB bumps per zone (`key3[16] += 6` for
#: a freshly created character, `+= incrementKeyValue` otherwise).
#:
#: We were sending `build_data_request(0xA2, ...)`, which puts the account id,
#: the search IP and the first nine bytes of the LSB session hash exactly where
#: the key belongs. The client then discards every world packet the map sends --
#: measured 2026-08-15 as 73 datagrams each way with the client's ACK field
#: stuck at 0 for two and a half minutes, ending in FFXI-3001.
A2_SESSION_KEY = bytes.fromhex("00" * 16 + "58e05dad")


def build_data_request(cmd, account_id, session_hash):
    """Build an LSB data-server request (xiloader's data-side protocol).
    Layout LSB's data_session reads: [0]=cmd, [1:5]=accountID u32, [5:9]=serverIP
    u32 (search server), [12:28]=sessionHash. 28 bytes, matching the 0xFE reg.

    **`0xA2` does NOT use this layout** -- see `A2_SESSION_KEY`. Passing it here
    is refused rather than silently mis-built, because the failure it causes is
    two hundred seconds away from its cause and looks like a network fault.
    """
    if cmd == 0xA2:
        raise ValueError("0xA2 carries the session key, not a request "
                         "-- use build_a2_request()")
    p = bytearray(28)
    p[0] = cmd
    struct.pack_into("<I", p, 1, account_id)
    p[5:9] = socket.inet_aton(SEARCH_IP)
    p[12:28] = session_hash
    return bytes(p)


def build_a2_request():
    """The `0xA2` commit, byte-identical to xiloader's."""
    p = bytearray(28)
    p[0] = 0xA2
    p[1:1 + len(A2_SESSION_KEY)] = A2_SESSION_KEY
    return bytes(p)


def data_companion_reader(sock, ckey, account_id, session_hash, chan):
    """LSB pokes the data channel when the client asks something on view:
      poke byte 0x01  (from view 0x1F "Acquiring Player Data") -> we answer 0xA1,
                       which makes LSB build the char list and send 0x20 to the
                       client on the VIEW socket itself (data_session.cpp:304).
      poke byte 0x02  (from view 0x07 "Select Character")      -> we answer 0xA2
                       (commit selection -> world handoff 0x0B on view).
    So the companion is xiloader's data-side role, played server-side.
    """
    try:
        while True:
            b = sock.recv(8192)
            if not b:
                break
            code = b[0] if b else None
            log(chan, f"LSB data-chan {len(b)}B code={code}: {hexdump(b, 32)}")
            if code == 0x01:
                req = build_data_request(0xA1, account_id, session_hash)
                sock.sendall(req)
                log(chan, f"  -> sent 0xA1 (get char list) acct={account_id}")
            elif code in (0x02, 0x15):
                # xiloader answers BOTH pokes with the same payload
                # (`case 0x0002: case 0x0015:`); 0x15 was previously unanswered.
                req = build_a2_request()
                sock.sendall(req)
                log(chan, f"  -> sent 0xA2 (commit selection + world session key "
                          f"{A2_SESSION_KEY.hex()})")
            elif FORWARD_DATA_TO_VIEW:
                with _DATA_LOCK:
                    vs = _VIEW_SOCKETS.get(ckey)
                if vs is not None:
                    try:
                        vs.sendall(b)
                    except Exception as e:
                        log(chan, f"  -> forward to VIEW failed: {e}")
    except Exception as e:
        log(chan, f"data companion reader ended: {e}")
    finally:
        with _DATA_LOCK:
            cur = _DATA_COMPANIONS.get(ckey)
            if cur is not None and cur[0] is sock:
                del _DATA_COMPANIONS[ckey]
        try:
            sock.close()
        except Exception:
            pass


def ensure_data_companion(ckey, account_id, session_hash):
    # The companion MUST be registered with the SAME hash the view connection
    # uses, or LSB's per-(ip,hash) session lookup fails and 0x1F -> FFXI-3332.
    # Re-register whenever the session hash changed (new launch / re-auth) or the
    # socket died.
    with _DATA_LOCK:
        existing = _DATA_COMPANIONS.get(ckey)
        if existing is not None:
            old_sock, old_hash = existing
            alive = True
            try:
                old_sock.fileno()
            except Exception:
                alive = False
            if alive and old_hash == session_hash:
                return
            _DATA_COMPANIONS.pop(ckey, None)
            if old_hash != session_hash:
                log("DATA-COMP", f"session hash changed for {ckey}; re-registering")
            try:
                old_sock.close()
            except Exception:
                pass
    try:
        s = socket.create_connection((r_host(), r_data()), timeout=10)
        s.settimeout(None)  # keep the data_session alive for the whole login
    except Exception as e:
        log("DATA-COMP", f"connect to LSB data {LSB_DATA_PORT} failed: {e}")
        return
    # xiloader network.cpp: sendBuffer[0]=0xFE, [12:28]=hash, send 28 bytes.
    reg = bytearray(28)
    reg[0] = 0xFE
    reg[12:28] = session_hash
    try:
        s.sendall(bytes(reg))
    except Exception as e:
        log("DATA-COMP", f"registration send failed: {e}")
        s.close()
        return
    with _DATA_LOCK:
        _DATA_COMPANIONS[ckey] = (s, session_hash)
        _ACCT_IDS[ckey] = account_id
    log("DATA-COMP", f"registered data_session for {ckey} "
                     f"hash={session_hash.hex()} (0xFE + hash, 28B)")
    threading.Thread(target=data_companion_reader,
                     args=(s, ckey, account_id, session_hash, "DATA-COMP"),
                     daemon=True).start()


def handle_client(client, addr, lsb_port, chan):
    # A peer that never speaks was never a game client -- drop it before it
    # costs an LSB auth or a POL session claim. See wait_first_bytes.
    if not wait_first_bytes(client, chan, addr):
        try:
            client.close()
        except Exception:
            pass
        return
    # Pick the world BEFORE authenticating -- get_session/ensure_data_companion
    # both talk to whichever LSB this thread is routed at. VIEW only: the DATA
    # channel carries no 0x26, and its companion follows the VIEW decision.
    if chan == "VIEW" and LSB_ALT_VER and LSB_ALT_HOST:
        ver = peek_client_version(client)
        if ver == LSB_ALT_VER:
            _ROUTE.host = LSB_ALT_HOST
            _ROUTE.auth = LSB_ALT_AUTH_PORT
            _ROUTE.data = LSB_ALT_DATA_PORT
            _ROUTE.name = f"alt({LSB_ALT_VER})"
            _ROUTE.tag  = 'alt'
            lsb_port    = LSB_ALT_VIEW_PORT
        else:
            _ROUTE.host = _ROUTE.auth = _ROUTE.data = None
            _ROUTE.name = _ROUTE.tag = None
        log(chan, f"client build {ver!r} -> {r_name()} world "
                  f"({r_host()}:{lsb_port})")
    log(chan, f"client {addr} connected; authenticating to LSB...")
    # Everything this connection owns (data companion, pending create, swallow
    # flag) hangs off THIS key, never the bare address.
    ckey = f"{addr[0]}:{addr[1]}"
    try:
        # Look for pol-shim's stamp before choosing an LSB account. Costs one
        # MSG_PEEK and removes the guesswork entirely when it is present.
        stamped_sid = peek_pol_session(client) if chan == "VIEW" else None
        stamped_member = member_for_sid(stamped_sid) if stamped_sid else None
        if stamped_sid and stamped_member is None:
            log(chan, f"client stamped session {stamped_sid}, but POL has no such "
                      f"session -- falling back. (A stale stamp means the Viewer "
                      f"logged in before POL restarted.)")
        account_id, session_hash, member_id, ambiguous = get_session(
            addr[0], stamped_member, stamped_sid)
        log(chan, f"LSB session: account_id={account_id} "
                  f"hash={session_hash.hex()} (shared per client IP)")
    except Exception as e:
        log(chan, f"LSB auth FAILED: {e}; dropping client")
        client.close()
        return
    # Ensure LSB has a data_session for this client before the view handshake
    # reaches 0x1F (which needs it). Idempotent per client IP.
    if chan == "VIEW":
        with _DATA_LOCK:
            _VIEW_SOCKETS[ckey] = client
        ensure_data_companion(ckey, account_id, session_hash)
    try:
        upstream = socket.create_connection((r_host(), lsb_port), timeout=10)
        # The 10s is a CONNECT deadline only. Leaving it on the socket makes the
        # relay tear itself down after 10 seconds of LSB silence -- and LSB is
        # silent for as long as the player sits on the character-creation screen
        # picking a face and a name. That teardown reaches the client as
        # "Client Link Dead", with no bytes ever exchanged. `ensure_data_companion`
        # already clears it for the companion socket; this one was missed.
        upstream.settimeout(None)
    except Exception as e:
        log(chan, f"connect to LSB {r_host()}:{lsb_port} failed: {e}")
        client.close()
        return
    log(chan, f"relaying client<->LSB:{lsb_port}")
    t1 = threading.Thread(target=pump, args=(client, upstream, True, session_hash, f"{chan} c->s", member_id, ckey, ambiguous), daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, False, session_hash, f"{chan} s->c", member_id, ckey), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    with _DATA_LOCK:
        _VIEW_SOCKETS.pop(ckey, None)
        _ACCT_IDS.pop(ckey, None)
    with _swallow_lock:
        _swallow_charlist.pop(ckey, None)
        _create_pending.pop(ckey, None)
    with _idmap_lock:
        _pending_create.pop(ckey, None)
    log(chan, f"client {addr} session closed")


def listener(bind_port, lsb_port, chan):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", bind_port))
    srv.listen(8)
    log(chan, f"listening on 0.0.0.0:{bind_port} -> LSB {LSB_HOST}:{lsb_port}")
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle_client, args=(client, addr, lsb_port, chan), daemon=True).start()


# ---------------------------------------------------------------------------
# THE WORLD (MAP) CHANNEL -- a plain UDP relay, added purely to make it OBSERVABLE.
#
# After the 0x0B handoff the client is supposed to send its world-login packet
# (0x00A) by UDP to the address the handoff named. When that stops working there
# is nothing to read: LSB's map server logs NOTHING on its receive path
# (`MapSocket::Impl::armReceive` just queues the datagram), and every rejection in
# `recv_parse` is a silent `return -1`. So "the client never sent it" and "the map
# threw it away" look identical -- which is exactly the wall the POL-0001 chase hit.
#
# This relays UDP 54230 to the map container and decodes the first datagram of
# each client, which answers both questions at once and settles what `UniqueNo`
# actually is (the field the pending-session lookup keys on).
#
# NOTHING IS REWRITTEN HERE. The world protocol is Blowfish-enciphered from the
# second packet on and carries its own checksums; this only copies bytes.
# ---------------------------------------------------------------------------
MAP_HOST      = os.environ.get("MAP_HOST", "map")
MAP_PORT      = int(os.environ.get("MAP_PORT", "54230"))
BRIDGE_MAP    = int(os.environ.get("BRIDGE_MAP_PORT", "0"))   # 0 = relay disabled
_UDP_SEEN     = {}


def decode_world_login(d):
    """Decode a 0x00A GP_CLI_COMMAND_LOGIN datagram for the log.

    Offsets are FFXI_HEADER_SIZE (0x1C) + the GP_CLI_HEADER (4) + the field's own
    offset, read off `src/map/packets/c2s/0x00a_login.h`.
    """
    if len(d) < 0x6C:
        return f"{len(d)}B, too short for 0x00A"
    pid = struct.unpack_from("<H", d, 0x1C)[0] & 0x1FF
    if pid != 0x00A:
        return f"{len(d)}B, packet id 0x{pid:03X} (not 0x00A)"
    uniq = struct.unpack_from("<I", d, 0x28)[0]
    name = bytes(d[0x3E:0x4D]).split(b"\0")[0].decode("latin1", "replace")
    acct = bytes(d[0x4D:0x5C]).split(b"\0")[0].decode("latin1", "replace")
    ticket = bytes(d[0x5C:0x6C]).hex()
    return (f"0x00A world login: UniqueNo={uniq} name={name!r} account={acct!r} "
            f"ticket={ticket}")


def world_login_charid(d):
    """The charid the map will look the session key up by, or None.

    `recv_parse` uses `loginPacket.UniqueNo` DIRECTLY as the charid in its
    `accounts_sessions` join, so this reads it the same way LSB does rather
    than translating it -- if the two ever disagree, the watch logging "no
    accounts_sessions row" is the symptom worth seeing.
    """
    if len(d) < 0x6C:
        return None
    if (struct.unpack_from("<H", d, 0x1C)[0] & 0x1FF) != 0x00A:
        return None
    return struct.unpack_from("<I", d, 0x28)[0]


# ---------------------------------------------------------------------------
# World-channel instrumentation
#
# The counters below tell you THAT traffic moved. They cannot tell you what the
# two ends disagreed about, and on 2026-08-26 that was the whole question: the
# map logged `map_decipher_packet: bad packet` once per client datagram for 27 s
# and then dropped the session, twice, ~43 s after `InsertPC` both times. A live
# conversation neither end can decipher is not a timeout and not a refusal, and
# no counter distinguishes "wrong key" from "damaged datagram".
#
# So capture the bytes: one JSON line per datagram, payload base64, so an
# offline decoder can recover the key the CLIENT enciphered with -- the one
# value nothing on our side can otherwise see (tools/ffxi_bfdiff is the C++
# reference for that cipher).
#
# WARNING: THE FIRST FAILING DATAGRAM IS THE ONE THAT DECIDES. If the very first world
# datagram will not decipher, the key was already wrong and the relay is
# innocent; if the first N are clean and then they stop, the key was right and
# something broke mid-stream. That is why this captures from the flow's first
# datagram and not from the first error -- by the time an error is visible in
# map-server.log the evidence that discriminates is already gone.
WORLD_CAPTURE   = os.environ.get("FFXI_WORLD_CAPTURE", "1") == "1"
WORLD_CAP_DIR   = os.environ.get("FFXI_WORLD_CAP_DIR", os.path.join(PKT_DIR, "world"))
#: Per-flow ceilings. A world session at gameplay rate is ~2-3 datagrams/s each
#: way at ~150 B, so 20k datagrams is well over an hour and 32 MB is never
#: reached first. Bounded because this writes to the same small volume the
#: server logs live on -- an unbounded capture is an outage waiting for a long
#: session.
WORLD_CAP_MAX   = int(os.environ.get("FFXI_WORLD_CAP_MAX", "20000"))
WORLD_CAP_BYTES = int(os.environ.get("FFXI_WORLD_CAP_BYTES", str(32 << 20)))
#: How many capture files to keep. Per-file ceilings bound one flow; without
#: this the FILE COUNT still grows without bound, and "/logs cannot grow
#: without bound" is an invariant worth keeping. Oldest are pruned as new
#: flows open.
WORLD_CAP_KEEP  = int(os.environ.get("FFXI_WORLD_CAP_KEEP", "40"))

#: `{client: {"fh", "lock", "n", "bytes", "path", "capped"}}`
_WORLD_CAP = {}
_WORLD_CAP_LOCK = threading.Lock()


def _world_capture_prune(keep_open):
    """Drop the oldest captures beyond WORLD_CAP_KEEP. Never touches a file a
    live flow still holds open."""
    if WORLD_CAP_KEEP <= 0:
        return
    try:
        names = [n for n in os.listdir(WORLD_CAP_DIR)
                 if n.startswith("world-") and n.endswith(".jsonl")]
        paths = sorted((os.path.join(WORLD_CAP_DIR, n) for n in names),
                       key=lambda p: os.path.getmtime(p))
        for p in paths[:max(0, len(paths) - WORLD_CAP_KEEP)]:
            if p in keep_open:
                continue
            os.remove(p)
    except Exception as exc:
        log("MAP", f"world capture prune skipped: {exc!r}")


def world_capture_open(client):
    """Start a capture for one world flow. Returns the state dict, or None."""
    if not WORLD_CAPTURE:
        return None
    with _WORLD_CAP_LOCK:
        st = _WORLD_CAP.get(client)
        if st is not None:
            return st
        try:
            os.makedirs(WORLD_CAP_DIR, exist_ok=True)
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            path = os.path.join(
                WORLD_CAP_DIR, f"world-{stamp}-{client[0]}-{client[1]}.jsonl")
            # APPEND, never truncate. A flow that is reaped and rebuilt (the
            # 2026-08-23 self-heal) comes back on the same client port within
            # the same second and would otherwise reopen this exact filename
            # and destroy the first half -- the half that says whether the
            # trouble started before or after the rebuild.
            _world_capture_prune({s["path"] for s in _WORLD_CAP.values()} | {path})
            fh = open(path, "a", encoding="utf-8")
            try:
                fh.write(json.dumps({"t": round(time.time(), 6), "dir": "meta",
                                     "note": "flow opened"}) + "\n")
                fh.flush()
            except Exception:
                fh.close()
                raise
            st = {"fh": fh, "lock": threading.Lock(),
                  "n": 0, "bytes": 0, "path": path, "capped": False}
            _WORLD_CAP[client] = st
            log("MAP", f"capturing world traffic for {client[0]}:{client[1]} -> {path}")
            return st
        except Exception as exc:
            log("MAP", f"world capture could not open a file: {exc!r}")
            return None


def world_capture(client, direction, data):
    """Append one datagram. Empty datagrams are recorded too -- they are legal
    UDP and mishandling one is what wedged the relay on 2026-08-23."""
    st = _WORLD_CAP.get(client)
    if st is None or st["capped"]:
        return
    with st["lock"]:
        if st["capped"]:
            return
        if st["n"] >= WORLD_CAP_MAX or st["bytes"] >= WORLD_CAP_BYTES:
            st["capped"] = True
            # Say so. A capture that silently stops reads as a flow that went
            # quiet, which is precisely the wrong conclusion.
            log("MAP", f"world capture for {client[0]}:{client[1]} hit its cap "
                       f"({st['n']} datagrams, {st['bytes']}B); no longer recording")
            try:
                st["fh"].flush()
            except Exception:
                pass
            return
        st["n"] += 1
        st["bytes"] += len(data)
        try:
            st["fh"].write(json.dumps({
                "t": round(time.time(), 6),
                "dir": direction,
                "len": len(data),
                "b64": base64.b64encode(data).decode("ascii"),
            }) + "\n")
            # Flushed per datagram on purpose: the interesting runs end in a
            # client abort or a container restart, and a buffered tail is
            # exactly the part that decides.
            st["fh"].flush()
        except Exception as exc:
            st["capped"] = True
            log("MAP", f"world capture write failed: {exc!r}")


def world_capture_close(client, expect=None):
    """Close one flow's capture.

    WARNING: IDENTITY-CHECKED, for the same reason `udp_relay` identity-checks `peers`.
    A reaped flow's `udp_back` thread runs its teardown LATE -- after the
    client's next datagram has already rebuilt the flow and opened a fresh
    capture. Closing by client alone would let the dead thread close its
    successor's file, and `world_capture` would then silently record nothing
    for the rest of the session. Silent is the operative word: the log would
    show a healthy relay and the capture would simply stop, which reads as a
    flow that went quiet -- the exact misreading that cost 2026-08-23.
    """
    with _WORLD_CAP_LOCK:
        st = _WORLD_CAP.get(client)
        if st is None or (expect is not None and st is not expect):
            return
        _WORLD_CAP.pop(client, None)
    with st["lock"]:
        try:
            st["fh"].close()
        except Exception:
            pass
    log("MAP", f"world capture for {client[0]}:{client[1]} closed: "
               f"{st['n']} datagram(s), {st['bytes']}B in {st['path']}")


# ---------------------------------------------------------------------------
# `accounts_sessions.session_key` watch -- making a hypothesis falsifiable.
#
# The map deciphers with the key it loaded out of this row at 0x00A time. We
# send LSB a CONSTANT (`A2_SESSION_KEY`), so the row should hold that constant
# and never move -- but the row is also written by the map itself on every zone
# (`map_networking.cpp` UPDATEs it right after `incrementBlowfish`), and it is
# demonstrably not hygienic: a stale `charid 5, client_port 0` row survived a
# failed world connect on 2026-08-26. Until the stored bytes can be compared
# with the sent bytes, "something rewrote the key mid-session" (H1 below) is
# unfalsifiable.
#
# So sample it, and log only CHANGES. A row that never moves clears H1's
# "something rewrote it mid-session" branch outright; a row that moves names the
# moment it did.
SESSION_KEY_WATCH = float(os.environ.get("FFXI_SESSION_KEY_WATCH", "5"))
#: Give up watching after this long with no world traffic either way.
SESSION_KEY_IDLE  = float(os.environ.get("FFXI_SESSION_KEY_IDLE", "120"))


def session_key_connect():
    """One connection, held for the life of a watch.

    WARNING: Deliberately NOT a connection per sample. This runs during the exact
    window it is measuring, and the 2026-08-23 investigation spent hours on DB
    connection noise that turned out to be a bystander -- an instrument that
    opens 180 connections over a 15-minute acceptance run manufactures more of
    the same evidence and would poison the next reader of `Aborted_clients`.
    """
    try:
        import pymysql
    except ImportError:
        return None, "pymysql unavailable in this image"
    try:
        conn = pymysql.connect(host=LSB_DB_HOST, port=LSB_DB_PORT,
                               user=LSB_DB_USER, password=LSB_DB_PASS,
                               database=LSB_DB_NAME, autocommit=True,
                               connect_timeout=5)
        return conn, None
    except Exception as exc:
        return None, f"LSB database unreachable: {exc}"


def session_key_row(conn, charid):
    """One read of the row the map deciphers with. Returns a dict or an error
    string -- never raises, this is instrumentation and must not affect a flow."""
    try:
        conn.ping(reconnect=True)
        with conn.cursor() as cur:
            cur.execute("SELECT accid, session_key, client_addr, client_port, targid "
                        "FROM accounts_sessions WHERE charid = %s", (charid,))
            row = cur.fetchone()
        if not row:
            return "no accounts_sessions row"
        key = row[1] or b""
        return {"accid": row[0], "key": bytes(key).hex(),
                "client_addr": row[2], "client_port": row[3], "targid": row[4]}
    except Exception as exc:
        return f"query failed: {exc}"


#: charid last seen on a flow's opening 0x00A, and the flows already watched.
#: Both keyed by client address so a reaped-and-rebuilt flow resumes rather
#: than starting a second watcher against the same row.
_WORLD_CHARID = {}
_WORLD_WATCH = {}
_WORLD_WATCH_LOCK = threading.Lock()


def start_session_key_watch(client, charid, peers):
    """Start a watch unless this flow already has one running."""
    if SESSION_KEY_WATCH <= 0:
        return
    with _WORLD_WATCH_LOCK:
        th = _WORLD_WATCH.get(client)
        if th is not None and th.is_alive():
            return
        th = threading.Thread(target=session_key_watcher,
                              args=(client, charid, peers), daemon=True)
        _WORLD_WATCH[client] = th
        th.start()


def session_key_watcher(client, charid, peers):
    """Watch one flow's session-key row for as long as the flow exists."""
    if SESSION_KEY_WATCH <= 0:
        return
    sent = bytes(A2_SESSION_KEY).hex()
    log("MAP", f"{client[0]}:{client[1]} charid {charid}: bridge sent 0xA2 key "
               f"{sent}; watching accounts_sessions every {SESSION_KEY_WATCH:g}s")
    conn, err = session_key_connect()
    if conn is None:
        log("MAP", f"charid {charid}: session-key watch unavailable -- {err}")
        return
    last = None
    why = "the flow ended"
    try:
        while peers.get(client) is not None:
            # A client that simply stops sending leaves `udp_back` blocked in
            # recv() forever, so the flow is never reaped and this loop would
            # poll the database for the life of the process. Bound it on
            # TRAFFIC, not on the flow.
            with _UDP_STATS_LOCK:
                st = _UDP_STATS.get(client)
            if st and time.time() - max(st[4], st[5]) > SESSION_KEY_IDLE:
                why = f"no world traffic for {SESSION_KEY_IDLE:g}s"
                break
            row = session_key_row(conn, charid)
            current = row if isinstance(row, str) else row["key"]
            if current != last:
                if isinstance(row, str):
                    log("MAP", f"charid {charid}: session_key row -> {row}")
                else:
                    agree = "MATCHES the 0xA2 we sent" if row["key"] == sent else \
                            "DIFFERS from the 0xA2 we sent -- something rewrote it (H1)"
                    log("MAP", f"charid {charid}: session_key={row['key']} ({agree}) "
                               f"accid={row['accid']} client_addr={row['client_addr']} "
                               f"client_port={row['client_port']} targid={row['targid']}")
                last = current
            time.sleep(SESSION_KEY_WATCH)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log("MAP", f"charid {charid}: session-key watch ended -- {why}")


#: Per-client world-channel traffic counters, `{client: [c2s, c2s_bytes, s2c,
#: s2c_bytes, last_c2s, last_s2c]}`. The relay used to log only the first three
#: CLIENT datagrams and nothing at all coming back, which cannot tell "the map
#: never answered" from "the answer never reached the client" from "the client
#: gave up first" -- and a disconnect mid-zone looks identical in all three. That
#: is the same blind spot that made POL-0001 take days; do not remove these.
_UDP_STATS = {}
_UDP_STATS_LOCK = threading.Lock()


def _udp_count(client, c2s=0, c2s_b=0, s2c=0, s2c_b=0):
    with _UDP_STATS_LOCK:
        st = _UDP_STATS.setdefault(client, [0, 0, 0, 0, 0.0, 0.0])
        st[0] += c2s
        st[1] += c2s_b
        st[2] += s2c
        st[3] += s2c_b
        if c2s:
            st[4] = time.time()
        if s2c:
            st[5] = time.time()
        return st


def udp_stats_reporter(period=15.0):
    """One line per active world client per period. Silence in this log means
    the RELAY is idle, not that the client is -- which is the distinction the
    first version could not make."""
    last = {}
    while True:
        time.sleep(period)
        now = time.time()
        with _UDP_STATS_LOCK:
            snap = {c: list(v) for c, v in _UDP_STATS.items()}
        for client, st in snap.items():
            if last.get(client) == st[:4]:
                continue                      # nothing moved either way
            last[client] = st[:4]
            log("MAP", f"{client[0]}:{client[1]} traffic c2s={st[0]} ({st[1]}B) "
                       f"s2c={st[2]} ({st[3]}B); last c2s "
                       f"{now - st[4]:.1f}s ago, last s2c "
                       f"{(now - st[5]) if st[5] else -1:.1f}s ago")


#: Per-client upstream sockets, `{client: connected-UDP-socket to the map}`.
#: Module-global so `tools/ffxi_udp_relay_check.py` can pin the wedge below.
_UDP_PEERS = {}


def udp_back(up, srv, client, peers, cap=None):
    """map -> client. Logs the first few datagrams and counts the rest.

    `cap` is the capture this flow opened, carried so the teardown can close
    ITS OWN file and not a successor's -- see `world_capture_close`.

    WARNING: `up` is a CONNECTED UDP socket, and a zero-length `recv()` on it is a
    real EMPTY DATAGRAM, not EOF -- UDP has no EOF. LSB's map emits empty
    datagrams: `handle_incoming_packet` (map_networking.cpp) sends
    unconditionally, and both the resend-previous-packet path and the
    `*buffsize = 0` error paths can hand it size 0. The first version of this
    loop did `if not data: break`, which treated that as end-of-stream and
    returned SILENTLY (the `except` log never ran). Measured live on
    2026-08-23 (FFXI-3001 chase): the thread died between world attempts,
    every later map reply queued unread on this socket until SO_RCVBUF
    filled -- /proc/net/udp showed rx_queue 0x34080 = 213,120 B and 22
    drops -- and three consecutive world logins got InsertPC on the map and
    total silence on the client. Do not turn any recv() result into `break`.
    """
    seen = 0
    try:
        while True:
            data = up.recv(65535)
            seen += 1
            _udp_count(client, s2c=1, s2c_b=len(data))
            world_capture(client, "s2c", data)
            if seen <= 3 or not data:
                log("MAP", f"  s2c #{seen} {len(data)}B {hexdump(data, 16)}")
            srv.sendto(data, client)      # forward even a 0-length datagram
    except Exception as exc:
        log("MAP", f"return path for {client} ended after {seen} datagram(s): {exc!r}")
    finally:
        # Self-heal: drop the flow so the client's NEXT datagram rebuilds the
        # upstream socket and this thread. Without this, a dead return path
        # left c2s forwarding forever while s2c stayed frozen -- the client
        # kept re-sending its 136 B world login into a black hole (the
        # 2026-08-23 wedge). Identity-checked so a rebuilt flow is never
        # removed by its predecessor's late teardown.
        log("MAP", f"return path for {client} closed after {seen} datagram(s); "
                   f"flow rebuilds on the next c2s datagram")
        if peers.get(client) is up:
            peers.pop(client, None)
        world_capture_close(client, cap)
        try:
            up.close()
        except Exception:
            pass


def udp_relay():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", BRIDGE_MAP))
    log("MAP", f"UDP relay listening on 0.0.0.0:{BRIDGE_MAP} -> {MAP_HOST}:{MAP_PORT}")
    peers = _UDP_PEERS
    while True:
        try:
            data, client = srv.recvfrom(65535)
        except Exception as exc:
            log("MAP", f"recvfrom failed: {exc!r}")
            continue
        up = peers.get(client)
        if up is None:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Re-resolves MAP_HOST per flow, so a recreated map container
                # (new IP) heals on the next flow instead of wedging forever.
                up.connect((MAP_HOST, MAP_PORT))
            except Exception as exc:
                log("MAP", f"cannot reach map {MAP_HOST}:{MAP_PORT}: {exc!r}")
                continue
            peers[client] = up
            # Open the capture BEFORE the first datagram is recorded below, so
            # the flow's opening 0x00A is in the file. It is the only datagram
            # whose plaintext we can read without a key, and it anchors the
            # timeline the map-server errors are correlated against.
            cap = world_capture_open(client)
            threading.Thread(target=udp_back, args=(up, srv, client, peers, cap),
                             daemon=True).start()
            log("MAP", f"world client {client[0]}:{client[1]} -- {decode_world_login(data)}")
            dump_packet("MAP-c2s-first", data)
            # Remember the charid across a reap-and-rebuild. Only the flow's
            # opening 0x00A names it, and a rebuilt flow's first datagram is an
            # ordinary enciphered game packet -- so without this the self-heal
            # path would silently lose the session-key watch exactly when it
            # is most wanted.
            charid = world_login_charid(data) or _WORLD_CHARID.get(client)
            if charid:
                _WORLD_CHARID[client] = charid
                start_session_key_watch(client, charid, peers)
        elif _UDP_SEEN.get(client, 0) < 3:
            log("MAP", f"  c2s #{_UDP_SEEN[client] + 1} {len(data)}B {hexdump(data, 16)}")
        _UDP_SEEN[client] = _UDP_SEEN.get(client, 0) + 1
        _udp_count(client, c2s=1, c2s_b=len(data))
        world_capture(client, "c2s", data)
        try:
            up.send(data)
        except Exception as exc:
            # A connected UDP socket surfaces ICMP unreachable as a send
            # error (e.g. the map was recreated). Tear the flow down; the
            # client's next datagram rebuilds it against a fresh resolve.
            log("MAP", f"forward to map failed: {exc!r}; dropping flow for {client}")
            if peers.get(client) is up:
                peers.pop(client, None)
            world_capture_close(client, _WORLD_CAP.get(client))
            try:
                up.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Character-import endpoint -- the self-serve half of tools/ffxi_import.py.
#
# A client-side helper that knows the Viewer's session token (the settings
# dialog of a shim) POSTs a polexport JSON dump here with an `X-POL-Session`
# header carrying the first 16 hex chars of sha1(USER token) -- the SAME digest
# such a helper stamps into lobby packets (see POLTOKEN_MAGIC), so attribution
# is the session table lookup the launch path already trusts (member_for_sid),
# not an inference. No signed-in Viewer session, no import.
#
# The SQL is the shared ffxi_import_core plan (identical statements to the
# admin import path); pymysql talks to the LSB `db` service directly. The idmap
# bind happens IN PROCESS, so no bridge restart is needed afterwards -- unlike
# the CLI `bind` step.
# ---------------------------------------------------------------------------
BRIDGE_HTTP  = int(os.environ.get("BRIDGE_HTTP_PORT", "0"))   # 0 = endpoint off
LSB_DB_HOST  = os.environ.get("LSB_DB_HOST", "db")
LSB_DB_PORT  = int(os.environ.get("LSB_DB_PORT", "3306"))
LSB_DB_NAME  = os.environ.get("LSB_DB_NAME", "xidb")
LSB_DB_USER  = os.environ.get("LSB_DB_USER", "xiadmin")
LSB_DB_PASS  = os.environ.get("LSB_DB_PASSWORD", "")


def do_import(dump, member_id):
    """Import a polexport dump for a member. Returns (ok, message, charid)."""
    try:
        import pymysql
    except ImportError:
        return (False, "bridge image lacks pymysql -- rebuild the bridge image "
                       "(lsb/Dockerfile.bridge) or use tools/ffxi_import.py", None)
    import ffxi_import_core as IC
    try:
        plan = IC.build_statements(dump)
    except (ValueError, TypeError, KeyError) as exc:
        return (False, f"bad dump: {exc}", None)
    name = plan["name"]

    # POL issues ONE FFXI Content ID per member; a living character means no
    # free one, and the import must not orphan a charid with no pairing.
    cids = pol_content_ids(member_id)
    with _idmap_lock:
        taken = set(_idmap.values())
    free = [c for c in cids if c not in taken]
    if not free:
        # SAY WHAT IS HOLDING IT. "No free Content ID, delete first" is unusable
        # advice on its own: it does not name the character, so a player who has
        # already deleted theirs reads it as a bug -- and sometimes they are right,
        # because the holder can be a charid that is NOT in their character list
        # and therefore cannot be deleted from the game at all. Seen live
        # 2026-08-26: member 3's only id was held by charid 2, accid 0, a row on no
        # account, invisible to every char list, with an empty name in this map
        # (it had never appeared in a 0x20 for us to learn one). The id could never
        # come back, and the message sent the player to delete a character that was
        # not the problem.
        with _idmap_lock:
            holders = [(k, _charnames.get(k) or "(unnamed)", v)
                       for k, v in _idmap.items() if v in cids]
        if holders:
            who = "; ".join(f"charid {k} \"{n}\" holds {v}" for k, n, v in holders)
            return (False,
                    f"member {member_id} has no free FFXI Content ID -- {who}. "
                    "Delete that character in FFXI and the id comes back. If it is "
                    "NOT in your character list, it is stranded (a charid on no "
                    "account) and only an admin can release the pairing.", None)
        return (False, f"member {member_id} has no free FFXI Content ID "
                       f"(have {cids or 'none'}, all bound) -- delete the "
                       "existing character first", None)

    # The member's LSB account (auto-provisioned on first use, same path as
    # a normal first launch).
    try:
        aid, _sh, login = lsb_member_session(member_id)
    except Exception as exc:
        return (False, f"LSB account for member {member_id} failed: {exc}", None)

    try:
        conn = pymysql.connect(host=LSB_DB_HOST, port=LSB_DB_PORT,
                               user=LSB_DB_USER, password=LSB_DB_PASS,
                               database=LSB_DB_NAME, autocommit=False,
                               connect_timeout=10)
    except Exception as exc:
        return (False, f"LSB database unreachable: {exc}", None)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM chars WHERE charname = %s", (name,))
            if cur.fetchone():
                return (False, f"character name {name!r} is already taken "
                               "on this world", None)
            cur.execute("SET @accid = %s", (aid,))
            # The same allocation LSB's own createCharacter performs; FOR
            # UPDATE so two simultaneous imports cannot mint one charid.
            cur.execute("SELECT COALESCE(MAX(charid), 0) + 1 FROM chars FOR UPDATE")
            charid = int(cur.fetchone()[0])
            cur.execute("SET @charid = %s", (charid,))
            for stmt in plan["core"]:
                cur.execute(stmt)
            conn.commit()
            for stmt in plan["best"]:
                try:
                    cur.execute(stmt)
                    conn.commit()
                except Exception as exc:
                    conn.rollback()
                    log("import", f"best-effort statement failed ({exc!r}): "
                                  f"{stmt[:80]}...")
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        return (False, f"import failed, nothing committed: {exc}", None)
    finally:
        conn.close()

    # In-process idmap bind -- the reason no restart is needed.
    with _idmap_lock:
        _idmap[str(charid)] = free[0]
        _charnames[str(charid)] = name
        save_idmap()
    log("import", f"member {member_id}: imported {name!r} as charid {charid} "
                  f"(accid {aid}), bound to Content ID {free[0]}; "
                  f"{plan['n_items']} items, {plan['n_skills']} skill rows, "
                  f"{plan['n_equip']} equipped, {plan['n_spells']} spells, "
                  f"{plan['n_currencies']} currencies, {plan['n_keyitems']} key items, "
                  f"{plan['gil']} gil, storage {plan['storage']}")
    for w in plan["warnings"]:
        log("import", f"member {member_id}: {name} -- {w}")
    # The warnings ride back to the player, not just into the log. Every one of
    # them is "this imported but will not look the way you expect", and the
    # player is the only person who can tell that something is missing.
    tail = ("".join(" NOTE: " + w for w in plan["warnings"]))
    return (True, f"character {name} imported (charid {charid}). Sign out of "
                  "PlayOnline and back in, then launch FFXI." + tail, charid)


def http_import_server():
    import re as _re
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.rstrip("/") == "/import":
                self._send(200, {"ok": True, "service": "polimport"})
            else:
                self._send(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if self.path.rstrip("/") != "/import":
                return self._send(404, {"ok": False, "error": "not found"})
            sid_hex = (self.headers.get("X-POL-Session") or "").strip().lower()
            if not _re.fullmatch(r"[0-9a-f]{16}", sid_hex):
                return self._send(403, {"ok": False, "error":
                    "no POL session stamp -- sign into PlayOnline first "
                    "(and the shim must know its session token)"})
            member = member_for_sid("u" + sid_hex)
            if member is None:
                return self._send(403, {"ok": False, "error":
                    "POL session not signed in -- sign into PlayOnline first"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if not 0 < length <= 2 * 1024 * 1024:
                return self._send(413, {"ok": False,
                                        "error": "dump missing or over 2MB"})
            try:
                # utf-8-sig: dumps that pass through Windows tooling grow a BOM
                dump = json.loads(self.rfile.read(length).decode("utf-8-sig"))
            except Exception as exc:
                return self._send(400, {"ok": False, "error": f"bad JSON: {exc}"})
            ok, msg, charid = do_import(dump, member)
            self._send(200 if ok else 422,
                       {"ok": ok, "message": msg, "charid": charid})

        def log_message(self, fmt, *args):
            log("import", f"{self.client_address[0]} {fmt % args}")

    srv = ThreadingHTTPServer(("0.0.0.0", BRIDGE_HTTP), Handler)
    log("boot", f"import endpoint ON: POST /import on {BRIDGE_HTTP}")
    srv.serve_forever()


def main():
    global _pol_content_ids
    log("boot", f"FFXI->LSB bridge; LSB={LSB_HOST} auth={LSB_AUTH_PORT} "
                 f"view={LSB_VIEW_PORT} data={LSB_DATA_PORT}; account={LSB_ACCOUNT}")
    load_acctmap()
    log("boot", f"POL member -> LSB account map: "
                f"{ {k: v['login'] for k, v in _acctmap.items()} } ({ACCTMAP_FILE}); "
                f"members resolved from {POL_SESSIONS}")
    if FFXI_ID_MAP:
        _pol_content_ids = load_pol_content_ids()
        load_idmap()
        log("boot", f"Content-ID translation ON; POL FFXI Content IDs="
                    f"{_pol_content_ids or 'NONE (check accounts.db)'}; "
                    f"map={_idmap or 'empty'} ({IDMAP_FILE}); "
                    f"0x0B world handoff {'REWRITTEN' if MAP_HANDOFF else 'left alone'}")
    else:
        log("boot", "Content-ID translation OFF (FFXI_ID_MAP=0)")
    # Smoke-test auth once at startup so misconfig is obvious immediately. On a
    # fresh LSB the shared account does not exist yet, so a refused login is
    # followed by one LOGIN_CREATE and a retry; anything else is a real warning.
    try:
        aid, sh = lsb_authenticate()
        log("boot", f"startup auth OK: account_id={aid} hash={sh.hex()}")
    except Exception as e:
        try:
            reply = lsb_auth_request(0x20, LSB_ACCOUNT, LSB_PASSWORD)
            if isinstance(reply, dict) and reply.get("result") == LOGIN_SUCCESS_CREATE:
                aid, sh = lsb_authenticate()
                log("boot", f"created the shared LSB account {LSB_ACCOUNT!r} and "
                            f"authenticated: account_id={aid} hash={sh.hex()}")
            else:
                log("boot", f"WARNING: startup auth failed: {e}; the create "
                            f"attempt replied {reply}")
        except Exception as e2:
            log("boot", f"WARNING: startup auth failed: {e} (create attempt: {e2})")
    threading.Thread(target=listener, args=(BRIDGE_VIEW, LSB_VIEW_PORT, "VIEW"), daemon=True).start()
    threading.Thread(target=listener, args=(BRIDGE_DATA, LSB_DATA_PORT, "DATA"), daemon=True).start()
    if BRIDGE_MAP:
        threading.Thread(target=udp_relay, daemon=True).start()
        threading.Thread(target=udp_stats_reporter, daemon=True).start()
    else:
        log("boot", "world UDP relay OFF (BRIDGE_MAP_PORT unset)")
    if BRIDGE_HTTP:
        threading.Thread(target=http_import_server, daemon=True).start()
    else:
        log("boot", "import endpoint OFF (BRIDGE_HTTP_PORT unset)")
    # Heartbeat. A silent log is otherwise ambiguous between "no client tried"
    # and "the bridge is gone" -- and it HAS gone: an instance launched from a
    # transient console died with an empty stderr and no traceback, which read on
    # the client as FFXI-3100 (nothing listening on 54001).
    while True:
        time.sleep(300)
        log("alive", f"listening {BRIDGE_VIEW}/{BRIDGE_DATA}; map={_idmap or 'empty'}")


if __name__ == "__main__":
    main()
