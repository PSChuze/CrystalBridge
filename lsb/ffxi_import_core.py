"""Shared core of the polexport character import.

Turns a polexport-1 JSON dump into SQL statements against the LSB database.
Two consumers, one source of truth for the mapping:

  * tools/ffxi_import.py renders the statements to a REVIEWABLE text script
    (the admin import path);
  * lsb/ffxi_bridge.py's import endpoint executes them over a pymysql
    connection (the self-serve path, driven by a client-side helper).

Both modes speak through MySQL session variables: every statement references
@accid / @charid, and the consumer supplies the SET preamble -- the text
renderer as literal SQL, the endpoint with the values it resolved itself.
Statements are split into CORE (one transaction; identity, jobs, items, gil,
and the CONTAINER SIZES those items need -- a failure rolls everything back)
and BEST-EFFORT (skills, key items, rank, equipment; each stands alone so an
optional-column mismatch cannot take the character with it).

The plan is also returned with `warnings`: things that imported but may not
present as the player expects (mog storage, oversize containers, equipment
that could not be matched). Both consumers show them -- an import that lands
silently short is the failure mode this whole file is guarding against.

Skill values are written as displayed_skill * skill_scale (default 10: LSB's
char_skills stores tenths). EXPERIMENTAL until live-verified.
"""
import re
import struct

# Tables GENERATED from LandSandBoat's own source (tools/gen_ffxi_lsb_tables.py):
# the currency packet layouts, and the ids of abilities LSB gates on a "learned"
# bit. Kept optional at import time on purpose: if the deployed image predates
# them, the rest of the import must still work and SAY which pieces were
# skipped, rather than dying at module load and taking the whole endpoint down.
try:
    from ffxi_lsb_tables import PACKETS as CURRENCY_PACKETS
    from ffxi_lsb_tables import LEARNED_ABILITIES, WS_UNLOCKS
    from ffxi_lsb_tables import (QUEST_LOG, QUEST_OFFER, QUEST_COMPLETE,
                                 MISSION_LOG, MISSION_COMPLETE,
                                 LOG_STRUCTS, LOG_COUNTS, HOMEPOINTS)
except ImportError:                                     # pragma: no cover
    CURRENCY_PACKETS = None
    LEARNED_ABILITIES = None
    WS_UNLOCKS = None
    QUEST_LOG = None
    HOMEPOINTS = None

# sizeof(CCharEntity::m_LearnedAbilities) -- 49 bytes, so ids 0..391. addBit()
# silently declines anything past that, which would import as "never learned".
LEARNED_ABILITY_BYTES = 49

# sizeof(CCharEntity::m_LearnedWeaponskills) -- xi::bitset<64>, so 8 bytes.
# WARNING: THE BIT POSITIONS ARE NOT WEAPON SKILL IDS. They are `wsUnlockId`, a dense
# 1..63 index living in weapon_skills.unlock_id: Decimation is weapon skill 72
# and unlock id 5. Setting bit 72 would be nonsense (out of range); setting a
# weapon skill id that happens to be <= 63 would silently grant a DIFFERENT
# weapon skill, which is worse. WS_UNLOCKS is the translation, generated from
# that column. Bit 0 is never valid -- unlock_id 0 is LSB's "not unlockable".
LEARNED_WS_BYTES = 8

_UNPACK = {"uint8_t": "<B", "int8_t": "<b", "uint16_t": "<H", "int16_t": "<h",
           "uint32_t": "<I", "int32_t": "<i", "uint64_t": "<Q", "int64_t": "<q"}

# FFXI job id -> LSB char_jobs column.
JOB_COLS = {1: "war", 2: "mnk", 3: "whm", 4: "blm", 5: "rdm", 6: "thf",
            7: "pld", 8: "drk", 9: "bst", 10: "brd", 11: "rng", 12: "sam",
            13: "nin", 14: "drg", 15: "smn", 16: "blu", 17: "cor", 18: "pup",
            19: "dnc", 20: "sch", 21: "geo", 22: "run"}

# Nation -> starting-city zone the imported character wakes up in.
NATION_ZONE = {0: 230, 1: 234, 2: 238}  # S.San d'Oria / Bastok Mines / Windurst Waters
NATION_RANK_COL = {0: "rank_sandoria", 1: "rank_bastok", 2: "rank_windurst"}

CRAFT_SKILL_BASE = 48   # Ashita CraftSkills[i] == LSB skill id 48 + i, for
                        # i = 0..11: fishing(48)..synergy(57), rid(58), dig(59)

# ---------------------------------------------------------------------------
# CONTAINER SIZES -- why this is not cosmetic.
#
# LSB sizes every container from char_storage at LoadChar, THEN loads the items
# (charutils.cpp: the char_storage SELECT is ~line 627, LoadInventory is called
# at ~971). CItemContainer::InsertItem(item, slot) refuses `slot > m_size` with
# nothing but a ShowDebug -- so an item in a slot past the size is DROPPED at
# world load, silently, after a clean-looking import.
#
# The skeleton char_storage row this importer used to write takes the schema
# defaults: inventory 30, safe 50, locker 0, satchel 0, sack 0. A retail
# character has an 80-slot inventory and may have a full locker, satchel and
# sack -- all of which would land in char_inventory, pass every check, and then
# never exist in game. So the sizes have to be imported too.
#
# WARNING: LOC_MOGSAFE2 (9) has no column of its own: charutils.cpp sizes it from
# `safe`. It folds in here for the same reason -- a 9 that needed 80 has to
# raise `safe`, or half the mog safe disappears.
# ---------------------------------------------------------------------------
STORAGE_COLS = {0: "inventory", 1: "safe", 9: "safe", 4: "locker",
                5: "satchel", 6: "sack", 7: "case", 8: "wardrobe",
                10: "wardrobe2", 11: "wardrobe3", 12: "wardrobe4",
                13: "wardrobe5", 14: "wardrobe6", 15: "wardrobe7",
                16: "wardrobe8"}

# sql/char_storage.sql's DEFAULTs. Measured sizes are taken as a FLOOR against
# these, never a replacement: an import must not cost a character the storage
# LSB would have given it anyway.
STORAGE_DEFAULTS = {"inventory": 30, "safe": 50, "locker": 0, "satchel": 0,
                    "sack": 0, "case": 80, "wardrobe": 80, "wardrobe2": 80,
                    "wardrobe3": 80, "wardrobe4": 80, "wardrobe5": 80,
                    "wardrobe6": 80, "wardrobe7": 80, "wardrobe8": 80}

STORAGE_MAX = 80        # CItemContainer::AddBuff clamps to 0..80 for a player

# LOC_STORAGE (2), the mog storage, is the one container with no char_storage
# column: LSB derives its size from the furnishings installed in the mog safe
# (charutils.cpp LoadInventory, the AddBuff(getStorage()) call). We cannot set
# it, so items imported into it are at the mercy of whether the furnishings'
# exdata survives -- which is why the import REPORTS a non-empty container 2
# rather than pretending it landed.
LOC_STORAGE = 2

# ---------------------------------------------------------------------------
# SPELLS.
#
# LSB's spell id space is 0..MAX_SPELL_ID-1 = 0..1023 (`spell.h`), held on the
# character as `xi::bitset<1024> m_SpellList`. The shipped `spell_list` has 928
# rows spread over 1..1019, so the range is sparse and there is no shortcut
# bound to sweep to.
#
# char_spells is just (charid, spellid) -- but note UNIQUE KEY (spellid,
# charid), so a duplicate id fails the INSERT exactly the way a duplicate
# skillid did (see the skills merge below). The ids are de-duplicated.
#
# Unknown ids are SAFE: LoadSpells joins char_spells against spell_list
# filtered by enabled expansions AND re-checks `spell::GetSpell() != nullptr`
# (charutils.cpp ~1049), so an id LSB does not have is ignored rather than
# fatal. That is why these go in `best` and why an out-of-range id is dropped
# here rather than refused -- but the count that will not resolve is REPORTED,
# because "imported 300 spells" and "imported 300 rows, 40 of which the world
# will ignore" are different claims.
MAX_SPELL_ID = 1024


def q(s):
    """Single-quote a string for SQL, refusing anything exotic."""
    if not re.fullmatch(r"[A-Za-z0-9_' -]*", s):
        raise ValueError(f"refusing to embed {s!r} in SQL")
    return "'" + s.replace("'", "''") + "'"


def validate_name(dump, override=None):
    n = (override or dump.get("name") or "").strip().capitalize()
    if not re.fullmatch(r"[A-Za-z]{3,15}", n):
        raise ValueError(f"character name {n!r} is not 3-15 letters")
    return n


# ---------------------------------------------------------------------------
# KEY ITEMS -- and, because of how FFXI files them, MOUNTS.
#
# WARNING: `chars.keyitems` IS NOT A FLAT BIT ARRAY. It is `keyitems_t` (common/mmo.h):
# eight TABLES, each holding a 512-bit `keyList` followed by a 512-bit
# `seenList` -- 128 bytes per table, 1024 in total. Key item K lives in table
# K/512 at bit K%512, i.e. byte `(K // 512) * 128 + (K % 512) // 8`
# (charutils.cpp `hasKeyItem`/`addKeyItem`).
#
# This importer used to write a FLAT array, byte `K // 8`. That is correct for
# table 0 and WRONG FOR EVERY KEY ITEM FROM 512 UP -- it lands in a different
# table's bits entirely. Key item 3072 (the Chocobo mount) went to byte 384,
# which is table 3's `keyList` byte 0, i.e. it granted key item 1536 instead.
# Silent in both directions: the real key item is missing and an unrelated one
# appears. Fixed 2026-08-26.
#
# KEY: MOUNTS ARE KEY ITEMS 3072..3108 (table 6, bits 0..36) -- there is no mounts
# column anywhere in LSB, and `0x0AE GP_SERV_COMMAND_MOUNT_DATA` is literally a
# memcpy of `keys.tables[6].keyList`. So mounts need no export and no import of
# their own; they ride the key item sweep polexport has always done, and they
# were among the casualties of the flat-array bug above.
#
# `seenList` is deliberately left CLEAR: LSB's own `addKeyItem` sets `keyList`
# only (`seenKeyItem` is a separate call), so an imported key item shows as new
# exactly as a granted one does. The client does not expose "seen" anyway.
# ---------------------------------------------------------------------------
KEYITEM_TABLES = 8
KEYITEM_BITS_PER_TABLE = 512
KEYITEM_TABLE_BYTES = 128        # keyList (64) + seenList (64)
KEYITEM_BLOB_BYTES = KEYITEM_TABLES * KEYITEM_TABLE_BYTES
KEYITEM_MAX = KEYITEM_TABLES * KEYITEM_BITS_PER_TABLE      # 4096, exclusive

# The mount block, for reporting. LSB has no mount enum in its data files; these
# come from KeyItem::CHOCOBO_COMPANION..CRAKLAW_COMPANION.
MOUNT_KEYITEM_FIRST = 3072
MOUNT_KEYITEM_LAST = 3108


def keyitem_blob(ids):
    """-> the full 1024-byte keyitems_t, or (None, dropped) semantics via count.

    Always full length: `extractFromBlob` memcpy's min(sizeof(T), blob), so a
    short blob silently leaves the higher tables zero -- which is survivable but
    makes a truncation look like "owns nothing up there".
    """
    ids = [int(k) for k in ids or []]
    if not ids:
        return None, 0
    buf = bytearray(KEYITEM_BLOB_BYTES)
    dropped = 0
    for k in ids:
        if not 0 <= k < KEYITEM_MAX:
            dropped += 1
            continue
        table, index = divmod(k, KEYITEM_BITS_PER_TABLE)
        buf[table * KEYITEM_TABLE_BYTES + index // 8] |= 1 << (index % 8)
    return bytes(buf), dropped


def decode_currencies(blocks):
    """[{id, data}] (raw 0x113/0x118 bodies, hex) -> ({column: value}, warnings).

    The client is never asked for these: FFXI pushes currencies in packets
    0x113 and 0x118 and the client renders its menus from the push, so the only
    way to export them is to catch the packets -- exactly what polexport
    already does for the quest log. Decoding happens here, against LSB's own
    builders, for the same reason the item Extra blob is exported raw: a field
    decoded wrongly in the addon is lost from every dump ever taken, whereas raw
    bytes make a decoder fix a re-run.

    A block whose length does not match the struct is REFUSED WHOLE. Currencies
    are a flat sequence with no internal markers, so a length mismatch means
    every field after the divergence is silently misaligned -- and a plausible
    wrong number in a wallet is worse than no number.
    """
    cols, warnings = {}, []
    if CURRENCY_PACKETS is None:
        return cols, ["this build has no ffxi_lsb_tables (regenerate with "
                      "tools/gen_ffxi_lsb_tables.py) -- currencies skipped."]
    for blk in blocks or []:
        try:
            pid = int(blk["id"])
            raw = bytes.fromhex(blk["data"])
        except (KeyError, TypeError, ValueError):
            warnings.append("a currency block was unreadable and was skipped.")
            continue
        spec = CURRENCY_PACKETS.get(f"0x{pid:03x}")
        if spec is None:
            warnings.append(f"currency packet 0x{pid:03x} is not one this build "
                            "knows (0x113/0x118) -- skipped.")
            continue
        if len(raw) != spec["size"]:
            warnings.append(
                f"currency packet 0x{pid:03x} was {len(raw)} bytes, expected "
                f"{spec['size']}. REFUSED WHOLE rather than decoded from the "
                "wrong offsets -- a wrong balance is worse than none. This "
                "usually means the client and our LSB revision disagree.")
            continue
        for fname, kind, off, ctype, extra, unit in spec["fields"]:
            col = spec["columns"].get(fname)
            if col is None:          # padding, unknowns, and computed fields
                continue
            if not re.fullmatch(r"[a-z_0-9]+", col):
                raise ValueError(f"refusing odd char_points column {col!r}")
            if kind == "array":
                continue             # only ever padding in these two packets
            if kind == "bits":
                shift, nbits = extra
                word = struct.unpack_from(_UNPACK[ctype], raw, off)[0]
                val = (word >> shift) & ((1 << nbits) - 1)
            else:
                val = struct.unpack_from(_UNPACK[ctype], raw, off)[0]
            if val < 0:
                # every column these land in is UNSIGNED (only daily_tally and
                # plaudits are signed, and neither is column-backed here)
                warnings.append(f"currency `{col}` decoded as {val}; clamped to 0.")
                val = 0
            cols[col] = val
    return cols, warnings


# ---------------------------------------------------------------------------
# THE QUEST AND MISSION LOG (packet 0x056).
#
# `polexport` has captured these raw since 2026-08-25, keyed by the `Port` at
# body offset 32 that says which block each one is. Nothing consumed them until
# now. Decoding happens here, against LSB's own builders
# (0x056_mission{,_other,_tvr}.cpp), for the reason the raw capture exists: a
# field decoded wrongly in the addon is lost from every dump anyone ever takes,
# whereas raw bytes make a decoder fix a re-run.
#
# KEY: ALL THREE SHAPES ARE 36 BYTES WITH `Port` AT OFFSET 32. That is worth
# stating because `0x056_mission.h` looks longer at a glance -- nine uint32s --
# but `expansion_addon_t` and `tales_beginning_t` are uint16 bitfields, not
# uint32s, so it comes to 32 bytes of payload like the others. It could not be
# otherwise: the client dispatches on Port, so a variable Port offset is
# impossible.
#
# The destinations are raw-struct blobs on `chars` -- charutils' SaveQuestsList
# and SaveMissionsList bind `m_questLog` / `m_missionLog` / `m_assaultLog` /
# `m_campaignLog` straight through, so their in-memory layout IS the on-disk
# format. LOG_STRUCTS and LOG_COUNTS carry the sizes, parsed from mmo.h.
# ---------------------------------------------------------------------------
QM_BODY_SIZE = 36           # 32 bytes payload + uint16 Port + uint16 padding
QM_PORT_OFF = 32
MISSION_PORT = 0xFFFF       # the nation/expansion currents


def _u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


def _u16(b, off):
    return int.from_bytes(b[off:off + 2], "little")


def decode_questlog(blocks):
    """[{port, data}] -> ({blob name: bytes}, warnings).

    Returns only the blobs at least one block actually spoke to: writing an
    all-zero `quests` blob because no quest block arrived would erase a real
    quest log, which is the whole reason the capture states its own count.
    """
    warnings = []
    if QUEST_LOG is None:
        return {}, ["this build has no ffxi_lsb_tables (regenerate with "
                    "tools/gen_ffxi_lsb_tables.py) -- quest log skipped."]

    qsize, _ = LOG_STRUCTS["questlog_t"]
    msize, mfields = LOG_STRUCTS["missionlog_t"]
    quests = [bytearray(qsize) for _ in range(LOG_COUNTS["questlog_t"])]
    missions = [bytearray(msize) for _ in range(LOG_COUNTS["missionlog_t"])]
    assault = bytearray(LOG_STRUCTS["assaultlog_t"][0])
    campaign = bytearray(LOG_STRUCTS["campaignlog_t"][0])
    touched = set()

    moff = {f[0]: f[3] for f in mfields}          # member -> offset in missionlog_t
    offer = {v: QUEST_LOG[k] for k, v in QUEST_OFFER.items()}
    complete = {v: QUEST_LOG[k] for k, v in QUEST_COMPLETE.items()}
    aht = QUEST_LOG["AhtUrghan"]

    def set_mission_current(logid, value):
        missions[logid][moff["current"]:moff["current"] + 2] = \
            min(value, 0xFFFF).to_bytes(2, "little")
        touched.add("missions")

    def set_mission_complete(logid, mid):
        # `bool complete[64]` -- ONE BYTE per mission, not one bit. The packet
        # is bit-packed; the blob is not. Conflating them would set mission 8
        # when the player finished mission 1.
        missions[logid][moff["complete"] + mid] = 1
        touched.add("missions")

    for blk in blocks or []:
        try:
            port = int(blk["port"])
            body = bytes.fromhex(blk["data"])
        except (KeyError, TypeError, ValueError):
            warnings.append("a quest/mission block was unreadable; skipped.")
            continue
        if len(body) != QM_BODY_SIZE:
            warnings.append(
                f"quest/mission block Port 0x{port:04x} was {len(body)} bytes, "
                f"expected {QM_BODY_SIZE}. REFUSED -- these are flat bit arrays "
                "with no internal markers, so a wrong length misaligns every "
                "flag after it.")
            continue
        inner = _u16(body, QM_PORT_OFF)
        if inner != port:
            warnings.append(
                f"block claims Port 0x{port:04x} but carries 0x{inner:04x} at "
                "offset 32; REFUSED rather than guessing which is right.")
            continue
        data = body[:32]

        if port in offer:
            area = offer[port]
            if area == aht:
                # WARNING: The AhtUrghan offer packet OVERWRITES Data[4..7] with the
                # current Assault / ToAU / WoTG / Campaign missions AFTER the
                # quest memcpy, so the upper 16 bytes of that quest area's
                # `current` are simply not on the wire. They stay zero.
                quests[area][0:16] = data[0:16]
                assault[0:2] = min(_u32(data, 16), 0xFFFF).to_bytes(2, "little")
                touched.add("assault")
                set_mission_current(MISSION_LOG["ToAU"], _u32(data, 20))
                set_mission_current(MISSION_LOG["WoTG"], _u32(data, 24))
                campaign[0:2] = min(_u32(data, 28), 0xFFFF).to_bytes(2, "little")
                touched.add("campaign")
            else:
                quests[area][0:32] = data
            touched.add("quests")

        elif port in complete:
            area = complete[port]
            off = 32                              # `complete` follows `current`
            if area == aht:
                quests[area][off:off + 16] = data[0:16]
                for mid in range(128):            # assault complete, Data[4..7]
                    if data[16 + mid // 8] >> (mid % 8) & 1:
                        assault[2 + mid] = 1
                touched.add("assault")
            else:
                quests[area][off:off + 32] = data
            touched.add("quests")

        elif port == MISSION_COMPLETE["Nations"]:
            # Data[logID * 2 + q/32], bit q % 32, for Sandoria..Zilart
            for logid in range(MISSION_LOG["Sandoria"], MISSION_LOG["Zilart"] + 1):
                for q in range(64):
                    word = _u32(data, (logid * 2 + q // 32) * 4)
                    if word >> (q % 32) & 1:
                        set_mission_complete(logid, q)

        elif port == MISSION_COMPLETE["ToAU_WoTG"]:
            for q in range(64):
                if _u32(data, (q // 32) * 4) >> (q % 32) & 1:
                    set_mission_complete(MISSION_LOG["ToAU"], q)
                if _u32(data, (2 + q // 32) * 4) >> (q % 32) & 1:
                    set_mission_complete(MISSION_LOG["WoTG"], q)

        elif port in (MISSION_COMPLETE["Campaign1"], MISSION_COMPLETE["Campaign2"]):
            base = 0 if port == MISSION_COMPLETE["Campaign1"] else 256
            for mid in range(256):
                if _u32(data, (mid // 32) * 4) >> (mid % 32) & 1:
                    campaign[2 + base + mid] = 1
            touched.add("campaign")

        elif port == MISSION_PORT:
            nation = _u32(data, 0)
            if nation < LOG_COUNTS["missionlog_t"]:
                set_mission_current(nation, _u32(data, 4))
            else:
                warnings.append(f"nation {nation} in the mission packet is out "
                                "of range; nation mission not imported.")
            set_mission_current(MISSION_LOG["Zilart"], _u32(data, 8))
            set_mission_current(MISSION_LOG["CoP"], _u32(data, 12))
            cop2 = _u32(data, 16)
            cop = MISSION_LOG["CoP"]
            missions[cop][moff["statusUpper"]:moff["statusUpper"] + 2] = \
                (cop2 >> 16).to_bytes(2, "little")
            missions[cop][moff["statusLower"]:moff["statusLower"] + 2] = \
                (cop2 & 0xFFFF).to_bytes(2, "little")
            addons = _u16(data, 20)
            set_mission_current(MISSION_LOG["ACP"], addons & 0xF)
            set_mission_current(MISSION_LOG["AMK"], addons >> 4 & 0xF)
            set_mission_current(MISSION_LOG["ASA"], addons >> 8 & 0xF)
            # WARNING: SoA and RoV are OFFSET on the wire, and LSB's own source calls
            # the constants magic. A value below the offset means the player
            # declined the storyline (LSB sends 0 then), and the real progress
            # is NOT recoverable from this packet -- so it is left at 0 rather
            # than underflowed into a large wrong mission number.
            soa = _u32(data, 24)
            if soa >= 0x6E and (soa - 0x6E) % 2 == 0:
                set_mission_current(MISSION_LOG["SoA"], (soa - 0x6E) // 2)
            elif soa:
                warnings.append(f"SoA mission word 0x{soa:x} does not fit LSB's "
                                "current*2 + 0x6E encoding; left at 0.")
            rov = _u32(data, 28)
            if rov >= 0x6C:
                set_mission_current(MISSION_LOG["RoV"], rov - 0x6C)
            elif rov:
                warnings.append(f"RoV mission word 0x{rov:x} is below LSB's "
                                "+0x6C offset; left at 0.")
            # TalesBeginning (offset 22) records which storylines the player
            # DECLINED to start. LSB keeps those as char_vars, not in any blob
            # this importer writes, so they are read and dropped on purpose.

        else:
            warnings.append(f"quest/mission Port 0x{port:04x} is not one this "
                            "build knows; skipped.")

    out = {}
    if "quests" in touched:
        out["quests"] = b"".join(bytes(q) for q in quests)
    if "missions" in touched:
        out["missions"] = b"".join(bytes(m) for m in missions)
    if "assault" in touched:
        out["assault"] = bytes(assault)
    if "campaign" in touched:
        out["campaign"] = bytes(campaign)
    return out, warnings


# ---------------------------------------------------------------------------
# JOB POINTS AND TELEPORT UNLOCKS.
#
# Neither is readable from the client: the SDK has no fame, teleport, outpost,
# maw, survival or waypoint getter at all, and `GetJobPointsSpent` gives only a
# per-job total. Both ride packets instead, so both take the currency treatment
# -- captured raw by the addon, decoded here.
#
# WARNING: These layouts are HAND-WRITTEN, unlike the 193-field currency table. That is
# a deliberate line: the currency packets were far too many fields to transcribe
# safely, whereas these are six fields, three of them arrays. They are cited to
# their source below and the tests exercise every offset.
#
#   0x063 MISCDATA type 6 (Homepoints), PacketData 68 bytes
#       0 type u16 | 2 unknown06 u16 | 4 homePoint[4] | 20 survivalGuide[4]
#       36 waypoint[4] | 52 telepoint | 56 atmos | 60 eschanPortal | 64 unknown
#   0x063 MISCDATA type 5 (JobPoints), PacketData 152 bytes
#       0 type u16 | 2 unknown06 u16 | 4 access u8 | 5 pad[3]
#       8 jobs[24] of { capacityPoints u16, currentJp u16, totalJpSpent u16 }
#   0x08D JOB_POINTS, PacketData 256 bytes
#       points[64], each a u32 bitfield: index:5, job_no:11, next:10, level:6
# ---------------------------------------------------------------------------
MISC_TYPE_JOBPOINTS = 0x05
MISC_TYPE_HOMEPOINTS = 0x06
MISC_JP_SIZE = 152
MISC_HP_SIZE = 68
JP_TYPES_SIZE = 256

TELEPOINT_BYTES = 56        # telepoint_t: access[4] then menu[10]
WAYPOINT_BYTES = 12         # waypoint_t:  access[2], bool, 3 pad
JP_CATEGORIES = 10          # JOBPOINTS_JPTYPE_PER_CATEGORY -> jptype0..jptype9


def decode_teleports(body):
    """0x063 Homepoints PacketData -> {char_unlocks column: bytes|int}, warnings.

    WARNING: Only the three masks LSB actually drives are imported. Its own builder has
    `telepoint`, `atmos` and `eschanPortal` COMMENTED OUT as
    "untested/unimplemented", so decoding those would be inferring retail's
    layout from a stub -- a guess dressed as a transfer.
    """
    out, warnings = {}, []
    if len(body) != MISC_HP_SIZE:
        return {}, [f"teleport block was {len(body)} bytes, expected "
                    f"{MISC_HP_SIZE}; REFUSED rather than decoded from the "
                    "wrong offsets."]
    # telepoint_t is access[4] followed by menu[10]; `menu` is the client's own
    # ordering of the list, not an unlock, so it is left zero.
    out["homepoints"] = body[4:20] + bytes(TELEPOINT_BYTES - 16)
    out["survivals"] = body[20:36] + bytes(TELEPOINT_BYTES - 16)
    # WARNING: The packet carries FOUR waypoint words; LSB's waypoint_t holds TWO
    # (`access[2]`), and its own memcpy reads 16 bytes out of an 8-byte field.
    # Only the two LSB can hold are imported; the rest have nowhere to go.
    out["waypoints"] = body[36:44] + bytes(WAYPOINT_BYTES - 8)
    if int.from_bytes(body[44:52], "little"):
        warnings.append(
            "this character has waypoint unlocks past the two words LSB stores "
            "(waypoint_t.access[2]); those are not imported.")
    for off, what in ((52, "telepoints"), (56, "maws/atmacite"),
                      (60, "Eschan portals")):
        if int.from_bytes(body[off:off + 4], "little"):
            warnings.append(
                f"{what} are set in the dump but NOT imported: LSB leaves that "
                "field commented out as unimplemented, so its layout is "
                "unverified and writing it would be a guess.")
    return out, warnings


def decode_job_points(jp_body, type_bodies):
    """-> ({jobid: {column: value}}, warnings) from 0x063 type 5 plus 0x08D.

    Two packets, because neither is enough alone: 0x063 carries the per-job
    totals (capacity, unspent, spent) and 0x08D carries the per-CATEGORY levels
    that `char_job_points.jptype0..9` wants.
    """
    jobs, warnings = {}, []
    if jp_body is not None:
        if len(jp_body) != MISC_JP_SIZE:
            warnings.append(f"job point block was {len(jp_body)} bytes, "
                            f"expected {MISC_JP_SIZE}; REFUSED.")
        else:
            for j in range(1, 24):          # index 0 is NON, unused
                off = 8 + j * 6
                cap = int.from_bytes(jp_body[off:off + 2], "little")
                cur = int.from_bytes(jp_body[off + 2:off + 4], "little")
                spent = int.from_bytes(jp_body[off + 4:off + 6], "little")
                if cap or cur or spent:
                    jobs.setdefault(j, {}).update(
                        capacity_points=cap, job_points=cur,
                        job_points_spent=spent)
    for raw in type_bodies or []:
        # The dump carries these as hex, like every other raw capture.
        try:
            body = raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw)
        except (TypeError, ValueError):
            warnings.append("a job point category block was unreadable; skipped.")
            continue
        if len(body) != JP_TYPES_SIZE:
            warnings.append(f"a job point category block was {len(body)} bytes, "
                            f"expected {JP_TYPES_SIZE}; skipped.")
            continue
        for i in range(64):
            word = int.from_bytes(body[i * 4:i * 4 + 4], "little")
            if not word:
                continue
            index = word & 0x1F                 # bits 0-4
            job_no = (word >> 5) & 0x7FF        # bits 5-15
            level = (word >> 26) & 0x3F         # bits 26-31; `next` is derived
            if not 1 <= job_no <= 23 or index >= JP_CATEGORIES:
                continue
            if level:
                jobs.setdefault(job_no, {})[f"jptype{index}"] = level
    return jobs, warnings


def build_statements(dump, name=None, skill_scale=10):
    """dump (parsed polexport-1 JSON) -> {name, core: [sql], best: [sql]}.

    Every statement references @accid/@charid; the caller supplies both (see
    module docstring). Raises ValueError on an unusable dump.
    """
    if dump.get("format") != "polexport-1":
        raise ValueError("not a polexport-1 dump")
    name = validate_name(dump, name)
    look = dump.get("look") or {}
    race = min(max(int(look.get("race") or 1), 1), 8)
    face = min(max(int(look.get("face") or 0), 0), 15)
    size = min(max(int(look.get("size") or 0), 0), 2)
    nation = int(dump.get("nation") or 0)
    nation = nation if nation in NATION_ZONE else 0
    mjob = int(dump.get("main_job") or 1)
    mjob = mjob if 1 <= mjob <= 22 else 1
    sjob = int(dump.get("sub_job") or 0)
    jobs = {int(k): int(v) for k, v in (dump.get("jobs") or {}).items()
            if int(k) in JOB_COLS and int(v) > 0}
    gil = max(int(dump.get("gil") or 0), 0)

    core, best, warnings = [], [], []
    # The skeleton LSB's loginHelpers::createCharacter writes, verbatim.
    core.append(f"INSERT INTO chars(charid,accid,charname,pos_zone,nation) "
                f"VALUES(@charid, @accid, {q(name)}, {NATION_ZONE[nation]}, {nation})")
    core.append(f"INSERT INTO char_look(charid,face,race,size) "
                f"VALUES(@charid, {face}, {race}, {size})")
    core.append(f"INSERT INTO char_stats(charid,mjob) VALUES(@charid, {mjob})")
    for t in ("char_exp", "char_jobs", "char_points", "char_unlocks",
              "char_profile", "char_storage"):
        core.append(f"INSERT INTO {t}(charid) VALUES(@charid) "
                    f"ON DUPLICATE KEY UPDATE charid = charid")
    core.append("INSERT INTO char_flags(charid) VALUES(@charid) "
                "ON DUPLICATE KEY UPDATE disconnecting = disconnecting")
    core.append("DELETE FROM char_inventory WHERE charid = @charid")
    core.append("INSERT INTO char_inventory(charid) VALUES(@charid)")  # gil row

    # What the character actually is.
    if 1 <= sjob <= 22:
        core.append(f"UPDATE char_stats SET sjob = {sjob} WHERE charid = @charid")
    if jobs:
        unlocked = 0x7E  # the six base jobs
        for j in jobs:
            if j >= 7:
                unlocked |= 1 << j
        sets = ", ".join(f"{JOB_COLS[j]} = {lv}" for j, lv in sorted(jobs.items()))
        core.append(f"UPDATE char_jobs SET unlocked = {unlocked}, {sets} "
                    f"WHERE charid = @charid")
    if gil:
        core.append(f"UPDATE char_inventory SET quantity = {gil} "
                    f"WHERE charid = @charid AND location = 0 AND slot = 0")

    rows = []
    placed = {}     # (location, slot) -> itemId, exactly what we are inserting
    needed = {}     # char_storage column -> the size those rows require
    for _cname, c in sorted((dump.get("containers") or {}).items()):
        loc = int(c.get("id", -1))
        if loc < 0 or loc == 3:   # Temporary is not imported
            continue
        # The size the container has to be for its contents to survive load.
        # `size` is what the exporting client reported (GetContainerCountMax);
        # dumps taken before the exporter recorded it fall back to the highest
        # occupied slot, which is a true lower bound either way.
        hi = max([int(s) for s, *_ in c.get("items", [])] or [0])
        want = max(int(c.get("size") or 0), hi)
        col = STORAGE_COLS.get(loc)
        if col:
            needed[col] = max(needed.get(col, 0), want)
        for slot, item_id, count, extra_hex in c.get("items", []):
            if loc == 0 and int(slot) == 0:
                continue  # gil handled above
            extra = (extra_hex or "")[:48]  # 24 bytes, LSB's extra size
            ok_hex = (extra and len(extra) % 2 == 0
                      and re.fullmatch(r"[0-9a-fA-F]+", extra))
            extra_sql = f"x'{extra}'" if ok_hex else "''"
            rows.append(f"(@charid, {loc}, {int(slot)}, {int(item_id)}, "
                        f"{int(count)}, {extra_sql})")
            placed[(loc, int(slot))] = int(item_id)
        if loc == LOC_STORAGE and c.get("items"):
            warnings.append(
                f"{len(c['items'])} item(s) are in mog STORAGE (container 2). "
                "LSB has no char_storage column for it -- it sizes that "
                "container from the furnishings installed in the mog safe, and "
                "furnishing placement does not transfer. They may not appear "
                "in game until furniture is installed.")
    if rows:
        core.append("INSERT INTO char_inventory"
                    "(charid,location,slot,itemId,quantity,extra) VALUES\n"
                    + ",\n".join("  " + r for r in rows))

    # Size the containers to fit. CORE, not best-effort: without this the
    # INSERT above commits rows that LSB silently drops at world load.
    sizes = {col: min(max(want, STORAGE_DEFAULTS[col]), STORAGE_MAX)
             for col, want in needed.items()}
    grew = {c: n for c, n in sizes.items() if n != STORAGE_DEFAULTS[c]}
    if grew:
        sets = ", ".join(f"`{c}` = {n}" for c, n in sorted(grew.items()))
        core.append(f"UPDATE char_storage SET {sets} WHERE charid = @charid")
    for col, want in sorted(needed.items()):
        if want > STORAGE_MAX:
            warnings.append(
                f"container `{col}` needs {want} slots but LSB caps a player "
                f"container at {STORAGE_MAX} -- items past slot {STORAGE_MAX} "
                "will not load.")

    # Equipment. dump.equipment is {equipslot: [container, index, itemId]} and
    # LSB's char_equip is (equipslotid, containerid, slotid) pointing at a
    # char_inventory row -- so this is a reference, not a copy, and a stale one
    # equips the WRONG item. The reference only holds because this importer
    # preserves the dump's own container/slot numbering verbatim (see `placed`
    # above); rather than trust that, every entry is checked against the row
    # actually being inserted, itemId included, and a mismatch is dropped.
    # NB the sort key must not be int(): a non-numeric equipment key would raise
    # from OUTSIDE the try below and abort the entire import over one bad slot.
    eqrows, eqdrop = [], 0
    for eslot, ent in sorted((dump.get("equipment") or {}).items(),
                             key=lambda kv: str(kv[0])):
        try:
            es = int(eslot)
            cid, idx, iid = int(ent[0]), int(ent[1]), int(ent[2])
        except (TypeError, ValueError, IndexError, KeyError):
            eqdrop += 1
            continue
        if not 0 <= es < 16 or placed.get((cid, idx)) != iid:
            eqdrop += 1
            continue
        eqrows.append((es, f"(@charid, {es}, {idx}, {cid})"))
    eqrows = [r for _, r in sorted(eqrows)]
    if eqrows:
        # Cleared first for the same reason char_inventory is: char_equip's PK is
        # (charid, equipslotid), so a re-run against an existing charid would hit
        # a duplicate key -- and because this is ONE statement, that would lose
        # every equipped slot, not just the colliding one.
        best.append("DELETE FROM char_equip WHERE charid = @charid")
        best.append("INSERT INTO char_equip(charid,equipslotid,slotid,containerid)"
                    " VALUES\n" + ",\n".join("  " + r for r in eqrows))
    if eqdrop:
        warnings.append(f"{eqdrop} equipped item(s) could not be matched to an "
                        "imported inventory row and were left unequipped.")

    # Skills. ONE ROW PER skillid, and that is not a formality: char_skills'
    # primary key is (charid, skillid) and these rows go out as a SINGLE INSERT,
    # so one duplicate does not lose one skill -- it fails the whole statement
    # and the character lands with NO skills at all, in the best-effort section,
    # i.e. logged and nowhere else.
    #
    # Crafts WIN the merge: the craft entry is the one that carries `rank`, and
    # LSB only reads rank for skillid >= Fishing (charutils.cpp ~899).
    #
    # WARNING: The ORIGINAL argument for this merge is RETRACTED, and it is worth
    # keeping the correction visible. It claimed polexport's combat sweep to id
    # 63 "walked through the craft block", exporting every craft twice, because
    # FFXI's flat numbering puts crafts at 48..57. That flat numbering is the
    # MEMORY layout and LSB's database ids -- it is NOT Ashita's calling
    # convention. The SDK's own annotations define two SEPARATE, both-0-based
    # arrays: `combatskills_t` is 48 entries
    # (0..47) and `craftskills_t` is re-based at 0, Fishing 0 .. Digging 11. So
    # GetCombatSkill(48) was reading past the end of a 48-entry array, not
    # reading Fishing.
    #
    # The merge STAYS, for two reasons that do not depend on that argument:
    # whether those out-of-bounds reads were bounds-checked or ran on into the
    # adjacent CraftSkills field is not answerable from the annotations, so
    # dumps already taken may or may not carry duplicates; and a duplicate here
    # costs the character EVERY skill, which is far too expensive an outcome to
    # leave resting on a reading of someone else's array bounds.
    #
    # `value` is displayed_skill * skill_scale. VERIFIED, not assumed: LSB's
    # RealSkills.skill[] is tenths everywhere it is consumed --
    # `WorkingSkills.skill[i] = (RealSkills.skill[i] / 10) * 0x20 + rank`
    # (charutils.cpp ~3735), and the same /10 in the fishing and skill-up paths.
    skills = {int(k): int(v) for k, v in (dump.get("skills") or {}).items()}
    craft = {int(k): (v if isinstance(v, dict) else {"skill": v, "rank": 0})
             for k, v in (dump.get("crafts") or {}).items()}
    merged = {sid: (int(val) * skill_scale, 0) for sid, val in skills.items()}
    for idx, c in craft.items():
        merged[CRAFT_SKILL_BASE + int(idx)] = (
            int(c.get("skill", 0)) * skill_scale, int(c.get("rank", 0)))
    collisions = sorted(set(skills) & {CRAFT_SKILL_BASE + int(i) for i in craft})
    if collisions:
        warnings.append(
            f"skill id(s) {collisions} were reported as BOTH a combat skill and "
            "a craft; the craft value was kept. Dumps from polexport before 0.3 "
            "swept combat skills past the end of the client's 48-entry array, "
            "so this is that dump's ambiguity, not corrupt data.")
    skrows = [f"(@charid, {sid}, {val}, {rank})"
              for sid, (val, rank) in sorted(merged.items())]
    if skrows:
        best.append("INSERT INTO char_skills(charid,skillid,value,`rank`) VALUES\n"
                    + ",\n".join("  " + r for r in skrows))
    kids = sorted(set(int(k) for k in dump.get("key_items") or []))
    ki, ki_dropped = keyitem_blob(kids)
    n_mounts = sum(1 for k in kids
                   if MOUNT_KEYITEM_FIRST <= k <= MOUNT_KEYITEM_LAST)
    if ki:
        best.append(f"UPDATE chars SET keyitems = x'{ki.hex()}' "
                    f"WHERE charid = @charid")
    if ki_dropped:
        warnings.append(f"{ki_dropped} key item id(s) were outside LSB's "
                        f"0..{KEYITEM_MAX - 1} range and were dropped.")
    rank = int(dump.get("rank") or 0)
    if rank > 0:
        best.append(f"UPDATE char_profile SET {NATION_RANK_COL[nation]} = {rank}, "
                    f"rank_points = {int(dump.get('rank_points') or 0)} "
                    f"WHERE charid = @charid")

    # The level cap. `genkai` is "the maximum genkai level achieved" and LSB
    # gates exp on it (charutils.cpp ~5199: at genkai the bar pins one point
    # short), so a level-75 import left at the schema default 50 cannot gain a
    # point. DERIVED, not exported -- but it is a proof, not a guess: a
    # character cannot BE level N without having reached genkai N.
    #
    # WARNING: THE CEILING IS 99, NOT 75. LSB's own limit-break quests set genkai to
    # 55/60/65/70/75 and then 80/85/90/95/99 (scripts/quests/jeuno/LB01..LB10),
    # so clamping to 75 would strand every imported character above level 75 --
    # 90 >= 75 pins the bar exactly the same way the default 50 does.
    #
    # It is a LOWER bound, not the true value: a character who reached level 75
    # may already hold an 80 cap. They re-earn the difference; nothing they had
    # is taken away, which is the right direction for a guess to be wrong in.
    genkai = min(max(max(jobs.values(), default=0), 50), 99)
    if genkai > 50:
        best.append(f"UPDATE char_jobs SET genkai = {genkai} WHERE charid = @charid")

    # Title. TWO places, because LSB keeps them apart: char_stats.title is the
    # one being WORN (charutils.cpp ~811) and chars.titles is the bit array of
    # every title OBTAINED (m_TitleList[143], loaded at ~527). Writing only the
    # first gives a character wearing a title that its own title list says it
    # never earned. The bit order is identical to keyitems -- addBit() is
    # `BitArray[value >> 3] |= 1 << (value % 8)` (common/utils.cpp) -- so
    # keyitem_blob builds it.
    title = int(dump.get("title") or 0)
    if 0 < title < 143 * 8:
        best.append(f"UPDATE char_stats SET title = {title} "
                    f"WHERE charid = @charid")
        best.append(f"UPDATE chars SET titles = x'{keyitem_blob([title]).hex()}' "
                    f"WHERE charid = @charid")
    merits = int(dump.get("merits") or 0)
    if merits > 0:
        best.append(f"UPDATE char_exp SET merits = {min(merits, 255)} "
                    f"WHERE charid = @charid")

    # Spells. `spells` is a flat list of ids the client said it knows.
    #
    # WARNING: ABSENT AND EMPTY ARE DIFFERENT and must not be conflated. A dump from
    # an exporter that could not read spells at all carries no `spells` key; a
    # dump from a character who genuinely knows none carries an empty list. The
    # first must not read as "this character has no spells" -- that is the same
    # trap the quest log guards with its explicit `count`, and the reason the
    # exporter states `spells_readable` separately.
    n_spells = 0
    spells_raw = dump.get("spells")
    if spells_raw is None:
        warnings.append(
            "this dump carries NO spell list (exported before polexport 0.4). "
            "The character's spells were not imported -- that is missing data, "
            "not an empty spellbook. Re-export to bring them over.")
    elif dump.get("spells_readable") is False:
        warnings.append(
            "the exporting client could not read the spell list, so no spells "
            "were imported. This is a client/API problem, not an empty "
            "spellbook -- do not treat the character as fully transferred.")
    else:
        ids, dropped = set(), 0
        for sid in spells_raw:
            try:
                v = int(sid)
            except (TypeError, ValueError):
                dropped += 1
                continue
            if 0 < v < MAX_SPELL_ID:
                ids.add(v)
            else:
                dropped += 1
        if ids:
            best.append("DELETE FROM char_spells WHERE charid = @charid")
            best.append("INSERT INTO char_spells(charid,spellid) VALUES\n"
                        + ",\n".join(f"  (@charid, {v})" for v in sorted(ids)))
        n_spells = len(ids)
        if dropped:
            warnings.append(
                f"{dropped} spell id(s) were outside LSB's 1..{MAX_SPELL_ID - 1} "
                "range and were dropped.")

    # Abilities. `chars.abilities` is a 49-byte bit array and LSB consults it for
    # exactly one thing: an ability flagged ADDTYPE_LEARNED is refused unless its
    # bit is set (charutils.cpp ~6403). Everything else is granted by job and
    # level, so a bit set for it is inert.
    #
    # In practice that set is the CORSAIR ROLLS -- 31 of them at the pinned LSB
    # revision -- which is worth saying plainly, because "abilities imported"
    # sounds like far more than it is. A COR who arrives without their rolls is
    # broken; a WAR notices nothing either way.
    #
    # The exporter sweeps broadly and the FILTERING HAPPENS HERE, against the
    # generated table. That way a future LSB that gates a different ability is
    # picked up by re-running the generator, with no need to re-export anything.
    n_abilities = 0
    abil_raw = dump.get("abilities")
    if abil_raw is None:
        pass                     # exported before 0.6; nothing claimed either way
    elif dump.get("abilities_readable") is False:
        warnings.append(
            "the client had not received ability data, so learned abilities "
            "(Corsair rolls) were not imported. Not the same as having none.")
    elif LEARNED_ABILITIES is None:
        warnings.append("this build has no ffxi_lsb_tables (regenerate with "
                        "tools/gen_ffxi_lsb_tables.py) -- abilities skipped.")
    else:
        ids = set()
        for a in abil_raw:
            try:
                v = int(a)
            except (TypeError, ValueError):
                continue
            if v in LEARNED_ABILITIES:
                ids.add(v)
        if ids:
            blob = bytearray(LEARNED_ABILITY_BYTES)
            for v in ids:
                blob[v // 8] |= 1 << (v % 8)
            best.append(f"UPDATE chars SET abilities = x'{bytes(blob).hex()}' "
                        f"WHERE charid = @charid")
        n_abilities = len(ids)

    # Weapon skills. `chars.weaponskills` is an xi::bitset<64> whose bit layout
    # matches addBit exactly (bit N in byte N/8 at 1 << (N % 8), bytes ascending;
    # xi.h `bitset::set` is `data[pos / 8] |= 1 << (pos % 8)`), and the blob is
    # the raw 8 bytes. LSB reads it as `getUnlockId() == 0 || hasLearned...`
    # (battleutils.cpp ~396), so a weapon skill with no unlock id is available
    # regardless and only the unlockable ones are worth storing.
    #
    # The dump carries the CLIENT's weapon skill ids; the translation to
    # wsUnlockId happens here, against the generated table.
    n_ws = 0
    ws_raw = dump.get("weaponskills")
    if ws_raw is None:
        pass                     # exported before 0.6; nothing claimed either way
    elif dump.get("abilities_readable") is False:
        pass                     # already warned about by the abilities block
    elif WS_UNLOCKS is None:
        warnings.append("this build has no ffxi_lsb_tables (regenerate with "
                        "tools/gen_ffxi_lsb_tables.py) -- weapon skills skipped.")
    else:
        bits, unmapped = set(), 0
        for w in ws_raw:
            try:
                v = int(w)
            except (TypeError, ValueError):
                continue
            unlock = WS_UNLOCKS.get(v)
            if unlock is None:
                unmapped += 1    # not unlockable, or not a ws id LSB knows
            else:
                bits.add(unlock)
        if bits:
            blob = bytearray(LEARNED_WS_BYTES)
            for b in bits:
                blob[b // 8] |= 1 << (b % 8)
            best.append(f"UPDATE chars SET weaponskills = x'{bytes(blob).hex()}' "
                        f"WHERE charid = @charid")
        n_ws = len(bits)
        # NOT a warning: most weapon skills have no unlock id and are available
        # to anyone who meets the requirements. Reported only so the number is
        # explainable rather than mysterious.
        if unmapped and not bits:
            warnings.append(
                f"none of the {unmapped} weapon skill(s) in this dump are ones "
                "LSB gates behind an unlock. If that seems wrong, the exported "
                "ids may not be LSB's weapon skill ids.")

    # The quest and mission log. Captured raw since polexport 0.2 (2026-08-25)
    # and, until now, never consumed.
    #
    # WARNING: REFUSED rather than half-written when the capture never happened. The
    # log arrives on ZONE-IN, so a dump taken without zoning has count 0, and
    # writing the all-zero blobs that would produce erases a real quest log.
    # This is the case the exporter's `count` exists for.
    n_qm = 0
    ql = dump.get("questlog") or {}
    if ql:
        if not int(ql.get("count") or 0):
            warnings.append(
                "the quest/mission log was NOT captured in this dump (it "
                "arrives on ZONE-IN, so the addon must be loaded before you "
                "zone). Quests and missions were left untouched rather than "
                "overwritten with an empty log.")
        else:
            qblobs, qwarn = decode_questlog(ql.get("blocks"))
            warnings.extend(qwarn)
            for col, blob in sorted(qblobs.items()):
                best.append(f"UPDATE chars SET {col} = x'{blob.hex()}' "
                            f"WHERE charid = @charid")
            n_qm = len(qblobs)

    # Teleport unlocks and job points -- both off the wire, see above.
    n_jp = 0
    misc = dump.get("miscdata") or {}
    jp_totals = None
    for blk in (misc.get("blocks") or []):
        try:
            t = int(blk["type"])
            body = bytes.fromhex(blk["data"])
        except (KeyError, TypeError, ValueError):
            warnings.append("a miscdata block was unreadable; skipped.")
            continue
        if t == MISC_TYPE_HOMEPOINTS:
            cols, twarn = decode_teleports(body)
            warnings.extend(twarn)
            if cols:
                sets = ", ".join(
                    f"`{c}` = x'{v.hex()}'" for c, v in sorted(cols.items()))
                best.append(f"UPDATE char_unlocks SET {sets} "
                            f"WHERE charid = @charid")
        elif t == MISC_TYPE_JOBPOINTS:
            jp_totals = body
        else:
            warnings.append(f"miscdata type {t} is not one this build "
                            "consumes; skipped.")

    jpjobs, jwarn = decode_job_points(jp_totals, dump.get("job_point_types"))
    warnings.extend(jwarn)
    if jpjobs:
        # char_job_points is UNIQUE (charid, jobid) -- one row per job, so this
        # is an upsert rather than a blind insert.
        rows = []
        cols = ["capacity_points", "job_points", "job_points_spent"] + \
               [f"jptype{i}" for i in range(JP_CATEGORIES)]
        for jid, vals in sorted(jpjobs.items()):
            rows.append("(@charid, %d, %s)" % (
                jid, ", ".join(str(int(vals.get(c, 0))) for c in cols)))
        upd = ", ".join(f"{c} = VALUES({c})" for c in cols)
        best.append("INSERT INTO char_job_points(charid,jobid," + ",".join(cols)
                    + ") VALUES\n" + ",\n".join("  " + r for r in rows)
                    + "\nON DUPLICATE KEY UPDATE " + upd)
        n_jp = len(jpjobs)

    # Currencies. Same shape as the quest log: raw packets in, decoded here.
    #
    # WARNING: 0x113/0x118 arrive on ZONE-IN like the quest log, so a dump taken
    # without zoning carries none -- and `count` is what tells the two apart.
    # An absent capture must not read as "this character has nothing", which is
    # the same trap as spells and quests.
    cur = dump.get("currencies") or {}
    n_currencies = 0
    if cur:
        ccols, cwarn = decode_currencies(cur.get("blocks"))
        warnings.extend(cwarn)
        # Only non-zero values are written. Every column these touch defaults to
        # 0 in char_points (the sole exception, daily_tally, defaults to -1 and
        # is deliberately NOT column-backed -- the packet sends 0 for -1, so the
        # value cannot be inverted), which makes this exactly equivalent to
        # writing all 193 and leaves a reviewable statement instead of a wall.
        nz = {c: v for c, v in ccols.items() if v}
        n_currencies = len(nz)
        if nz:
            sets = ", ".join(f"`{c}` = {v}" for c, v in sorted(nz.items()))
            best.append(f"UPDATE char_points SET {sets} WHERE charid = @charid")
    elif dump.get("format") == "polexport-1":
        warnings.append(
            "no currencies in this dump (exported before polexport 0.5, or the "
            "addon was loaded after zoning -- 0x113/0x118 arrive on ZONE-IN). "
            "Conquest points, sparks, guild points, bayld and the rest were NOT "
            "imported. That is missing data, not an empty wallet.")

    # `set_blue_spells` (the twenty EQUIPPED blue magic slots) is NOT imported
    # and is not the same thing as the list above. LSB keeps it as a
    # `char(20)`-style blob on `chars`, each byte holding `spellid - 0x200`
    # (blueutils.cpp LoadSetSpells; blue ids run 513..746, so the subtraction
    # fits a uint8), and it is only read when BLU is the main or sub job. A BLU
    # who arrives with every spell LEARNED can set them again in a minute; a
    # wrong byte here silently un-sets a spell instead. Export it first.

    # Home point.
    #
    # `GetHomepoint()` gives the client's INDEX; LSB wants a zone and a
    # position. This was refused for a day on the grounds that the index->zone
    # table did not exist -- it does, and always did:
    # `scripts/globals/homepoint.lua`, index -> {x, y, z, rot, zone}. HOMEPOINTS
    # is that table with `xi.zone.*` resolved against zone.yaml.
    #
    # WARNING: THE RESOLVED ZONE IS REPORTED, NOT WRITTEN SILENTLY. The one thing not
    # verified is whether the client's index numbering is the same as LSB's
    # table -- it must be for LSB's own homepoint menu to work, but nobody has
    # measured it here, and a wrong index is precisely the failure that LOOKS
    # fine: the character simply wakes up somewhere plausible and wrong. Naming
    # the destination makes it checkable by the one person who knows.
    #
    # WARNING: Index 0 is a real home point (Southern San d'Oria #1), not a "unset"
    # sentinel, so it cannot be filtered out -- which is the other reason to
    # report the name rather than trust the number.
    home_zone = None
    hp = dump.get("homepoint")
    if hp is not None and HOMEPOINTS:
        try:
            hp = int(hp)
        except (TypeError, ValueError):
            hp = None
        entry = HOMEPOINTS.get(hp) if hp is not None else None
        if entry is None:
            if hp is not None:
                warnings.append(
                    f"home point index {hp} is not in LSB's homepoint table "
                    f"(0..{max(HOMEPOINTS)}); left at the nation start point.")
        else:
            x, y, z, rot, zid, zname = entry
            home_zone = zname
            best.append(
                f"UPDATE chars SET home_zone = {zid}, home_rot = {rot}, "
                f"home_x = {x}, home_y = {y}, home_z = {z} "
                f"WHERE charid = @charid")
            warnings.append(
                f"home point set to {zname.replace('_', ' ')} (index {hp}). "
                "CHECK THIS -- if it is not where you set your home point, the "
                "client's homepoint numbering differs from LSB's and the rest "
                "of this field should be treated as suspect.")

    return {"name": name, "core": core, "best": best, "warnings": warnings,
            "n_items": len(rows), "n_skills": len(skrows), "n_equip": len(eqrows),
            "n_keyitems": len(dump.get("key_items") or []),
            "n_mounts": n_mounts, "n_jp": n_jp, "gil": gil,
            "n_spells": n_spells, "n_currencies": n_currencies,
            "n_abilities": n_abilities, "n_ws": n_ws, "n_qm": n_qm,
            "home_zone": home_zone, "storage": sizes}
