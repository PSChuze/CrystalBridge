#!/usr/bin/env python3
# The tables this script writes are derived from LandSandBoat
# (https://github.com/LandSandBoat/server), which is licensed under the GNU
# General Public License v3.0. The generated module (lsb/ffxi_lsb_tables.py) is
# therefore distributed under GPL-3.0 as well; see LICENSE and NOTICE. Source
# files read: src/map/packets/s2c/0x113_currencies_1.{h,cpp} and
# 0x118_currencies_2.{h,cpp}, sql/abilities.sql, sql/weapon_skills.sql,
# src/map/enums/quest_log.h, src/map/enums/mission_log.h, src/common/mmo.h,
# src/map/entities/char_entity.h, data/enums/zone.yaml and
# scripts/globals/homepoint.lua.
"""Generate lsb/ffxi_lsb_tables.py from LandSandBoat's own source.

Everything the character import needs to know about LSB's wire formats and id
sets, parsed out of LSB rather than transcribed into Python by hand. Two tables
so far -- the currency packets, and the set of abilities LSB gates on a
"learned" bit -- and the rule for adding a third is the same: if the fact lives
in LSB's source or its shipped data, parse it, do not copy it.

CURRENCIES

FFXI currencies are not in any client structure an addon can read: the server
pushes them and the client renders its menus from the push. So the only way to
export them is to catch packets 0x113 and 0x118 -- exactly the treatment the
quest log (0x056) already gets -- and decode them server-side.

Decoding needs two things, and BOTH already exist in LSB, so neither is
transcribed by hand here:

  * the wire LAYOUT -- `struct PacketData` in 0x113_currencies_1.h / 0x118_*.h;
  * the field -> char_points COLUMN mapping -- the `packet.x = rset->get<T>("y")`
    lines in the matching .cpp, which is the code that BUILDS these packets from
    char_points and is therefore a spec rather than a guess.

There are 193 of those pairs. Hand-copying them is precisely the sort of job
that produces one silent transposition nobody finds for a month, so this script
parses them instead and the generated module is regenerated rather than edited.

LEARNED ABILITIES

`chars.abilities` is a 49-byte bit array (`m_LearnedAbilities`) and LSB consults
it for exactly one thing: an ability whose `addType` has ADDTYPE_LEARNED (8) is
refused unless its bit is set (charutils.cpp ~6403). Every other ability is
granted by job and level, so a bit set for one is inert. Rather than import
whatever the client reports and hope the extra bits are harmless, the importer
writes only the ids LSB actually gates -- and that set is read here out of
`sql/abilities.sql`.

WEAPON SKILL UNLOCKS

`chars.weaponskills` is an `xi::bitset<64>` and its bit positions are NOT weapon
skill ids -- they are `wsUnlockId`, a dense 1..63 index. Decimation is weapon
skill **72** and unlock id **5**. Confusing the two would set an arbitrary wrong
bit, i.e. grant an unrelated weapon skill. The translation lives in one column,
`weapon_skills.unlock_id`, and is read from there.

QUEST AND MISSION LOGS

The 0x056 packet family carries the quest and mission log, keyed by a `Port`
value that says which block it is. Three things are needed to invert it and all
three are read from LSB rather than typed in here: the `Port` values
(`enums/quest_log.h`, `enums/mission_log.h`), the log indices those ports map to,
and the byte sizes of the structures the blobs hold (`common/mmo.h`).

WARNING: What is NOT generated is the PACKING, because it is code and not data --
`0x056_mission_other.cpp` does bit twiddling that no table can express. That
part is written by hand in ffxi_import_core and is the part the tests hammer.

HOME POINTS

`GetHomepoint()` gives the client's homepoint INDEX; `chars.home_zone` plus
`home_x/y/z/rot` wants a zone and a position. That was once taken for a
blocker on the grounds that the index->zone table did not exist. It does:
`scripts/globals/homepoint.lua` is exactly that table, index ->
`{x, y, z, rot, zone}`, with the zone as an `xi.zone.NAME` resolved here against
`data/enums/zone.yaml`.

    python tools/gen_ffxi_lsb_tables.py [--lsb ./lsb-server] [--check]

`--lsb` is a checkout of LandSandBoat at the revision the pinned image was
built from (default: `lsb-server/` in the repository root). --check
regenerates in memory and exits non-zero if the committed file differs, which
is the thing to run after bumping the pinned LSB revision.
"""
import argparse
import os
import re
import sys

PACKETS = [
    ("0x113", "GP_SERV_COMMAND_CURRENCIES_1", "0x113_currencies_1"),
    ("0x118", "GP_SERV_COMMAND_CURRENCIES_2", "0x118_currencies_2"),
]

CTYPE_SIZE = {"uint8_t": 1, "int8_t": 1, "uint16_t": 2, "int16_t": 2,
              "uint32_t": 4, "int32_t": 4, "uint64_t": 8, "int64_t": 8}

ADDTYPE_LEARNED = 8          # src/map/ability.h
ABILITY_ADDTYPE_COL = 19     # 0-based column of `addType` in sql/abilities.sql
LEARNED_ABILITY_BITS = 49 * 8   # sizeof(m_LearnedAbilities) * 8, char_entity.h
WS_UNLOCK_BITS = 64             # sizeof(m_LearnedWeaponskills) in bits

# splits a SQL VALUES list on commas that are not inside single quotes
RE_SQL_SPLIT = re.compile(r",(?=(?:[^']*'[^']*')*[^']*$)")
RE_ABILITY_ROW = re.compile(r"INSERT INTO `abilities` VALUES \((.*?)\);")
RE_WS_ROW = re.compile(r"INSERT INTO `weapon_skills` VALUES \((.*?)\);")

RE_ENUM_MEMBER = re.compile(r"^\s*(\w+)\s*=\s*(0[xX][0-9a-fA-F]+|\d+)\s*,", re.M)
# [ 12] = { group = 2, fee = 1, dest = { -328, -12, -33, 0, xi.zone.BASTOK_MARKETS } },
RE_HOMEPOINT = re.compile(
    r"\[\s*(?P<idx>\d+)\s*\]\s*=\s*\{[^}]*?dest\s*=\s*\{\s*"
    r"(?P<x>-?[\d.]+)\s*,\s*(?P<y>-?[\d.]+)\s*,\s*(?P<z>-?[\d.]+)\s*,\s*"
    r"(?P<rot>-?[\d.]+)\s*,\s*xi\.zone\.(?P<zone>\w+)\s*\}")
RE_YAML_VALUE = re.compile(r"^\s{2}(\w+):\s*(\d+)", re.M)
RE_STRUCT_MEMBER = re.compile(
    r"^\s*(?P<ctype>u?int(?:8|16|32|64)|bool)\s+(?P<name>\w+)"
    r"(?:\s*\[\s*(?P<count>\d+)\s*\])?\s*;", re.M)
# LSB's own aliases in common/mmo.h -- uint8/uint16/... not the _t spellings
MMO_SIZE = {"uint8": 1, "int8": 1, "uint16": 2, "int16": 2, "uint32": 4,
            "int32": 4, "uint64": 8, "int64": 8, "bool": 1}

# a plain scalar, an array, or a bitfield member
RE_FIELD = re.compile(
    r"^\s*(?P<ctype>u?int(?:8|16|32|64)_t)\s+(?P<name>\w+)"
    r"(?:\s*\[\s*(?P<count>\d+)\s*\])?"
    r"(?:\s*:\s*(?P<bits>\d+))?\s*;")
RE_MAP = re.compile(
    r"packet\.(?P<field>\w+)\s*=\s*rset->get<(?P<ctype>\w+)>\(\"(?P<col>\w+)\"\)")
RE_OTHER_ASSIGN = re.compile(r"packet\.(?P<field>\w+)\s*=\s*(?P<rhs>[^;]+);")


def parse_struct(header_text):
    """-> ordered [ {name, ctype, size, count, bits} ] for `struct PacketData`."""
    m = re.search(r"struct PacketData\s*\{(.*?)\n    \};", header_text, re.S)
    if not m:
        raise SystemExit("could not find `struct PacketData`")
    fields = []
    for line in m.group(1).splitlines():
        line = line.split("//")[0]
        fm = RE_FIELD.match(line)
        if not fm:
            continue
        ctype = fm.group("ctype")
        fields.append({
            "name": fm.group("name"),
            "ctype": ctype,
            "size": CTYPE_SIZE[ctype],
            "count": int(fm.group("count")) if fm.group("count") else None,
            "bits": int(fm.group("bits")) if fm.group("bits") else None,
        })
    if not fields:
        raise SystemExit("`struct PacketData` parsed to zero fields")
    return fields


def parse_mapping(cpp_text):
    """-> ({field: (column, ctype)}, {field: rhs}) for column-backed vs computed."""
    mapped, computed = {}, {}
    for m in RE_MAP.finditer(cpp_text):
        mapped[m.group("field")] = (m.group("col"), m.group("ctype"))
    for m in RE_OTHER_ASSIGN.finditer(cpp_text):
        f = m.group("field")
        if f not in mapped:
            computed[f] = " ".join(m.group("rhs").split())
    return mapped, computed


def layout(fields):
    """Assign byte offsets. `#pragma pack(push, 1)` -> no padding anywhere.

    Consecutive bitfield members share one storage unit of their declared type,
    filled LSB-first on little-endian. Everything here is uint64_t : 9 x5 plus a
    :19 filler, i.e. exactly one 8-byte unit -- but the packer below is written
    generally and ASSERTS that, rather than assuming it.
    """
    out, off, bitunit = [], 0, None
    for f in fields:
        if f["bits"] is not None:
            if bitunit is None or bitunit["ctype"] != f["ctype"] or \
                    bitunit["used"] + f["bits"] > f["size"] * 8:
                bitunit = {"ctype": f["ctype"], "offset": off,
                           "size": f["size"], "used": 0}
                off += f["size"]
            out.append(dict(f, kind="bits", offset=bitunit["offset"],
                            unit_size=bitunit["size"], shift=bitunit["used"]))
            bitunit["used"] += f["bits"]
            continue
        bitunit = None
        n = f["count"] or 1
        out.append(dict(f, kind="array" if f["count"] else "scalar", offset=off))
        off += f["size"] * n
    return out, off


def parse_learned_abilities(sql_text):
    """-> ordered [(abilityId, name)] for every ability LSB gates on a learned bit.

    Refuses any id the blob cannot physically hold: `addBit` silently declines
    `value >= size * 8`, so an id past 391 would import as nothing at all and
    look exactly like a character who never learned it.
    """
    out, overflow = [], []
    for m in RE_ABILITY_ROW.finditer(sql_text):
        parts = [p.strip() for p in RE_SQL_SPLIT.split(m.group(1))]
        if len(parts) <= ABILITY_ADDTYPE_COL:
            continue
        try:
            aid = int(parts[0])
            addtype = int(parts[ABILITY_ADDTYPE_COL])
        except ValueError:
            continue
        if not addtype & ADDTYPE_LEARNED:
            continue
        if aid >= LEARNED_ABILITY_BITS:
            overflow.append(aid)
            continue
        out.append((aid, parts[1].strip("'")))
    if overflow:
        print(f"  WARNING: learned ability id(s) {overflow} exceed the "
              f"{LEARNED_ABILITY_BITS}-bit char_abilities blob and are omitted",
              file=sys.stderr)
    return sorted(out)


def parse_ws_unlocks(sql_text):
    """-> {weaponskillid: unlock_id} for every unlockable weapon skill.

    `unlock_id` 0 is the sentinel for "not unlockable" -- battleutils.cpp ~396
    reads `getUnlockId() == 0 || hasLearnedWeaponskill(...)` -- so a 0 is
    dropped rather than stored as bit 0, which is never a valid position.
    """
    out, bad = {}, []
    for m in RE_WS_ROW.finditer(sql_text):
        parts = [p.strip() for p in RE_SQL_SPLIT.split(m.group(1))]
        try:
            wsid = int(parts[0])
            unlock = int(parts[-1])
        except (ValueError, IndexError):
            continue
        if unlock == 0:
            continue
        if not 0 < unlock < WS_UNLOCK_BITS:
            bad.append((wsid, unlock))
            continue
        out[wsid] = unlock
    if bad:
        raise SystemExit(f"weapon skills with an unlock_id outside 1..{WS_UNLOCK_BITS - 1}: "
                         f"{bad} -- the bitset cannot hold them; investigate "
                         "before generating a table that would set wrong bits")
    dupes = [u for u in set(out.values()) if list(out.values()).count(u) > 1]
    if dupes:
        raise SystemExit(f"unlock_id(s) {sorted(dupes)} map from more than one "
                         "weapon skill -- refusing to generate an ambiguous table")
    return dict(sorted(out.items()))


def parse_enum(header_text, name):
    """-> {member: value} for `enum class <name> : ...  { ... };`."""
    m = re.search(r"enum class %s\s*:[^{]*\{(.*?)\n\};" % name, header_text, re.S)
    if not m:
        raise SystemExit(f"could not find `enum class {name}`")
    out = {k: int(v, 0) for k, v in RE_ENUM_MEMBER.findall(m.group(1))}
    if not out:
        raise SystemExit(f"`enum class {name}` parsed to zero members")
    return out


def parse_log_struct(mmo_text, name):
    """-> (total_bytes, [(member, ctype, count, offset)]) for a struct in mmo.h.

    These structures are written to the blob verbatim (charutils SaveQuestsList
    binds `PChar->m_questLog` straight through `is_blob_v`), so their in-memory
    layout IS the on-disk format. Every member here is uint16 or bool, so there
    is no padding to reason about -- asserted below rather than assumed.
    """
    m = re.search(r"struct %s\s*\{(.*?)\n\};" % name, mmo_text, re.S)
    if not m:
        raise SystemExit(f"could not find `struct {name}`")
    fields, off = [], 0
    for fm in RE_STRUCT_MEMBER.finditer(m.group(1)):
        ctype = fm.group("ctype")
        n = int(fm.group("count")) if fm.group("count") else 1
        size = MMO_SIZE[ctype]
        if off % size:
            raise SystemExit(f"{name}.{fm.group('name')} would need padding at "
                             f"offset {off}; this parser assumes none")
        fields.append((fm.group("name"), ctype, n, off))
        off += size * n
    if not fields:
        raise SystemExit(f"`struct {name}` parsed to zero members")
    return off, fields


def parse_homepoints(lua_text, zone_ids):
    """-> {index: (x, y, z, rot, zone_id, zone_name)} from homepoint.lua.

    WARNING: Every zone name must resolve. An unresolved one would silently drop a
    homepoint, and a character whose home point is missing wakes up at their
    nation start instead -- a small wrong answer that looks like a right one.
    """
    out, unresolved = {}, set()
    for m in RE_HOMEPOINT.finditer(lua_text):
        zone = m.group("zone").lower()
        if zone not in zone_ids:
            unresolved.add(m.group("zone"))
            continue
        out[int(m.group("idx"))] = (
            float(m.group("x")), float(m.group("y")), float(m.group("z")),
            int(float(m.group("rot"))), zone_ids[zone], zone)
    if unresolved:
        raise SystemExit(f"homepoint zones not in zone.yaml: {sorted(unresolved)}")
    if not out:
        raise SystemExit("homepoint.lua parsed to zero entries")
    gaps = sorted(set(range(max(out) + 1)) - set(out))
    if gaps:
        print(f"  note: homepoint indices absent from the table: {gaps}",
              file=sys.stderr)
    return dict(sorted(out.items()))


def render(entries, abilities, ws_unlocks, logs, homepoints):
    lines = [
        "# Derived from LandSandBoat (https://github.com/LandSandBoat/server),",
        "# GNU General Public License v3.0; this file is GPL-3.0 as well. See",
        "# tools/gen_ffxi_lsb_tables.py for the exact source files read.",
        '"""GENERATED -- do not edit. `python tools/gen_ffxi_lsb_tables.py`.',
        "",
        "Wire layout and char_points mapping for the FFXI currency packets,",
        "parsed straight out of LandSandBoat's own s2c builders so that neither is",
        "transcribed by hand. See the generator's docstring for why.",
        "",
        "Each PACKETS entry:",
        "  size    total PacketData bytes, EXCLUDING the 4-byte GP_SERV_HEADER",
        "  fields  ordered [(name, kind, offset, ctype, extra)] where extra is the",
        "          array length for 'array' and (shift, bits) for 'bits'",
        "  columns {field: char_points column}",
        "  computed {field: the C++ expression} -- NOT column-backed, never imported",
        '"""',
        "",
        "PACKETS = {",
    ]
    for pid, cls, entry in entries:
        lines.append(f'    "{pid}": {{')
        lines.append(f'        "class": "{cls}",')
        lines.append(f'        "size": {entry["size"]},')
        lines.append('        "fields": [')
        for f in entry["fields"]:
            if f["kind"] == "bits":
                extra = f'({f["shift"]}, {f["bits"]})'
            elif f["kind"] == "array":
                extra = str(f["count"])
            else:
                extra = "None"
            unit = f["unit_size"] if f["kind"] == "bits" else f["size"]
            lines.append(f'            ("{f["name"]}", "{f["kind"]}", '
                         f'{f["offset"]}, "{f["ctype"]}", {extra}, {unit}),')
        lines.append("        ],")
        lines.append('        "columns": {')
        for field, (col, _ct) in entry["columns"].items():
            lines.append(f'            "{field}": "{col}",')
        lines.append("        },")
        lines.append('        "computed": {')
        for field, rhs in entry["computed"].items():
            lines.append(f'            "{field}": {rhs!r},')
        lines.append("        },")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("# Abilities LSB gates on a `learned` bit (addType & ADDTYPE_LEARNED)")
    lines.append("# in char_abilities. Everything else is granted by job and level, so a")
    lines.append("# bit set for it is inert -- these are the only ids worth importing.")
    lines.append("LEARNED_ABILITIES = {")
    for aid, nm in abilities:
        lines.append(f'    {aid}: "{nm}",')
    lines.append("}")
    lines.append("")
    lines.append("# weapon skill id -> wsUnlockId, the BIT POSITION in chars.weaponskills")
    lines.append("# (xi::bitset<64>). These are two different id spaces: Decimation is")
    lines.append("# weapon skill 72 and unlock id 5. Only unlockable weapon skills appear;")
    lines.append("# unlock_id 0 is LSB's sentinel for 'not unlockable' and bit 0 is unused.")
    lines.append("WS_UNLOCKS = {")
    for wsid, unlock in ws_unlocks.items():
        lines.append(f"    {wsid}: {unlock},")
    lines.append("}")
    lines.append("")
    lines.append("# 0x056 quest/mission log: the enums that say which block a `Port` is,")
    lines.append("# and the byte layout of the structures chars.quests / .missions /")
    lines.append("# .assault / .campaign hold. The PACKING is code, not data, and lives")
    lines.append("# in ffxi_import_core -- these are only the numbers it needs.")
    for k in ("QuestLog", "QuestOffer", "QuestComplete",
              "MissionLog", "MissionComplete"):
        lines.append(f"{camel_to_upper(k)} = {{")
        for nm, v in logs["enums"][k].items():
            lines.append(f'    "{nm}": {v},')
        lines.append("}")
        lines.append("")
    lines.append("# struct name -> (size_in_bytes, [(member, ctype, count, offset)])")
    lines.append("LOG_STRUCTS = {")
    for nm, (size, fields) in logs["structs"].items():
        lines.append(f'    "{nm}": ({size}, [')
        for f in fields:
            lines.append(f'        ("{f[0]}", "{f[1]}", {f[2]}, {f[3]}),')
        lines.append("    ]),")
    lines.append("}")
    lines.append("")
    lines.append("# how many of each structure the corresponding chars blob holds")
    lines.append("LOG_COUNTS = {")
    for nm, v in logs["counts"].items():
        lines.append(f'    "{nm}": {v},')
    lines.append("}")
    lines.append("")
    lines.append("# The client's homepoint INDEX -> where LSB puts you when you go home.")
    lines.append("# index: (x, y, z, rot, zone_id, zone_name), from")
    lines.append("# scripts/globals/homepoint.lua with xi.zone.* resolved via zone.yaml.")
    lines.append("HOMEPOINTS = {")
    for idx, (x, y, z, rot, zid, zname) in homepoints.items():
        lines.append(f'    {idx}: ({x!r}, {y!r}, {z!r}, {rot}, {zid}, "{zname}"),')
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def camel_to_upper(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def build(lsb_root):
    entries = []
    for pid, cls, stem in PACKETS:
        base = os.path.join(lsb_root, "src", "map", "packets", "s2c", stem)
        with open(base + ".h", encoding="utf-8") as fh:
            header = fh.read()
        with open(base + ".cpp", encoding="utf-8") as fh:
            cpp = fh.read()
        fields = parse_struct(header)
        placed, total = layout(fields)
        cols, computed = parse_mapping(cpp)

        names = {f["name"] for f in placed}
        unknown = set(cols) | set(computed) - names
        if unknown - names:
            raise SystemExit(f"{pid}: .cpp assigns fields absent from the struct: "
                             f"{sorted(unknown - names)}")
        entries.append((pid, cls, {"size": total, "fields": placed,
                                   "columns": cols, "computed": computed}))
        print(f"{pid}: {len(placed)} fields, {total} bytes, "
              f"{len(cols)} column-backed, {len(computed)} computed",
              file=sys.stderr)
    with open(os.path.join(lsb_root, "sql", "abilities.sql"),
              encoding="utf-8", errors="replace") as fh:
        abilities = parse_learned_abilities(fh.read())
    print(f"learned abilities: {len(abilities)} "
          f"(ids {abilities[0][0]}..{abilities[-1][0]})" if abilities
          else "learned abilities: NONE FOUND", file=sys.stderr)
    if not abilities:
        raise SystemExit("no ADDTYPE_LEARNED abilities parsed -- refusing to "
                         "write a table that would silently import nothing")

    with open(os.path.join(lsb_root, "sql", "weapon_skills.sql"),
              encoding="utf-8", errors="replace") as fh:
        ws_unlocks = parse_ws_unlocks(fh.read())
    print(f"weapon skill unlocks: {len(ws_unlocks)} "
          f"(unlock ids {min(ws_unlocks.values())}..{max(ws_unlocks.values())})",
          file=sys.stderr)
    if not ws_unlocks:
        raise SystemExit("no unlockable weapon skills parsed -- refusing to "
                         "write a table that would silently import nothing")
    src = os.path.join(lsb_root, "src")
    with open(os.path.join(src, "map", "enums", "quest_log.h"),
              encoding="utf-8-sig") as fh:
        quest_h = fh.read()
    with open(os.path.join(src, "map", "enums", "mission_log.h"),
              encoding="utf-8-sig") as fh:
        mission_h = fh.read()
    with open(os.path.join(src, "common", "mmo.h"), encoding="utf-8-sig") as fh:
        mmo_h = fh.read()
    with open(os.path.join(src, "map", "entities", "char_entity.h"),
              encoding="utf-8-sig") as fh:
        char_h = fh.read()

    enums = {
        "QuestLog": parse_enum(quest_h, "QuestLog"),
        "QuestOffer": parse_enum(quest_h, "QuestOffer"),
        "QuestComplete": parse_enum(quest_h, "QuestComplete"),
        "MissionLog": parse_enum(mission_h, "MissionLog"),
        "MissionComplete": parse_enum(mission_h, "MissionComplete"),
    }
    # An offer port and a complete port must exist for every quest area, or a
    # silently-unhandled area would import as "no quests there".
    missing = set(enums["QuestLog"]) - set(enums["QuestOffer"])
    missing |= set(enums["QuestLog"]) - set(enums["QuestComplete"])
    if missing:
        raise SystemExit(f"quest areas with no Port: {sorted(missing)}")

    structs = {n: parse_log_struct(mmo_h, n) for n in
               ("questlog_t", "missionlog_t", "assaultlog_t", "campaignlog_t")}
    counts = {}
    for macro, struct in (("MAX_QUESTAREA", "questlog_t"),
                          ("MAX_MISSIONAREA", "missionlog_t")):
        m = re.search(r"#define\s+%s\s+(\d+)" % macro, char_h)
        if not m:
            raise SystemExit(f"could not find #define {macro}")
        counts[struct] = int(m.group(1))
    counts["assaultlog_t"] = 1
    counts["campaignlog_t"] = 1

    for nm, (size, _f) in structs.items():
        print(f"{nm}: {size} bytes x{counts[nm]} = {size * counts[nm]}",
              file=sys.stderr)
    print(f"quest ports: {len(enums['QuestOffer'])} offer / "
          f"{len(enums['QuestComplete'])} complete; "
          f"mission complete ports: {len(enums['MissionComplete'])}",
          file=sys.stderr)

    logs = {"enums": enums, "structs": structs, "counts": counts}

    with open(os.path.join(lsb_root, "data", "enums", "zone.yaml"),
              encoding="utf-8") as fh:
        ztext = fh.read()
    zbody = ztext.split("values:", 1)[1] if "values:" in ztext else ""
    zone_ids = {k: int(v) for k, v in RE_YAML_VALUE.findall(zbody)}
    if not zone_ids:
        raise SystemExit("zone.yaml parsed to zero zones")
    with open(os.path.join(lsb_root, "scripts", "globals", "homepoint.lua"),
              encoding="utf-8") as fh:
        homepoints = parse_homepoints(fh.read(), zone_ids)
    print(f"home points: {len(homepoints)} (indices {min(homepoints)}.."
          f"{max(homepoints)}) across {len(zone_ids)} known zones", file=sys.stderr)

    return entries, abilities, ws_unlocks, logs, homepoints


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--lsb", default=os.path.join(here, os.pardir, "lsb-server"),
                    help="a LandSandBoat checkout at the pinned revision")
    ap.add_argument("--out", default=os.path.join(here, os.pardir, "lsb",
                                                  "ffxi_lsb_tables.py"))
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed file is stale")
    args = ap.parse_args()

    text = render(*build(args.lsb))
    if args.check:
        with open(args.out, encoding="utf-8") as fh:
            if fh.read() != text:
                raise SystemExit(f"STALE: {args.out} differs from LSB source -- "
                                 "re-run without --check")
        print("up to date", file=sys.stderr)
        return
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
