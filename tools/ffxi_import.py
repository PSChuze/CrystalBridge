#!/usr/bin/env python3
"""Import a polexport character dump into the LSB world.

The client-side half is a `polexport` addon (an Ashita addon that walks the
character and writes a `polexport-1` JSON dump; it is not part of this
repository, and lsb/ffxi_import_core.py documents the dump format it reads):
a player runs `/polexport` on the character they want to bring over -- retail
or any other server -- and hands the resulting JSON to the admin. (A client-side
helper can instead POST the same JSON to the bridge's import endpoint; this
tool is the admin, reviewable path, and both share lsb/ffxi_import_core.py.)

    1. python tools/ffxi_import.py sql dump.json --member 5 > import.sql
       # review it, then apply against the LSB database:
       docker compose exec -T db \
           mariadb -u"$LSB_DB_USER" -p"$LSB_DB_PASSWORD" "$LSB_DB_NAME" \
           < import.sql
       # the last SELECT prints the allocated charid

    2. # inside the bridge container, which mounts both state files at /data
       # (the tools are not baked into the image, so mount them for the call):
       docker compose run --rm --entrypoint python \
           -v "$PWD/tools:/app/tools:ro" bridge \
           tools/ffxi_import.py bind <charid> --member 5 --name <Charname>
       docker compose restart bridge
       # bind records the POL Content ID <-> LSB charid pairing in the bridge's
       # idmap (the restart makes the running bridge re-read it; do this while
       # nobody is mid-launch). The world_field half is recorded automatically
       # by the bridge the first time the player fetches their character list.

Two steps by design (same philosophy as ffxi_provision.py's rehome printing
its UPDATE): the SQL is reviewable before it touches the DB, and a typo'd
member id cannot silently gift a character to the wrong account.

PREREQUISITES
  * the member has an LSB account: `ffxi_provision.py create <member>` (the
    generated SQL references the account by its login name `pol<member>` and
    aborts visibly if it is missing);
  * the member's FFXI Content ID (content_code 1) is UNUSED -- POL issues one
    per member, so a member with a living character cannot also import one.

WHAT IS IMPORTED (v2)
  identity (name/race/face/size/nation), main+sub job, all job levels and the
  level cap they imply (genkai), gil, inventory containers incl. the 24-byte
  extra blob (augments) AND THEIR SIZES, what was equipped, combat + craft
  skills, key items, nation rank, title, unspent merits.

  Container sizes are new in v2 and are not a nicety: LSB sizes each container
  from char_storage before it loads the items and silently drops anything in a
  slot past that size, so a retail 80-slot inventory imported against the
  schema default of 30 used to lose fifty items after a "successful" import.

  Spells are new in v2 as well (polexport 0.4 sweeps the client's own spell
  list). ABSENT and EMPTY are kept apart: a dump from an exporter that could
  not read spells warns rather than reading as "knows none".

  Currencies are new too (polexport 0.5): conquest points, sparks, guild
  points, bayld, escha silt, assault points and ~190 others, captured raw from
  packets 0x113/0x118 and decoded against a table GENERATED from LSB's own
  builders (tools/gen_ffxi_lsb_tables.py -- run it after bumping the pinned
  LSB revision, or `--check` to see if it went stale).

  Abilities (polexport 0.6) means precisely the abilities LSB gates on a
  "learned" bit -- at the pinned revision, the 31 CORSAIR ROLLS. Every other
  ability is granted by job and level, so nothing else is worth storing.

  Quests and missions (polexport 0.2 captured the raw 0x056 blocks; the decoder
  landed 2026-08-26) fill the chars.quests / .missions / .assault / .campaign
  blobs. REFUSED outright when questlog.count is 0 -- the log arrives on
  ZONE-IN, and writing the empty blobs that produces would erase a real log.

  Home point (2026-08-26) resolves the client's index through LSB's own
  scripts/globals/homepoint.lua and fills chars.home_zone + home_rot + home_x/
  y/z. The resolved zone is REPORTED: the client's index numbering has not been
  measured against LSB's, and a wrong one lands the character somewhere
  plausible and wrong rather than failing.

  MOUNTS transfer as of 2026-08-26, and needed no code of their own: FFXI files
  them as key items 3072..3108 (LSB has no mounts column at all, and its 0x0AE
  mount packet is a memcpy of key item table 6). They were previously LOST, not
  absent -- chars.keyitems is eight 128-byte tables and this importer wrote a
  flat bit array, which is correct only for table 0. Key item 3072 was landing
  on key item 1536.

  Job points and teleport unlocks (polexport 0.7) come off the wire too: 0x063
  MISCDATA type 5 carries the per-job capacity/unspent/spent totals, 0x08D the
  per-category levels (accumulated -- one packet holds only 64 entries), and
  0x063 type 6 the home point / survival guide / waypoint masks.

  WARNING: Only the three teleport masks LSB actually drives are imported. Its own
  builder leaves telepoints, maws and Eschan portals commented out as
  "untested/unimplemented", so those are REPORTED and skipped rather than
  decoded from a stub.

  WARNING: Mog Locker items import into the right rows and the right size, but access
  is gated separately by the char_vars mog-locker-expiry-timestamp rental, which
  this does not mint -- so they can be invisible in game. Not a decode problem.

  NOT imported: linkshells; furnishing placement; fame (no getter, no packet
  found); the twenty EQUIPPED blue magic slots (learned BLU spells DO
  transfer -- see the note in ffxi_import_core on why the set is left alone).

HONESTY: the dump is produced by the player's own client and is trivially
forgeable. This is an honor-system import for a preservation server, not a
verified transfer.
"""
import argparse
import json
import os
import sys

# Same import dance as ffxi_provision.py: `lsb/` beside tools/ in the repo,
# /app inside the bridge image.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "lsb"))
sys.path.append("/app")
import ffxi_import_core as core  # noqa: E402


def cmd_sql(args):
    # utf-8-sig: tolerate a BOM (files that pass through Windows tooling grow one)
    with open(args.dump, "r", encoding="utf-8-sig") as fh:
        dump = json.load(fh)
    try:
        plan = core.build_statements(dump, name=args.name,
                                     skill_scale=args.skill_scale)
    except ValueError as exc:
        raise SystemExit(str(exc))
    name = plan["name"]
    login = args.lsb_login or f"pol{args.member}"

    o = []
    w = o.append
    w(f"-- polexport import: {name} -> member {args.member} (LSB account {login})")
    w(f"-- source dump: {os.path.basename(args.dump)} "
      f"exported {dump.get('exported', '?')}")
    w("-- Apply with: docker compose exec -T db \\")
    w("--   mariadb -u\"$LSB_DB_USER\" -p\"$LSB_DB_PASSWORD\" \"$LSB_DB_NAME\" < this.sql")
    w("-- Then run the `bind` step with the charid the final SELECT prints.")
    w("")
    w("START TRANSACTION;")
    w(f"SET @accid = (SELECT id FROM accounts WHERE login = {core.q(login)});")
    # A NULL @accid makes the chars INSERT fail (accid NOT NULL) and roll the
    # transaction back -- the SELECT is there so whoever applies it sees WHY.
    w("SELECT IF(@accid IS NULL,"
      f" 'ABORT: LSB account {login} missing -- ffxi_provision.py create {args.member}',"
      " CONCAT('account ok, accid=', @accid)) AS account_check;")
    w(f"SELECT IF(EXISTS(SELECT 1 FROM chars WHERE charname = {core.q(name)}),"
      f" 'ABORT: character name {name} already taken', 'name free') AS name_check;")
    # The same allocation LSB's own createCharacter performs.
    w("SET @charid = (SELECT COALESCE(MAX(charid), 0) + 1 FROM chars);")
    w("")
    for s in plan["core"]:
        w(s + ";")
    w("")
    w("COMMIT;")
    w("")
    w("-- Best-effort section: each statement stands alone; a failure here")
    w("-- leaves the committed character intact (re-run pieces by hand).")
    for s in plan["best"]:
        w(s + ";")
    w("")
    w("SELECT @charid AS imported_charid;  -- use this in the `bind` step")
    if plan["warnings"]:
        w("")
        w("-- WARNINGS -- this SQL is correct and applies cleanly; these are the")
        w("-- ways the result will NOT present in game the way the dump reads.")
        for warn in plan["warnings"]:
            w("--   * " + warn)

    for warn in plan["warnings"]:
        print(f"WARNING: {warn}", file=sys.stderr)
    print(f"{name}: {plan['n_items']} items, {plan['n_skills']} skill rows, "
          f"{plan['n_equip']} equipped, {plan['n_spells']} spells, "
          f"{plan['n_currencies']} currencies, {plan['n_abilities']} rolls, "
          f"{plan['n_ws']} ws, {plan['n_qm']} quest/mission blob(s), "
          f"{plan['n_keyitems']} key items ({plan['n_mounts']} mounts), "
          f"{plan['n_jp']} job(s) with job points, "
          f"{plan['gil']} gil; container sizes {plan['storage']}",
          file=sys.stderr)

    out = "\n".join(o) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(out)


def cmd_bind(args):
    import ffxi_bridge as B
    B.load_idmap()
    # The member's FFXI Content ID, from accounts.db (content_code 1 = FFXI).
    import sqlite3
    db = sqlite3.connect(B.ACCOUNTS_DB, timeout=5.0)
    try:
        db.execute("PRAGMA query_only = 1")
        row = db.execute(
            "SELECT hc.content_id FROM member m "
            "JOIN handle h ON h.member_id = m.id "
            "JOIN handle_content hc ON hc.handle_id = h.id AND hc.content_code = 1 "
            "WHERE m.id = ?", (args.member,)).fetchone()
    finally:
        db.close()
    if not row:
        raise SystemExit(f"member {args.member} has no FFXI Content ID in accounts.db")
    content_id = int(row[0])
    key = str(args.charid)
    for k, v in B._idmap.items():
        if v == content_id and k != key:
            raise SystemExit(
                f"Content ID {content_id} is already bound to charid {k} "
                f"({B._charnames.get(k, '?')}) -- POL issues ONE FFXI Content ID "
                "per member; delete that character first (the delete releases it).")
    if key in B._idmap and B._idmap[key] != content_id:
        raise SystemExit(f"charid {key} is already bound to Content ID {B._idmap[key]}")
    B._idmap[key] = content_id
    if args.name:
        B._charnames[key] = args.name
    B.save_idmap()
    print(f"bound charid {args.charid} ({args.name or '?'}) -> Content ID "
          f"{content_id} (member {args.member}) in {B.IDMAP_FILE}")
    print("world_field will be recorded by the bridge on the player's first "
          "character-list fetch; have them sign into POL AFTER this step.")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("sql", help="generate the reviewable import SQL")
    ps.add_argument("dump")
    ps.add_argument("--member", type=int, required=True)
    ps.add_argument("--name", help="override the character name")
    ps.add_argument("--lsb-login", help="override the LSB account login "
                                        "(default pol<member>)")
    ps.add_argument("--skill-scale", type=int, default=10)
    ps.add_argument("--out")
    ps.set_defaults(fn=cmd_sql)
    pb = sub.add_parser("bind", help="record the Content ID pairing in the "
                                     "bridge idmap (run where FFXI_IDMAP_FILE "
                                     "and POL_ACCOUNTS_DB point at the live "
                                     "files, then restart bridge)")
    pb.add_argument("charid", type=int)
    pb.add_argument("--member", type=int, required=True)
    pb.add_argument("--name", help="the character's name, for the idmap record")
    pb.set_defaults(fn=cmd_bind)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
