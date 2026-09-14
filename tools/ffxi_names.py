#!/usr/bin/env python3
"""FFXI character name <-> PlayOnline handle mapping.

WHY THIS EXISTS
---------------
PlayOnline identifies people by HANDLE. FINAL FANTASY XI identifies them by
CHARACTER NAME. Retail could join the two because SE ran both sides; we cannot,
because the two halves of the chain live in different databases and neither knows
the other exists:

    FFXI character name   ->  Content ID   ->  handle
    \\__ LandSandBoat (xidb) __/                \\__ accounts.db __/
                          \\____ nobody ____/

`accounts.db` knows `handle_content(handle_id, content_code, content_id)` -- which
handle owns Content ID `1000000001` -- but has never been told that the FFXI
character on it is called "Alice". LandSandBoat knows the character but nothing
about PlayOnline. **The bridge is the only place both are ever seen together**, so
it records the pairing in its id map (`ffxi_idmap.json`, `FFXI_IDMAP_FILE`) as
it watches the lobby:

    {"1": {"content_id": 1000000001, "name": "Alice", "seen": "..."}}

This tool imports that into `accounts.db` as `content_character`, which is the
POL-side answer to "who is Alice?" -- and, read the other way, "what is this
handle's FFXI character called?".

DELIBERATELY STANDALONE. It creates its own table and does not touch
`accounts.py` or `responders.py`, so it can land while other work is in flight in
those files. The serving side (member search, friend-add resolution, the Content
ID list UI) is a separate, later step -- this only establishes the data.

USAGE
    python tools/ffxi_names.py import [--map /data/ffxi_idmap.json] [--db /data/accounts.db]
    python tools/ffxi_names.py list
    python tools/ffxi_names.py lookup <character-name>
    python tools/ffxi_names.py whois <handle-name>

`import` is idempotent: re-running it updates names and timestamps in place.

The defaults are the paths inside the bridge container (POL_ACCOUNTS_DB and
FFXI_IDMAP_FILE override them), so the usual invocation is:

    docker compose run --rm --entrypoint python \
        -v "$PWD/tools:/app/tools:ro" bridge tools/ffxi_names.py list
"""
import argparse
import json
import os
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.environ.get("POL_ACCOUNTS_DB", "/data/accounts.db")
DEFAULT_MAP = os.environ.get("FFXI_IDMAP_FILE", "/data/ffxi_idmap.json")

#: One row per (world, character). `content_id` is the join back to
#: `handle_content.content_id` -- TEXT there, so TEXT here too; a mismatched type
#: would make every join silently miss.
#:
#: `world_charid` is LandSandBoat's `chars.charid`, kept because it is the key the
#: world server actually uses and the only stable id if a character is renamed.
SCHEMA = """
CREATE TABLE IF NOT EXISTS content_character (
    content_id     TEXT NOT NULL,
    content_code   INTEGER NOT NULL DEFAULT 1,
    world_charid   INTEGER,
    character_name TEXT NOT NULL,
    world_name     TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    PRIMARY KEY (content_id, content_code)
);
CREATE INDEX IF NOT EXISTS content_character_by_name
    ON content_character (character_name);
"""


def connect(path):
    if not os.path.exists(path):
        sys.exit(f"no such database: {path}")
    # A normal handle: accounts.db is WAL, and `mode=ro` cannot create the -shm
    # index a WAL reader needs. Writers here are deliberate and small.
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def load_map(path):
    """Read the bridge's map, accepting both on-disk shapes.

    The original was a flat `{"<charid>": <ContentID>}` with no name in it; those
    entries are skipped rather than imported as blanks, so an old file produces
    "nothing to import" instead of a table full of empty names.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"no bridge map at {path} -- has the bridge seen a character list yet?")
    out = []
    for charid, v in raw.items():
        if not isinstance(v, dict):
            continue                    # old flat entry: Content ID only, no name
        name = (v.get("name") or "").strip()
        if not name:
            continue
        out.append((str(v["content_id"]), int(charid), name, v.get("world") or None))
    return out


def cmd_import(args):
    entries = load_map(args.map)
    if not entries:
        print(f"{args.map}: no named characters yet -- nothing to import.")
        print("The bridge fills the name in when it relays a character list or a")
        print("world handoff, so launch FFXI once and re-run this.")
        return 0
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = connect(args.db)
    added = updated = 0
    try:
        for content_id, charid, name, world in entries:
            row = conn.execute(
                "SELECT character_name FROM content_character "
                "WHERE content_id = ? AND content_code = 1", (content_id,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO content_character (content_id, content_code, "
                    "world_charid, character_name, world_name, first_seen, last_seen) "
                    "VALUES (?, 1, ?, ?, ?, ?, ?)",
                    (content_id, charid, name, world, now, now))
                added += 1
            else:
                conn.execute(
                    "UPDATE content_character SET world_charid = ?, character_name = ?, "
                    "world_name = COALESCE(?, world_name), last_seen = ? "
                    "WHERE content_id = ? AND content_code = 1",
                    (charid, name, world, now, content_id))
                if row["character_name"] != name:
                    print(f"  renamed: {row['character_name']!r} -> {name!r} "
                          f"on Content ID {content_id}")
                updated += 1
        conn.commit()
    finally:
        conn.close()
    print(f"imported {added} new, refreshed {updated} (from {args.map})")
    return 0


def _joined(conn, where="", params=()):
    """content_character joined through handle_content to the owning handle.

    LEFT JOIN on purpose: a character whose Content ID is not linked to any handle
    is a real and interesting state (the link was deleted, or the content belongs
    to another member), and an INNER JOIN would hide it.
    """
    return conn.execute(
        "SELECT cc.character_name, cc.content_id, cc.world_charid, "
        "       h.handle_name, h.id AS handle_id "
        "FROM content_character cc "
        "LEFT JOIN handle_content hc "
        "       ON hc.content_id = cc.content_id AND hc.content_code = cc.content_code "
        "      AND hc.status = 'active' "
        "LEFT JOIN handle h ON h.id = hc.handle_id "
        + where + " ORDER BY cc.character_name", params).fetchall()


def _print(rows):
    if not rows:
        print("(none)")
        return
    print(f"{'character':16} {'content id':12} {'charid':>6}  handle")
    for r in rows:
        handle = r["handle_name"] or "-- not linked to any handle --"
        print(f"{r['character_name']:16} {r['content_id']:12} "
              f"{r['world_charid'] if r['world_charid'] is not None else '?':>6}  {handle}")


def cmd_list(args):
    conn = connect(args.db)
    try:
        _print(_joined(conn))
    finally:
        conn.close()
    return 0


def cmd_lookup(args):
    conn = connect(args.db)
    try:
        # Case-insensitive: FFXI capitalises names, POL does not care, and a
        # lookup that only matched exact case would fail on user input.
        _print(_joined(conn, "WHERE UPPER(cc.character_name) = UPPER(?)", (args.name,)))
    finally:
        conn.close()
    return 0


def cmd_whois(args):
    conn = connect(args.db)
    try:
        _print(_joined(conn, "WHERE UPPER(h.handle_name) = UPPER(?)", (args.handle,)))
    finally:
        conn.close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import", help="import the bridge's map into accounts.db")
    p.add_argument("--map", default=DEFAULT_MAP)
    p.set_defaults(fn=cmd_import)
    sub.add_parser("list", help="every known character and its handle").set_defaults(fn=cmd_list)
    p = sub.add_parser("lookup", help="character name -> handle")
    p.add_argument("name")
    p.set_defaults(fn=cmd_lookup)
    p = sub.add_parser("whois", help="handle -> character name")
    p.add_argument("handle")
    p.set_defaults(fn=cmd_whois)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
