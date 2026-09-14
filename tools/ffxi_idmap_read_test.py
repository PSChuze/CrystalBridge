"""responders._ffxi_world_fields: a torn read must NOT become a sticky POL-0001.

    python tools/ffxi_idmap_read_test.py

WHY (2026-09-02). The FFXI id map is written by the bridge in one container and
read by responders' `_ffxi_world_fields()` in another, which caches it keyed by
the file's mtime. Two faults made an intermittent write race into a durable
POL-0001:

  * The bridge USED to truncate the file in place (open "w" then json.dump), so
    a read landing mid-write parsed `{}` -- world_field 0, which is the
    POL-0001 condition. (Fixed on the write side too: the bridge now does
    tmp + os.replace, like its acctmap sibling.)
  * On any parse failure `_ffxi_world_fields` stored `{}` UNDER THE OBSERVED
    MTIME and returned it. If no later write moved the mtime, every subsequent
    `1:3` was served the empty map -- the failure went sticky, not one-shot.

The fix keeps the last good map and retries on the next fetch instead of
caching the empty result. It also now derives a world field for LEGACY FLAT
entries `{charid: content_id}` (a restored .bak-*), which it used to skip --
serving world field 0, i.e. POL-0001, for a map the bridge considered valid.

This test drives the real function through those three cases. No network.
Needs the OpenLobby core's `services/responders.py`: set OPENLOBBY_DIR to a
checkout of it, or keep one beside this repository as ../openlobby. Without
it the suite SKIPS (exit 77) rather than failing.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from openlobby_paths import require_services                      # noqa: E402
require_services("ffxi_idmap_read_test")

import responders as R                                             # noqa: E402

fails = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  --  {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def _reset_cache():
    R._ffxi_world_cache["mtime"] = None
    R._ffxi_world_cache["map"] = {}
    R._ffxi_missing_warned.clear()


def main():
    tmp = tempfile.mkdtemp(prefix="ffxi-idmap-read-")
    path = os.path.join(tmp, "ffxi_idmap.json")
    R._FFXI_IDMAP = path

    # 1) a good dict map with an explicit world_field is served verbatim.
    _reset_cache()
    with open(path, "w") as f:
        json.dump({"17825793": {"content_id": 30000045, "name": "Cid",
                                 "world_field": 0x11223344}}, f)
    m = R._ffxi_world_fields()
    check("a dict entry's world_field is served",
          m.get(30000045) == 0x11223344, str(m))
    good = dict(m)

    # 2) a TORN read (invalid JSON) must keep the last good map, not cache {}.
    #    Force a new mtime so the cache does not short-circuit the read.
    os.utime(path, (0, 0))
    with open(path, "w") as f:
        f.write('{"17825793": {"content_id": 3000')      # truncated: invalid
    m = R._ffxi_world_fields()
    check("a torn read keeps the previous map (no POL-0001)",
          m == good and m.get(30000045) == 0x11223344, str(m))

    # 3) ...and it is NOT cached: once the file is whole again, the new map is
    #    served on the very next fetch (the failure was one-shot, not sticky).
    with open(path, "w") as f:
        json.dump({"17825793": {"content_id": 30000045, "world_field": 0x55},
                   "17825794": {"content_id": 30000046, "world_field": 0x66}}, f)
    m = R._ffxi_world_fields()
    check("the recovered map is served on the next fetch",
          m.get(30000045) == 0x55 and m.get(30000046) == 0x66, str(m))

    # 4) a LEGACY FLAT entry {charid: content_id} gets a DERIVED field, not 0.
    _reset_cache()
    with open(path, "w") as f:
        json.dump({"17825793": 30000045}, f)             # old flat format
    m = R._ffxi_world_fields()
    check("a legacy flat entry yields a non-zero derived field (not POL-0001)",
          m.get(30000045, 0) != 0, str(m))

    print(f"\n{'ffxi_idmap_read: OK' if not fails else 'FAILURES: ' + ', '.join(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
