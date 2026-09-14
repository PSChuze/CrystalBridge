"""Do the FFXI id map's WRITER and READER name the same file?

    python tools/ffxi_idmap_check.py

No containers, no network: it reads this repository's docker-compose.yml (the
WRITER: the `bridge` service's FFXI_IDMAP_FILE) and the OpenLobby core's
docker-compose.yml plus its source defaults (the READER: the `login` service's
POL_FFXI_IDMAP, falling back to services/srvcore.py's RELEASE_DEFAULTS and
then to the literal in services/responders.py, which is the order the core
applies them in), resolves each path through that service's own volume mounts
to a Docker volume plus a path inside it, and compares them. It also checks
that no core service publishes host port 54002, which LSB's search server
needs.

WHY THIS EXISTS -- a bug that ran on a live deployment for days with no symptom
anybody could see (found 2026-08-23):

  * The **bridge** persists `{charid: {content_id, world_field}}` to
    `FFXI_IDMAP_FILE`, on the shared data volume as `/data/ffxi_idmap.json`.
  * The **lobby** reads it back through `POL_FFXI_IDMAP`, whose built-in
    default in `responders.py` was `/lsb/ffxi_idmap.json`. Nothing set the
    variable, so the lobby used that default -- a different file, which did
    not exist.
  * `_ffxi_world_fields` turned the missing file into `{}` and returned it
    WITHOUT LOGGING, on the perfectly good reasoning that a stack with no
    bridge legitimately has no map. So a misconfigured stack looked exactly
    like an unconfigured one.

The consequence is not cosmetic. The lobby's `1:3` FFXI record carries the world
identity dword at record `+0x0C`, which comes from this map; FFXI's world lookup
(`FFXiMain FUN_100FFE00`, reached from char-select sub-state 14) will not open
the world socket unless it matches, and on no match writes -1 and aborts --
**POL-0001**. An empty map means it can never match.

The core now defaults the reader to the shared volume path, so a plain
deployment agrees by design. This check crosses the two things a plain
env-var diff cannot -- a value's default in the code, and where the other
service actually puts the file -- so a re-pinned default, a renamed volume
or a stray environment override is caught before a player finds it.

The OpenLobby checkout is found through OPENLOBBY_DIR, or as ../openlobby
beside this repository; without one the check SKIPS (exit 77).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, os.pardir))
sys.path.insert(0, HERE)
from openlobby_paths import require_root, skip                      # noqa: E402

READER_SERVICE = "login"
WRITER_SERVICE = "bridge"
SEARCH_PORT = "54002"

FAILED = []


def check(cond, what):
    print(f"  {'OK  ' if cond else 'FAIL'} {what}")
    if not cond:
        FAILED.append(what)
    return cond


def yaml_module():
    try:
        import yaml
    except ImportError:
        skip("ffxi_idmap_check", "PyYAML (pip install pyyaml)")
    return yaml


def load(yaml, path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def read_source(root, *parts):
    with open(os.path.join(root, *parts), encoding="utf-8") as fh:
        return fh.read()


def responders_default(root):
    """`POL_FFXI_IDMAP`'s literal fallback in responders.py."""
    m = re.search(r'_FFXI_IDMAP\s*=\s*os\.environ\.get\(\s*"POL_FFXI_IDMAP"\s*,\s*'
                  r'"([^"]+)"\s*\)', read_source(root, "services", "responders.py"))
    return m.group(1) if m else None


def release_default(root):
    """`POL_FFXI_IDMAP` in srvcore.py's RELEASE_DEFAULTS, applied with
    os.environ.setdefault before responders reads the variable."""
    src = read_source(root, "services", "srvcore.py")
    m = re.search(r"RELEASE_DEFAULTS\s*=\s*\{(.*?)\n\}", src, re.S)
    if not m:
        return None
    v = re.search(r'"POL_FFXI_IDMAP"\s*:\s*"([^"]+)"', m.group(1))
    return v.group(1) if v else None


def service(doc, name):
    return (doc.get("services") or {}).get(name) or {}


def env_of(svc):
    env = svc.get("environment")
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    if isinstance(env, list):                       # "KEY=value" form
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return {}


def volume_name(doc, key, project):
    """The Docker volume a compose volume key maps to."""
    spec = (doc.get("volumes") or {}).get(key) or {}
    if isinstance(spec, dict) and spec.get("name"):
        return spec["name"]
    return f"{project}_{key}"


def mounts_of(svc, doc, project):
    """`[(volume-or-host, container_path)]` for the service's mounts."""
    out = []
    for v in svc.get("volumes") or []:
        if not isinstance(v, str):
            continue
        parts = v.split(":")
        if len(parts) < 2:
            continue
        src, dst = parts[0], parts[1]
        if src.startswith((".", "/", "$")):
            src = "bind:" + re.sub(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}", "", src).strip("./")
        else:
            src = "volume:" + volume_name(doc, src, project)
        out.append((src, dst))
    return out


def resolve(container_path, mounts):
    """`volume:<name>/<rest>` for a path inside a container, or None.
    Longest matching mount wins, the way the kernel resolves them."""
    best = None
    for src, dst in mounts:
        d = dst.rstrip("/")
        if container_path == d or container_path.startswith(d + "/"):
            if best is None or len(d) > len(best[1].rstrip("/")):
                best = (src, dst)
    if best is None:
        return None
    src, dst = best
    rest = container_path[len(dst.rstrip("/")):].lstrip("/")
    return "/".join(p for p in (src, rest) if p)


def published_host_ports(svc):
    out = set()
    for p in svc.get("ports") or []:
        if isinstance(p, dict):
            out.add(str(p.get("published", "")))
            continue
        s = str(p).split("/")[0]                # strip /udp
        parts = s.split(":")
        # "host:container", "ip:host:container", or just "container"
        out.add(parts[-2] if len(parts) >= 2 else parts[-1])
    return out


def main():
    print(__doc__.splitlines()[0])
    print()
    yaml = yaml_module()
    core = require_root("ffxi_idmap_check")

    # --- the writer: this repository ------------------------------------
    here_doc = load(yaml, os.path.join(ROOT, "docker-compose.yml"))
    here_project = here_doc.get("name") or os.path.basename(ROOT)
    writer = service(here_doc, WRITER_SERVICE)
    if not check(bool(writer), f"a {WRITER_SERVICE!r} service exists in docker-compose.yml"):
        return 1
    w_env = env_of(writer).get("FFXI_IDMAP_FILE")
    w_host = resolve(w_env or "", mounts_of(writer, here_doc, here_project))
    print(f"  writer {WRITER_SERVICE}: FFXI_IDMAP_FILE={w_env} -> {w_host}")
    check(bool(w_env), "the bridge sets FFXI_IDMAP_FILE explicitly")
    check(w_host is not None,
          f"the writer's path {w_env} is inside a mount of {WRITER_SERVICE}")
    check(w_host is not None and w_host.startswith("volume:"),
          "the writer's file is on a named volume (not a bind mount)")

    # --- the reader: the OpenLobby core ------------------------------------
    print(f"  reader: {core}")
    core_doc = load(yaml, os.path.join(core, "docker-compose.yml"))
    core_project = core_doc.get("name") or os.path.basename(core)
    reader = service(core_doc, READER_SERVICE)
    if not check(bool(reader), f"a {READER_SERVICE!r} service exists in the core compose"):
        return 1
    r_env = env_of(reader).get("POL_FFXI_IDMAP")
    r_rel = release_default(core)
    r_lit = responders_default(core)
    print(f"  reader {READER_SERVICE}: compose env {r_env!r}, srvcore RELEASE_DEFAULTS "
          f"{r_rel!r}, responders.py literal {r_lit!r}")
    if not check(r_lit is not None,
                 "the literal default is still findable in responders.py (this check reads it)"):
        return 1
    # The ladder the core applies: an env var set on the service wins, else the
    # release default srvcore puts into os.environ at import, else the literal.
    r_path, r_from = ((r_env, "the compose environment") if r_env else
                      (r_rel, "srvcore RELEASE_DEFAULTS") if r_rel else
                      (r_lit, "the responders.py literal"))
    r_host = resolve(r_path, mounts_of(reader, core_doc, core_project))
    print(f"  reader {READER_SERVICE}: POL_FFXI_IDMAP={r_path} (from {r_from}) -> {r_host}")
    # PINNED IN THE RELEASE, NOT LEFT TO A SOURCE LITERAL. The literal being
    # right on one stack and wrong on another is what hid this for days.
    check(bool(r_env or r_rel),
          "POL_FFXI_IDMAP is pinned (compose env or RELEASE_DEFAULTS), not left "
          "to the responders.py literal")
    check(r_host is not None,
          f"the reader's path {r_path} is inside a mount of {READER_SERVICE} "
          "(otherwise it can only ever read nothing)")
    check(r_host is not None and r_host == w_host,
          f"reader and writer resolve to the SAME volume file ({r_host!r} vs {w_host!r})")

    # --- the port the search server needs ---------------------------------
    holders = sorted(name for name, svc in (core_doc.get("services") or {}).items()
                     if SEARCH_PORT in published_host_ports(svc or {}))
    check(not holders,
          f"no core service publishes host port {SEARCH_PORT} (LSB search needs it)"
          + (f"; held by {holders}" if holders else ""))
    print()

    if FAILED:
        print(f"RESULT: {len(FAILED)} FAILURE(S)")
        for f in FAILED:
            print(f"  - {f}")
        print()
        print("A mismatch here means the lobby serves world field 0 for every FFXI")
        print("character and FFXI refuses the world connect (POL-0001).")
        return 1
    print("RESULT: the FFXI id map's writer and reader agree, and 54002 is free")
    return 0


if __name__ == "__main__":
    sys.exit(main())
