"""Where is the OpenLobby core? Shared by the suites that need its modules.

Some suites in this directory exercise the core stack's own code (accounts.py,
responders.py) or read its compose files. Those live in the OpenLobby
repository, not here, so each such suite asks this module and SKIPS cleanly
when no checkout is reachable, instead of failing on an ImportError.

Lookup order:
  1. OPENLOBBY_SERVICES  -- the services/ directory itself (modules only)
  2. OPENLOBBY_DIR       -- the repository root
  3. ../openlobby        -- a checkout beside this repository

A skip is exit status 77, which tools/bridge_run_all.py reports as `skip`.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, os.pardir))
SKIP_EXIT = 77


def root_dir():
    """The OpenLobby repository root, or None."""
    env = os.environ.get("OPENLOBBY_DIR", "").strip()
    cands = [env] if env else [os.path.join(ROOT, os.pardir, "openlobby")]
    for c in cands:
        if c and os.path.isfile(os.path.join(c, "services", "accounts.py")):
            return os.path.normpath(c)
    return None


def services_dir():
    """The OpenLobby services/ directory, or None."""
    env = os.environ.get("OPENLOBBY_SERVICES", "").strip()
    if env:
        return env if os.path.isfile(os.path.join(env, "accounts.py")) else None
    r = root_dir()
    return os.path.join(r, "services") if r else None


def skip(what, needs):
    print(f"SKIP: {what} needs {needs}. Set OPENLOBBY_DIR to a checkout of the "
          f"OpenLobby core, or place one beside this repository as ../openlobby.")
    sys.exit(SKIP_EXIT)


def require_services(what):
    """Put the core's services/ on sys.path, or skip the calling suite."""
    d = services_dir()
    if d is None:
        skip(what, "the OpenLobby core's services/ (accounts.py, responders.py)")
    sys.path.insert(0, d)
    return d


def require_root(what):
    """The core's repository root, or skip the calling suite."""
    r = root_dir()
    if r is None:
        skip(what, "an OpenLobby checkout (its docker-compose.yml and services/)")
    return r
