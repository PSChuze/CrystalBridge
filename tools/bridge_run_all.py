#!/usr/bin/env python3
"""Run the offline selftest suite: every tools/ffxi_*_test.py and
tools/ffxi_*_check.py, plus the selftest embedded in ffxi_provision.py. No
Docker, no LSB, no client needed.

Some suites exercise the OpenLobby core's own modules (accounts.py,
responders.py) or read its compose files. They run when a checkout of the core
is reachable (OPENLOBBY_DIR, or ../openlobby beside this repository) and SKIP
otherwise: exit status 77, reported as `skip`, never as a failure. The C++
harness under tools/ffxi_bfdiff needs LandSandBoat's sources and is not run.

  python tools/bridge_run_all.py            # everything
  python tools/bridge_run_all.py -k idmap   # only suites whose name contains
  python tools/bridge_run_all.py -v         # stream each suite's own output
"""
import argparse
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 300
SKIP_EXIT = 77


def suites():
    out = [("provision", [sys.executable, "ffxi_provision.py", "selftest"])]
    paths = (glob.glob(os.path.join(HERE, "ffxi_*_test.py"))
             + glob.glob(os.path.join(HERE, "ffxi_*_check.py")))
    for p in sorted(paths):
        name = os.path.basename(p)[len("ffxi_"):-len(".py")]
        out.append((name, [sys.executable, p]))
    return out


def run(cmd, verbose):
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    try:
        r = subprocess.run(cmd, cwd=HERE, env=env, timeout=TIMEOUT,
                           stdout=None if verbose else subprocess.PIPE,
                           stderr=None if verbose else subprocess.STDOUT)
        out = "" if verbose else r.stdout.decode("utf-8", "replace")
        return r.returncode, out
    except subprocess.TimeoutExpired as exc:
        out = (exc.output or b"").decode("utf-8", "replace") if not verbose else ""
        return -1, out + f"\n*** TIMED OUT after {TIMEOUT}s"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-k", action="append", default=[],
                    help="only suites whose name contains this substring")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="stream each suite's output instead of capturing it")
    ap.add_argument("--list", action="store_true", help="list suite names and exit")
    args = ap.parse_args()
    todo = [s for s in suites()
            if not args.k or any(k in s[0] for k in args.k)]
    if args.list:
        for name, _cmd in todo:
            print(name)
        return 0
    if not todo:
        print(f"no suite matches {args.k!r}; --list shows them all")
        return 2

    width = max(len(s[0]) for s in todo)
    failed, skipped = [], []
    print(f"running {len(todo)} suite(s)\n")
    for name, cmd in todo:
        t0 = time.time()
        print(f"  {name:<{width}}  ... ", end="", flush=True)
        code, out = run(cmd, args.verbose)
        if code == 0:
            verdict = "ok  "
        elif code == SKIP_EXIT:
            verdict = "skip"
            skipped.append(name)
        else:
            verdict = "FAIL"
            failed.append((name, out))
        print(f"{verdict}  {time.time() - t0:5.1f}s")
        if code == SKIP_EXIT and not args.verbose:
            why = [l for l in out.splitlines() if l.startswith("SKIP:")]
            print(f"  {'':<{width}}       {why[0] if why else '(no reason given)'}")

    print()
    for name, out in failed:
        print("=" * 72)
        print(f"FAILED: {name}")
        print("=" * 72)
        tail = out.rstrip()[-4000:]
        try:
            print(tail)
        except UnicodeEncodeError:
            print(tail.encode("ascii", "replace").decode("ascii"))
        print()
    n = len(todo)
    passed = n - len(failed) - len(skipped)
    summary = f"{passed} passed, {len(skipped)} skipped, {len(failed)} failed (of {n})"
    if skipped:
        summary += f"; skipped: {', '.join(skipped)}"
    if failed:
        summary += f"; FAILED: {', '.join(nm for nm, _ in failed)}"
    print(summary)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
