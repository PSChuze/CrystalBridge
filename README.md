# CrystalBridge

The bridge between the OpenLobby PlayOnline core and a LandSandBoat FINAL
FANTASY XI world server. With both running, a player signs into an unmodified
PlayOnline Viewer, presses Play on FINAL FANTASY XI, and lands in a
LandSandBoat world under their own PlayOnline account, with no connection to
Square Enix and no client patching.

This is a bridge, not a world server. The world is upstream LandSandBoat
(LSB), run here unmodified from the LSB team's own prebuilt images, pinned by
digest. OpenLobby supplies accounts, login and Content IDs. This repository
supplies the piece in between, which plays the role xiloader plays for
LSB-only setups, but server-side, so the real Viewer launch works as shipped.

This project contains no Square Enix code, art or data. You need your own
FFXI client and PlayOnline Viewer.

## How it fits together

1. The Viewer logs into OpenLobby, which serves the account's FFXI Content IDs
   in its character table (lobby message `1:3`).
2. Play launches the FFXI client, which resolves `ffxi00.pol.com` to the
   OpenLobby host (OpenLobby's DNS does that) and dials 54001 (view) and 54230
   (data). Both land on the bridge.
3. The bridge asks OpenLobby's session table which member is launching,
   authenticates to LSB's auth server (54231, TLS+JSON) as that member's own
   LSB account (`pol<member id>`, created on first use), and relays the lobby
   stream, injecting LSB's session hash into every packet exactly as xiloader
   would client-side.
4. On the way back it translates LSB's character ids into the PlayOnline
   Content IDs the Viewer expects, and records the pairing plus the world
   identity dword in `ffxi_idmap.json`, which OpenLobby's login service reads
   so its `1:3` record matches what the client was told. Without that match
   the client refuses to open the world socket (POL-0001).
5. After character select the client sends its world login by UDP to
   `LSB_ADVERTISE_IP:54230`; the bridge relays that to LSB's map server
   unchanged, purely so the exchange is observable.

## Prerequisites

- Docker with Compose v2
- OpenLobby running on the same Docker host, brought up with its default
  project name (its data volume is `openlobby_pol-data`, and this stack mounts
  it). Its login service reads the bridge's id map from that volume by
  default (`POL_FFXI_IDMAP=/data/ffxi_idmap.json`), so nothing needs to be
  configured on the OpenLobby side.
- An FFXI client of the version the pinned LSB image expects, launched from
  the PlayOnline Viewer that OpenLobby already serves. The bridge itself does
  not care about the client version; LSB does (see Troubleshooting).
- The two LSB mesh volumes, populated once (below). About 570 MB.
- Python 3.10+ on the host for the selftests and the admin tools

## Bring-up

**1. Mesh volumes (one time).** LSB's map server needs both `/navmeshes`
(pathfinding) and `/ximeshes` (zone geometry), and aborts at start without the
second one, which LSB's own Docker notes do not mention. Both come from the
LSB team's ximeshes image, which populates a volume on first mount:

```
docker volume create lsb_navmeshes
docker run --rm -v lsb_navmeshes:/navmeshes ghcr.io/landsandboat/ximeshes:latest
docker volume create lsb_ximeshes
docker run --rm -v lsb_ximeshes:/ximeshes ghcr.io/landsandboat/ximeshes:latest
```

They are external volumes on purpose: `docker compose down -v` never touches
them. The ximeshes image is used by tag here because it is consumed once for
its data; pin it by digest yourself if you want reproducibility there too.

**2. Configure and start.**

```
cp .env.example .env      # set LSB_ADVERTISE_IP and change every password
docker compose up -d --build
```

The first start imports LSB's schema (a minute or two; `db-update` runs
once and exits) and points every zone at `LSB_ADVERTISE_IP`. `LSB_ADVERTISE_IP`
must be an address the FFXI client can route to; the default 127.0.0.1 works
only for a client on the same machine.

**3. Check.** `docker compose ps` shows db, connect, search, world, map and
bridge up, and `docker compose logs bridge` ends with `startup auth OK` (or
`created the shared LSB account ... and authenticated` on a fresh database)
and `listening on 0.0.0.0:54001`. Then run `python tools/ffxi_idmap_check.py`
with `OPENLOBBY_DIR` pointing at your OpenLobby checkout: it proves the two
stacks name the same id map file on the same volume, and that nothing in the
core stack publishes 54002, which LSB's search server needs.

State lives in named volumes and survives restarts: `lsb-db` (the world
database), `bridge-state` (the member-to-LSB-account map), `bridge-logs` and
`lsb-logs`. The Content ID map lives on OpenLobby's data volume because both
stacks read it.

## Giving an account FINAL FANTASY XI

A PlayOnline account plays FFXI when its handle holds FFXI Content IDs
(content code 1). OpenLobby mints them:

- through its admin panel (`http://127.0.0.1:8090` on the OpenLobby host):
  create the account with FINAL FANTASY XI among its per-title grants, or add
  the grant to an existing account; or
- through in-client sign-up, if the registration code was issued with FFXI
  granted.

Each grant mints `POL_FFXI_CHARACTER_SLOTS` Content IDs (OpenLobby's setting,
default 4), one per character slot, because FFXI issues one Content ID per
character. FFXI must also be listed in OpenLobby's `POL_LOBBY_CONTENT_IDS` for
the Play button to appear; the default list includes it.

The first launch does the rest: the bridge creates the member's LSB account
(`pol<member id>`, password derived from `FFXI_ACCT_SECRET`, never stored),
the client shows empty character slots carrying the member's free Content
IDs, and creating a character pairs the id it spent with the charid LSB
minted. Deleting a character releases its Content ID back to that member's
pool. A Content ID, once served to a client, is never re-minted or moved: the
client keeps that character's macros and settings under `USER/<hex id>/`.

Attribution needs a signed-in Viewer session. The FFXI lobby stream carries no
PlayOnline identity, so the bridge reads OpenLobby's session table: one
signed-in session at the client's address is the answer; two behind one NAT
are told apart by which one has already launched; a launch that cannot be
attributed is refused (`FFXI_REQUIRE_SIGNED_IN=1`) rather than guessed, since
a wrong guess spends someone else's Content ID. A client-side helper that
stamps the session id into the first lobby packet removes the inference
entirely; the bridge honours that stamp when present.

## Importing an existing character

A player who has a character elsewhere (retail or another server) can bring it
over from a `polexport-1` JSON dump: identity, jobs and levels, gil,
inventory with augments and container sizes, equipment, skills, spells, key
items and mounts, quest and mission logs, currencies, job points, teleport
unlocks, home point. `lsb/ffxi_import_core.py` documents the format and what
is and is not transferred; the addon that produces the dump is not part of
this repository. The dump is produced by the player's own client and is an
honour-system import, not a verified transfer.

Admin path, two reviewable steps:

```
python tools/ffxi_import.py sql dump.json --member 5 > import.sql
docker compose exec -T db mariadb -u"$LSB_DB_USER" -p"$LSB_DB_PASSWORD" "$LSB_DB_NAME" < import.sql
# the final SELECT prints the new charid; then pair it with the member's Content ID:
docker compose run --rm --entrypoint python -v "$PWD/tools:/app/tools:ro" bridge \
    tools/ffxi_import.py bind <charid> --member 5 --name <Charname>
docker compose restart bridge
```

The bridge also exposes the same import as `POST /import` on port 54004 for a
client-side helper that knows the Viewer's session token; it binds the pairing
in-process, so no restart is needed on that path. `BRIDGE_IMPORT_PORT=0`
turns it off.

Other admin tools, run the same way (the tools are not baked into the image,
so they are mounted for the one command): `ffxi_provision.py list|create|rehome`
(LSB accounts per member, and moving a character onto a member's account) and
`ffxi_names.py` (a character-name-to-handle table for OpenLobby's database).

## Ports

| host port | proto | owner | role |
|---|---|---|---|
| 54001 | TCP | bridge | lobby VIEW channel (the client dials `ffxi00.pol.com:54001`) |
| 54230 | TCP | bridge | lobby DATA channel |
| 54230 | UDP | bridge | world channel, relayed to LSB's map server |
| 54004 | TCP | bridge | character-import endpoint |
| 54002 | TCP | LSB search | search / auction house (the client dials `LSB_ADVERTISE_IP:54002`) |
| 127.0.0.1:8088 | TCP | LSB world | LSB's HTTP admin API, localhost only |

LSB's auth (54231), conf (51220) and internal view/data ports are reached by
the bridge over the compose network and are not published. The client's own
CONF channel is the PlayOnline lobby, not LSB's.

## Troubleshooting

- **FFXI-3331 at login, LSB logs "incorrect client version".** The classic
  one: LSB's `VER_LOCK` refused the build the client reported. `LSB_VER_LOCK`
  defaults to 0 here (accept any build); if you set 1 or 2, `LSB_CLIENT_VER`
  must match the client's `patch.ver` (2 compares the first six characters
  and requires the client to be at least that). The PS2 client always reads as
  older than any PC build. Client version skew also shows up as an in-world
  mismatch even when login is accepted: the pinned LSB image expects a client
  of its own era.
- **POL-0001 at character select ("writing character data to PlayOnline").**
  The client's world lookup found no entry in PlayOnline's 64-slot character
  table matching the character it picked. Either OpenLobby is not reading the
  bridge's id map (its `POL_FFXI_IDMAP` was overridden away from
  `/data/ffxi_idmap.json`; `tools/ffxi_idmap_check.py`; OpenLobby's lobby
  log says `FFXI id map ... DOES NOT EXIST`), or the member has no free
  Content ID for the character (the bridge log says `NO FREE FFXI Content
  ID`). Raise `POL_FFXI_CHARACTER_SLOTS` in OpenLobby or delete a character.
- **FFXI-3100.** Nothing answered on 54001: the bridge is down, or DNS sent
  the client elsewhere. `docker compose logs bridge`.
- **FFXI-3332 after "Acquiring Player Data".** LSB had no data session for
  the view session. The bridge opens one itself; check its log for
  `DATA-COMP` errors reaching `connect`.
- **Character selects, then hangs connecting to the world.** The 0x0B
  handoff advertised an address the client cannot reach: `LSB_ADVERTISE_IP`
  is wrong or 127.0.0.1. `db-zoneip` writes it into `zone_settings.zoneip`;
  change `.env` and `docker compose up -d` again to rerun it. Also confirm
  UDP 54230 is open to the client.
- **The bridge log says "no signed-in POL session ... refusing the launch".**
  The Viewer's session was not marked signed in (OpenLobby restarted since
  the login, or the launch came from an address no session matches). Sign out
  of the Viewer, sign back in, launch again.
- **`search` fails to start with "port is already allocated".** Something
  else on the host holds 54002 (an older OpenLobby release published it from
  an observation logger; current releases do not).
- **FFXI-3001 mid-session.** The world UDP relay's return path died. Fixed
  for the known cause (LSB's map legally sends empty datagrams); the relay now
  rebuilds a dead flow on the client's next datagram. If it recurs, the world
  capture under `bridge-logs` (`pkt/world/*.jsonl`) holds both directions of
  the flow from its first datagram.
- **Two players on one Viewer machine see each other's characters.** They
  share an address and both are signed in; the bridge tells them apart by
  launch order and blocks character creation while it is ambiguous. Sign one
  out to create.

## Optional: a second world for the Test Server client

The "FINAL FANTASY XI Test Server" client build (PlayOnline content 0015)
dials the same fixed ports as retail and is told apart only by the build it
reports. `docker-compose.lsb-test.yml` runs a second LSB world for it on
ports +1000, and `LSB_ALT_VER=201108` in `.env` makes the bridge route such
clients there. Comments in that file explain the wiring. Retail-only
deployments can ignore it.

## Selftests

```
python tools/bridge_run_all.py
```

runs the offline suite (no Docker, no LSB, no client). Three suites exercise
OpenLobby's own modules or compose files and need a checkout of it, found via
`OPENLOBBY_DIR` or as `../openlobby` beside this repository; without one they
report `skip`, not failure. `tools/ffxi_bfdiff` is a C++ differential harness
for LSB's world-packet cipher; it needs LSB's sources (its header says which)
and is not part of the runner.

## Regenerating the LSB tables

`lsb/ffxi_lsb_tables.py` is generated from LSB's source at the revision the
pinned image was built from. When you re-pin the image, clone that revision
of https://github.com/LandSandBoat/server and run

```
python tools/gen_ffxi_lsb_tables.py --lsb path/to/lsb-server          # rewrite
python tools/gen_ffxi_lsb_tables.py --lsb path/to/lsb-server --check  # is it stale?
```

## What is not included, and why

- No Square Enix files: no client, no Viewer, no game data. LSB's images and
  mesh data are the LSB team's own and are pulled from their registry.
- No world server code: LSB is upstream and unmodified.
- No client-side helper: the session stamp and the self-serve import endpoint
  are supported by the bridge, but the client half is not part of this
  repository. Everything works without it.
- No account data: the LSB database starts empty; accounts come from OpenLobby.

## License

GPL-3.0 (see LICENSE and NOTICE). Two files are derived from LandSandBoat,
which is GPL-3.0: `lsb/ffxi_lsb_tables.py` is generated from its source, and
`tools/ffxi_bfdiff/common/cbasetypes.h` is a verbatim excerpt of one of its
headers. The whole repository therefore carries the same license.

## Credits

- LandSandBoat (https://github.com/LandSandBoat/server): the world server,
  the prebuilt images and the mesh data. This project would be nothing
  without it.
- xiloader, whose client-side session injection this bridge reproduces
  server-side.
- The PlayOnline preservation community.
