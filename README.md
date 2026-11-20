<img src="assets/icon.svg" width="64" height="64" alt="">

# gitseed

Git hosting that cannot be taken down. A repository is a set of ordinary
BitTorrent files plus a signed manifest. It is found through the BitTorrent
Mainline DHT (millions of nodes, no owner) or any mirror. Once one other person
has your code, no host, registrar or court can remove it, and nobody can
silently swap it for something else.

```
cargo build --release            # needs git ≥ 2.34 on PATH
ln -s $(pwd)/target/release/gitseed ~/.local/bin/gitseed
ln -s $(pwd)/target/release/gitseed ~/.local/bin/git-remote-gitseed   # enables git clone/push gitseed://
```

Design and threat model: [PLAN.md](PLAN.md).

---

## Developers: publish

```sh
gitseed keygen --recovery-out /media/usb/recovery.key   # publishing key + an offline RECOVERY key
cd myproject
gitseed init --include main --include 'v*' \
  --require-signed tags --git-signer you@example.org=~/.ssh/id_ed25519.pub \
  --proof https://example.org/.well-known/gitseed
gitseed publish --dry-run            # what will (not) be published, size, secret scan
gitseed publish                      # first publish asks you to confirm it is permanent
git push gitseed://<key>/myproject main      # later updates: plain git push (or `gitseed publish`)
gitseed release v1.2 dist/*          # creates the signed tag v1.2 listing each file's sha256, and publishes
```

**What is published:** only the refs listed in `.gitseed` under `include`, and
by default only branches and tags. Stashes, remotes, notes and `refs/replace`
are never published. `--dry-run` lists every ref that is excluded.

**Size of updates:** each publish uploads only the new history, as one small
segment. Every 20 segments are compacted into a new base.

**Secrets:** `publish` scans new commits for keys and tokens, and uses gitleaks
if it is installed. If one slips through, `gitseed retract <snapshot>` asks
mirrors to stop listing that snapshot. Treat the secret as leaked and rotate it.

**Refused at publish time:** moving a published tag, publishing an unsigned tag
when the project requires signatures, and rewriting history unless you pass
`--force`. Clients would reject all three anyway.

**Forks:** a clone of someone else's project never silently becomes a new
project. `gitseed publish` publishes to the original if you are a maintainer
there, and refuses otherwise. `gitseed publish --fork` publishes your own copy
under your key.

**Team:**
- The root key holder runs `gitseed maintainer add <key> --label bob`.
- Bob joins with `gitseed init --address gitseed://…`. A plain `gitseed clone` of the project also works. For CI:
`gitseed maintainer add <ci-key> --scope 'refs/tags/v*' --expires-days 365`,
then run with `GITSEED_KEY_FILE=…` in CI. A scoped key can only move the refs
its scope covers.

**Lost or stolen laptop:** from any clone, run
`gitseed rotate --recovery-key /media/usb/recovery.key`. Add
`--address gitseed://…` if the clone doesn't record it. The first publish writes
`address` into `.gitseed`, so commit that file. Every client follows the rotation automatically, and the
stolen key is revoked. A thief holding only your publishing key cannot do this:
the recovery key was committed in advance.

**Prove it's you:** serve the line that `gitseed whoami` prints, `gitseed key: <your key>`,
at `https://<your-domain>/.well-known/gitseed`. A GitHub Pages site
(`you.github.io`) works too. List that URL with `--proof`.

Every client fetches the page itself and then shows the result as "published by
the owner of <your-domain>". Pages that anyone can comment on are not accepted
as proof.

**Moving from GitHub:**
- Before turning on `--require-signed`, run `gitseed init`. Existing unsigned
  tags are listed in `unsigned_ok` and marked as legacy.
- Add the `gitseed://…` address to your GitHub README so users can find it.

## Cautious users: verify

```sh
gitseed verify gitseed://<key>/<name>            # every branch, tag and release, with signer and status
gitseed verify gitseed://<key>/<name> --ref v1.2 # just one release; exit code 2 if it fails
gitseed clone  gitseed://<key>/<name> --ref v1.2 # fetches only what v1.2 needs, verified
gitseed serve                                    # the same view in a browser at http://127.0.0.1:7878
```

```
demo  ·  gitseed://d7df…f3/demo
  publisher key  d7df-145e-4e61-6c0f-fd0b
  identity       [VERIFIED] the key is published at https://example.org/.well-known/gitseed
  maintainers    root (d7df-145e)   ·   signatures required on: tags
  REF       COMMIT      SIGNED BY      STATUS
  -- tags --
  v1.1      65c652c507  ✔ dev@x        VERIFIED
  v1.0      f97914f138  ✔ dev@x        VERIFIED
  -- branches --
  main      4b664c2f98  — unsigned     branch — not signed; use a signed tag to verify  (= v1.1)
  other publishers of the same code (NOT this author):
    FORK  03a1-77c2-…  demo  2026-11-20
RESULT: OK
```

**Identity**, shown for the publisher:
- **VERIFIED:** a URL the author controls names this key.
- **PINNED:** the same key you trusted before.
- **UNKNOWN:** never seen and no proof. gitseed asks before you accept it.

**Status**, shown for each ref:
- **VERIFIED:** the git signature comes from a signer listed in the project's
  signed policy, and the author's identity is proven.
- **SIGNED:** the signature checks out, but the author's identity is not proven.
- **UNSIGNED:** the ref has no git signature.
- **UNVERIFIED:** the ref is signed by a key the project does not list.
- **FAIL:** gitseed refuses to check it out.

**Release files** appear under their tag with their sha256. Check a download
with `gitseed verify-file <address> <file>`. Changing a release file that was
already published counts as a failure. Adding a new file to an existing release
triggers a warning.

**Exit codes** for `verify` and `verify-file`:
- `0`: OK.
- `2`: failed.
- `3`: the signatures are fine, but nothing proves who owns the key.

`--json` gives machine-readable verdicts.

**What makes a ref FAIL:**
- A bad signature, or a missing one on a ref that must be signed.
- A moved tag. Tags are immutable on your machine.
- A rollback to an older snapshot.
- A snapshot signed by a non-maintainer.

**Updating:** `gitseed pull` shows the new commits and who signed the snapshot.
Plain `git pull` refuses an update that needs review and points you to
`gitseed pull`. It stops and asks when something unusual happens:
- a new signing key,
- a maintainer was added,
- the signature requirement was weakened,
- history was rewritten,
- the project was silent for months.

To wait before taking updates, set `git config gitseed.delay 72` (hours).

**Forks and impostors:** a project published by a different key is shown as
FORK, even when it has the same name and history. Lookalike keys are flagged.

**Public mirror websites** are for discovery only and say so. Only your own
client's verdict counts.

## Hosters: seed

```sh
gitseed seed add gitseed://<key>/<name> --refs main --refs 'release/*' --tags 'v2.*'
gitseed seed add gitseed://<key>/<other> --tags latest:3 --no-assets
gitseed seed dry-run           # what it would fetch, and how big it is
gitseed seed                   # daemon: fetch updates, seed, republish DHT records, serve web UI + mirror
gitseed seed systemd           # unit file for running unattended
gitseed health --needs-me      # projects with the fewest copies in the swarm
gitseed seed adopt 20GiB       # automatically host the least-seeded projects you know
gitseed block gitseed://…      # stop hosting one project (e.g. after a takedown request) and free its space
gitseed gc                     # free data no rule needs
gitseed seed rss               # RSS of magnet links (with webseeds) for qBittorrent; also served at /rss.xml
gitseed seed import-blobs ~/Downloads   # adopt files a plain torrent client downloaded
```

`~/.local/share/gitseed/seed.toml`:

```toml
disk_quota = "400GiB"          # never fetch past this
max_repo = "5GiB"              # skip any single project larger than this
interval_minutes = 30
listen = "127.0.0.1:7878"      # "0.0.0.0:7878" makes you a public HTTP mirror/webseed too
[defaults]
refs = ["*"]
tags = "all"                   # all | none | latest:N | glob
assets = true
[[follow]]
address = "gitseed://…/demo"
refs = ["main"]
tags = "latest:3"
assets = false
```

**The daemon:**
- syncs again as soon as `seed.toml` changes,
- runs gc after every pass,
- stops seeding anything that has been unfollowed or blocked,
- logs with timestamps, printing only what changed,
- writes `GET /health` (`ok`, `last_ok`, a status line for each project).

**What gc never deletes:** for every followed project, gc keeps
- the latest default branch,
- the first-ever snapshot (so a forced "empty update" can't erase history),
- every signed document.

**Network options** go in `~/.local/share/gitseed/config.toml`:

```toml
port = 6881
proxy = "socks5://127.0.0.1:9050"   # all TCP traffic through Tor/VPN; set dht = false to keep UDP off too
bind_interface = "wg0"              # or bind BitTorrent to your VPN interface
up_kbps = 5000
down_kbps = 20000
mirrors = ["https://mirror.example/", "/media/usb/gitseed"]
```

**Your exposure:** as with any BitTorrent seeding, peers can see your IP
address. Use a VPN, seedbox or proxy if that matters where you live.

## Mirrors and the index (the "site")

```sh
gitseed export /srv/www/gitseed        # static website + index.json + data; serve with any web server
gitseed import https://mirror.example/ # learn every project a mirror lists (also works from a folder or USB stick)
gitseed search rust http               # search what you know, offline
```

- An exported folder is a complete mirror: a searchable static site, every
  signed document, and all the data needed to clone.
- You can copy it anywhere, such as a cheap host, an onion service or a USB
  stick.
- `gitseed import` from that folder works just like `import` from a URL.
- Mirrors can hide projects but cannot forge them, so importing from several
  mirrors defeats censorship.

## Tests

```sh
cargo test && tests/e2e.sh && tests/net.sh      # INTERNET=1 tests/net.sh also uses the public DHT
```
