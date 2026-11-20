# gitseed: a P2P GitHub alternative built to survive takedowns

## Status (2026-11-20)

**Built and tested:** Phases 0–3, plus most of Phase 4: webseeds and HTTP,
import/export, and onion via SOCKS. These are in `src/`, `tests/e2e.sh` and
`tests/net.sh`. User docs are in [README.md](README.md).

Some details differ from the plan below:
- **One torrent per file.** Each segment, release file and signed doc is its
  own deterministic single-file torrent, instead of one padded torrent per
  snapshot. Unchanged files therefore dedupe across snapshots automatically.
- **Index distribution.** The index is a static mirror folder that `export`
  writes and `import` reads. It isn't yet published as a BEP46 torrent.
- **Release files** are pinned by sha256 in the signed tag message, which
  `gitseed release` writes.
- **Proofs** must be exactly `https://<domain>/.well-known/gitseed`.

**Not built yet:**
- the BEP51 DHT crawler,
- swarm gossip of records,
- archive dumps,
- the reproducible/threshold-signed release pipeline (§6),
- fuzzing,
- Phase 5 (collaboration).

Review rounds with the four personas, final scores: the adversary found no way
to take a project down or silently replace it, the developer scored 8/10, the
cautious user 8/10 and 8/10, the hoster 9/10.

> Working name: **gitseed**. You can rename it before Phase 1.
> This is revision 2. It incorporates a review by four personas: a state
> adversary, a developer, a cautious user and a hoster (see §10).

## 0. The goal, in one sentence

Once someone publishes a repository and **one other person** has it, no
single party (author, host, registrar, ISP, court, or a thief holding the
author's key) should be able to **make it disappear or silently replace it**.
Everything else is secondary.

---

## 1. Should we port GitTorrent? No. We redesign it and keep its good ideas.

[GitTorrent](https://github.com/cjb/GitTorrent) (2015) is a proof of concept,
not a foundation:

| GitTorrent design | Problem for our goal |
|---|---|
| Builds a custom packfile **on demand** for each `want/have` request | Every download is unique bytes, so there is **no swarm** and ordinary torrent clients can't help |
| Usernames registered on **Bitcoin** (Blockname) | Blockname is dead, names cost money, and it adds a heavy dependency |
| Its own bootstrap node, a DHT that never caught on | Single point of failure |
| No search or index | It can't offer the ThePirateBay experience |
| Node.js from 2015, inactive since around 2020 | Bitrot. Porting it would be a rewrite anyway. |

**What we keep:** the Mainline DHT, BEP44 signed mutable pointers, and a
`git clone <proto>://` remote helper.

**Alternatives considered:**
- **Radicle** is the best tool for *collaboration*. Its replication depends on
  its own small gossip network, though, and torrent clients and seedboxes can't
  host its repos.
- **IPFS** depends on pinning, and its gateways are choke points.
- **git-ssb / hypercore** communities are small or gone.

**Decision:** we write a new tool in **Rust**.

> **A repo snapshot is a normal torrent of git bundle files plus a signed
> manifest. Signed DHT records point at the latest snapshot.**

- **Ease of use like BitTorrent:** a magnet link is the repo. Anyone can seed
  it with qBittorrent, Transmission or a seedbox.
- **Robustness like ThePirateBay:** it rides the existing Mainline DHT (millions
  of nodes) instead of a network we would have to grow ourselves.
- **Not tied to one transport:** the same files can also come from webseeds,
  HTTPS, onion services, archives or a USB stick (see §3.7).

---

## 2. What made ThePirateBay hard to kill, and how we copy each part

| TPB property | Our equivalent |
|---|---|
| The site hosts **pointers, not content** | Indexes hold only signed manifests and magnets. The code lives in the swarm. |
| The index is **small and dumpable** | A full index dump is **one torrent**: the SQLite database **plus the static website**. To mirror it, download it and serve the folder anywhere. |
| Trackerless (DHT + PEX) | DHT only. Trackers are optional extras. |
| Hundreds of proxies and mirrors | There is no canonical domain. Every mirror is a static folder, and the same site runs locally (`gitseed serve`) and as an onion service. |
| Content verified by hash | Infohash, sha256 of every file, an ed25519-signed manifest and git hashes |

Indexes are **not authoritative**. Every entry is signed by its publisher,
so indexes can be merged freely. Censorship requires *every* index to omit an
entry. **Web mirrors are untrusted UI.** Only the local client decides what is
"verified" (§4).

---

## 3. Architecture

```
            ┌──────────── Mainline DHT (existing, ~10M nodes) ────────────┐
            │  BEP5  get_peers/announce → find seeders of an infohash     │
            │  BEP44 mutable put/get    → policy record, snapshot pointers│
            └──────────────────────────────────────────────────────────────┘
                 ▲                    ▲                        ▲
   publish/seed  │       clone/pull   │      crawl/announce    │ publish index
          ┌──────┴─────┐       ┌──────┴─────┐          ┌───────┴────────┐
          │ maintainer │◄─────►│ hoster /   │ ◄──────► │ indexer        │
          │            │ swarm │ user       │  dumps   │ (anyone)       │
          └────────────┘       └────────────┘          └───────┬────────┘
            also: webseeds (BEP19), HTTPS, onion, archives,    │ static site +
            `gitseed export/import` sneakernet                 ▼ index.sqlite
```

### 3.1 Keys, projects and the DHT records

There are two kinds of key. This allows several maintainers, key rotation and
offline root keys without giving up BEP44's rule of one signer per record.

- **The root key** identifies the project. The address is
  `gitseed://<root-pk-z32>/<name>`. The root key signs only **policy** changes,
  which are rare, so it can live offline or on a hardware key.
- **Maintainer keys** sign snapshots. A solo developer's root key is also their
  maintainer key.

**The policy record** is a BEP44 item with `k = root_pk` and `salt = name`. It
is bencoded and under 1000 bytes:
```
{ maintainers: [pk…], threshold: 1, next_root_hash: sha256(next root pk),
  policy_sha256: <hash of full policy.json>, revoked: [pk…] }
```

**Snapshot pointers** are one per maintainer: a BEP44 item with
`k = maint_pk` and `salt = sha1(root_pk‖name)`, holding
`{ ih: <infohash>, manifest_sha256 }`.
- To resolve a project, a client reads the policy, queries every listed
  maintainer's pointer, and takes the newest valid snapshot that chains
  correctly.

**`seq` = unix microseconds.** Clients reject a `seq` more than 10 minutes in
the future. This stops an attacker from locking the project with
`seq = i64::MAX`.
- Each client stores a high-water `seq` per key and warns on rollback.

**Rotation and revocation:**
- Every policy commits to `next_root_hash` (pre-rotation). A thief holding the
  current root key cannot name a successor that was not committed in advance.
- To rotate, publish the new root's first policy signed by both keys, or by the
  pre-committed next key alone if the old key is lost.
- To revoke a maintainer, publish a policy without them (`revoked: [pk]`). That
  maintainer's snapshots after the policy's `seq` become invalid.

**Anyone can re-put any signed record.** Mirrors republish both record types
about every hour, staggered, and skip any record that another mirror refreshed
recently. The pointers stay alive after the authors are gone.
- Records also travel in index dumps and in a BEP10 swarm-gossip message, so
  DHT eclipse attacks alone can't hide them.

### 3.2 Snapshot layout: layered bundles that are selectable and deduplicated

```
<name>-<seq>/
  manifest.json
  policy.json                  # full policy: proofs, git signer identities
  seg/<sha256>.bundle          # git bundle segments, content-addressed
  assets/<file>                # optional release binaries and notes
```

**Segments** are incremental bundles:
`git bundle create seg.bundle <new tips> ^<previous tips>`.
- The first publish produces a base segment. Each push adds one small segment.
- Old segment files are **byte-identical across snapshots**.
- Every file is **piece-aligned with BEP47 padding**. Unchanged files therefore
  have identical piece hashes in every snapshot torrent, so a hoster stores
  them once. We use hybrid v2 torrents if Phase 0 shows the library supports
  them.
- **Compaction:** after about 20 segments, or when segments exceed half the
  base's size, any maintainer can publish a fresh base segment.

**The manifest** binds everything. It is signed by a maintainer key, and the
signature covers canonical JSON without the `sig` field:
```json
{ "v": 1, "root_pk": "...", "name": "...", "policy_sha256": "...",
  "signer": "<maint pk>", "seq": 1763600000000000, "prev": ["<ih>", ...],
  "refs": { "refs/heads/main":  {"sha": "...", "segs": ["<sha256>", ...]},
            "refs/tags/v2.4.1": {"sha": "...", "tag_obj": "...", "segs": [...]} },
  "segs":   { "<sha256>": {"size": 0, "prereqs": ["<sha>"], "tips": ["<sha>"]} },
  "assets": [ {"path": "assets/x.tar.gz", "sha256": "...", "size": 0} ],
  "root_commits": ["..."], "retract": ["<ih>"],
  "description": "...", "topics": [], "license": "...", "readme_excerpt": "...",
  "proofs": ["dns:example.org", "https://github.com/me/repo"], "sig": "..." }
```

- **Choosing refs:** each ref lists the minimal chain of segments it needs. A
  hoster or user who wants only `main` plus `v2.*` downloads only those files.
  This is ordinary partial-file selection, which qBittorrent can also do.
- **What gets published** is decided by the publisher's `.gitseed` file. The
  default is `refs/heads/*` and `refs/tags/*`. `refs/stash`, `refs/remotes`,
  `refs/pull`, `refs/replace` and notes are **never** published.
- **The torrent `info` dict carries `"x-gitseed": 1`** so crawlers can find
  snapshots. Because the marker is inside the infohash, it can't be added to
  other torrents after the fact.
- **Client checks:** every segment's sha256 must match, `git bundle verify`
  must pass, and the bundle's ref set must **exactly** equal the manifest's.
  `refs/replace` and grafts are rejected, and `transfer.fsckObjects=true` is
  always on.

### 3.3 Projects, forks and mirrors
- **`project_id = sha256(sorted root_commits)`** is a **grouping hint only,
  never a basis for trust**. Shared template roots and squashed histories can
  collide it or split it. Indexers verify that a manifest's `root_commits` are
  really in its bundle, or mark the entry "unverified".
- **Kinds of result.** Within a project, results are:
  - the **canonical** project: the client's pinned root key;
  - **mirrors**: byte-identical snapshots signed by the same key;
  - **forks**: different root keys.
- **Ranking within a project** goes by key continuity: age, `prev`-chain
  length, verified proofs, and endorsements from keys you follow. It **never**
  goes by seeder count or recency, both of which can be faked for free.
- **Lookalike keys** within a project trigger a warning. The UI shows long
  fingerprints and local petnames.

### 3.4 Updates and hostile maintainers
- **Mirrors never delete** snapshots in the `prev` chain. Every infohash ever
  seen is kept, whatever a new head claims.
- **Tags are immutable across the chain.** A moved tag fails loudly.
- **A non-fast-forward update** triggers a "history rewritten" warning, and the
  client keeps both versions.
- **A fast-forward update by a stolen key** is the real threat. Defences:
  - Projects can set `require_signed: tags|commits` in their policy. New refs
    must then be git-signed (SSH, GPG or sigstore) by a signer listed in
    `policy.json`. A stolen gitseed key alone is not enough.
  - `gitseed pull` shows a diffstat, new signers, and the "first push from a
    new device or after long silence" flags before updating a checkout.
    `follow.delay = "72h"` is opt-in for users who want a waiting period.
  - Seeders always fetch new snapshots, because storing them is harmless. Only
    *checkouts* are gated.
- **Retracting a snapshot** (for example after leaking a secret) is a signed
  `retract: [ih]` in a later manifest. Well-behaved indexers and clients stop
  listing or seeding it. This is **advisory**, and the docs say so plainly:
  rotate the secret.

### 3.5 Identity: how a user knows the key is really the author's
1. **Proofs, checked by the client itself.** These are a DNS TXT record
   `_gitseed.<domain>`, `https://<domain>/.well-known/gitseed`, a line in the
   old GitHub README, or a Keyoxide profile. An index may display proof
   results, but the client always re-checks them.
2. **Trust on first use** per project. `~/.config/gitseed/pins` stores the root
   key, the policy version, the high-water `seq`, and every tag→sha seen.
3. **States** are computed only by the local client:

| Badge | Meaning |
|---|---|
| `VERIFIED` | A proof checked out, the root key is pinned, and the ref is signed by a listed maintainer or git signer |
| `PINNED` | The key matches what was seen on first use, but there is no external proof |
| `UNKNOWN` | A new key with no proof. Scripted use needs `--trust-new-key`. |
| `FORK` | Same `project_id` but a different root key. It is shown with its own proofs and never called the original. |
| `MIRROR` | A byte-identical snapshot republished by someone else |
| `⚠ WARN` | Unsigned commits past the last signed tag, history rewritten, a `seq` rollback, or a stale record |
| `✖ FAIL` | A moved tag, a bad signature, a policy change below the threshold, or a revoked key. The client exits non-zero and the last good snapshot stays checked out. |

### 3.6 Indexes: the "site"

**Sources.** Anyone can run `gitseed indexer`. It collects manifests from:
- direct announces (HTTP or onion; optional);
- other indexers' dumps (a union);
- its local seeds;
- later (Phase 4), a BEP51 DHT crawl that needs no submission at all.

**Abuse limits.** Indexers rate-limit per key and per project. Proof of work
for new keys is an option if spam grows.

**Output.**
- `index.sqlite` with FTS5 search over names, descriptions, topics and README
  excerpts.
- A **static site** that searches SQLite in the browser using HTTP range
  requests. It works on any file host, an onion service or `file://`.

**Distribution.**
- The dump also carries **DHT bootstrap node lists**, **signed gitseed
  binaries** (§6), and a recent set of records.
- It is published as a torrent and is BEP46-mutable under the indexer's key.
- `gitseed index follow <key>` keeps a local copy, so search works offline.
- `gitseed index mirror <key> --serve` makes you a public mirror.

**Archive dumps.** An optional, larger "archive" dump embeds every
small-to-medium repo's latest segments. Every archive mirror then seeds every
project, which defends niche projects.

**Moderation.** Each indexer keeps its own blocklist and publishes it openly.
Users follow several indexes, and the raw DHT crawl is the fallback.

### 3.7 Transport independence
A snapshot is just *signed manifest + files with sha256*. The client fetches
files from any source and verifies them identically:
- BitTorrent;
- BEP19 webseeds listed in the manifest, including Software Heritage and
  Internet Archive mirrors;
- plain HTTPS;
- onion services;
- `gitseed export <addr> > repo.gitseed` and `gitseed import` for USB drives
  and sneakernet.

Blocking BitTorrent with DPI inside one country doesn't stop delivery.

### 3.8 Threat model (after the review)

| Attack | Result |
|---|---|
| A mirror site's domain or host is seized | Other mirrors, onion mirrors and local copies keep working, and the dump keeps spreading |
| Every indexer is shut down | Clone by address, magnet or file still works. Any local index copy can restart an indexer. |
| A stolen key publishes an empty or rewritten update | Old snapshots persist, a rewrite warning fires, and tags are immutable. The key is rotated through `next_root_hash`. |
| A stolen key publishes a fast-forward backdoor | It is blocked by `require_signed`, and otherwise surfaced by the pull diff, the new-device flags and the optional delay |
| A stolen key sets `seq = MAX` to freeze the project | Rejected, because `seq` is a timestamp and future values are refused |
| A DHT eclipse or rollback of the records | Records also arrive through dumps and swarm gossip. The `seq` high-water mark and staleness warnings catch rollbacks. |
| A DHT eclipse of the swarm | Webseeds, HTTPS, onion sources and peer hints in dumps |
| A bootstrap node is seized | The routing table persists between runs. Hard-coded diverse IPs and node lists in dumps cover new installs. |
| A national firewall blocks BitTorrent | Non-BT transports (§3.7). Delivery still works worldwide. |
| Typosquats, vanity keys or Sybil forks | Pinning, proofs, continuity ranking, lookalike warnings, and a CLI that never trusts web mirrors |
| Junk forks to fill mirrors' disks | Per-publisher quotas, forks only by rule, and quarantine of new publishers (§5) |
| A manifest re-paired with a different bundle | The manifest pins the sha256 of every segment, and ref sets must match exactly |
| `refs/replace` tricks or malicious git objects | Rejected. fsck is always on. |
| CSRF or DNS rebinding against the local daemon | A token is required, Origin and Host are checked, actions need confirmation, and READMEs are sanitized |
| The gitseed binary itself is backdoored | §6: reproducible builds, threshold-signed releases, distribution in dumps, no automatic updates |
| The last seeders of a niche project are waited out | Archive dumps, `seed --adopt` for under-seeded projects, and webseeds to archives |
| **Legal pressure on individual seeders** | **Not solved by design.** IPs are visible, as with BitTorrent. We document this, support SOCKS5/Tor or a pinned VPN interface for **all** traffic, and offer `gitseed block`, so a takedown request for one repo can be honored without quitting. |

---

## 4. Experience by persona

### Developer
```sh
gitseed keygen --from-ssh ~/.ssh/id_ed25519   # or a new encrypted key file; ed25519-sk hardware keys work through ssh-agent
cd myproject
gitseed init --include main --include 'v*' --proof dns:myproject.org   # writes .gitseed
gitseed publish --dry-run       # lists refs, size and exclusions, then runs a secret scan (gitleaks if installed)
gitseed publish                 # the first publish requires typing "forever"
git push gitseed://k7fp…/myproject main          # adds one small segment and returns in seconds
gitseed push --wait-seeders 1                    # blocks until another peer holds the data
git tag -s v1.2 && gitseed release v1.2 dist/*   # tag plus assets/, all sha256-pinned in the manifest
gitseed maintainer add <pk>                      # updates the policy (signed by the root key)
gitseed key rotate                               # uses the pre-committed next key
```
- **CI** uses a maintainer key limited to `refs/tags/v*` with an expiry, read
  from `GITSEED_KEY_FILE`.
- **Contributions:** `gitseed forks <project>` lists forks, and
  `gitseed pull-from gitseed://other/repo branch` fetches from one.
- **Migration:** `gitseed import-github owner/repo` exports issues and PRs into
  `assets/issues.json` and prints a README snippet that points to the gitseed
  address.

### Cautious user
```
coinvault · project 7f3a…c91e · root hk4q…8zt1 [VERIFIED]
  proofs: dns coinvault.org ✓  github.com/coinvault ✓   (checked locally)
  maintainers 3, threshold 2 · policy v4
RELEASES / TAGS      commit    signed by              assets     status
 v2.4.1 (latest)     9e1c04a   alice ssh:Qx… ✓        3 sha256   VERIFIED
 v2.4.0              41bb7d2   bob   gpg:A1… ✓        3 sha256   VERIFIED
 v2.3.8-rc1          d2a990b   unsigned               —          ⚠ unsigned tag
BRANCHES
 main                b81f3e0   12 past v2.4.1, 2 unsigned        ⚠ WARN
SNAPSHOTS  #14 ← #13 ← … ← #1   no rewrites · no rollbacks
OTHER PUBLISHERS
 xm2p…a0d4 "coinvault"   FORK  UNKNOWN   +1 commit on v2.4.1
```
```sh
gitseed refs gitseed://hk4q…/coinvault                    # the view above, in the CLI and the local web UI
gitseed clone gitseed://hk4q…/coinvault --ref v2.4.1      # fetches only the segments v2.4.1 needs
gitseed verify --ref v2.4.1                               # re-checks proofs, policy chain, seq, sha256, refs, tag signature, assets
```
Public mirror sites show the same view with a banner: **"Discovery only. Verify
with the client."**

### Hoster
`~/.config/gitseed/seed.toml`:
```toml
[limits]
disk_quota = "400GiB"; disk_reserve = "20GiB"
up_kbps = 50000; down_kbps = 20000; monthly_up = "2TiB"
schedule = "01:00-07:00 full; else 25%"

[network]
proxy = "socks5://127.0.0.1:9050"     # or bind_interface = "wg0"

[defaults]
refs = ["refs/heads/main"]; tags = "latest:3"; forks = false
max_repo = "5GiB"; new_publishers = "quarantine"   # quarantine = manifest only, until approved

[[rule]]
match = "project:a1b2…"; refs = ["main", "release/*"]; tags = "v2.*"; forks = "top:5"; pin = true

[[rule]]
match = "publisher:k4f…"; forks = true; max_repo = "20GiB"
```
```sh
gitseed seed add <addr> --refs main --tags 'v2.*' --pin
gitseed seed dry-run            # what would be fetched or evicted
gitseed health --needs-me       # projects ranked by how few copies their pieces have
gitseed seed --adopt 10GiB      # automatically seed the least-seeded projects within a budget
gitseed gc --to-quota           # evict in this order: compacted segments → old tags past the rule → unpinned forks
gitseed block <ih|project>      # purge and stop announcing (for takedown requests)
gitseed export-rss              # feed for qBittorrent's RSS auto-downloader
```
- **Survival floor:** the minimum gc never evicts for a pinned project. It is
  the segments for the latest default branch, the first-ever snapshot, and
  every manifest in the `prev` chain. Manifests are tiny.
- **Running unattended:** a systemd unit (`MemoryMax`, `IOWeight`), a JSON
  `/health` endpoint on localhost, journald logs, a versioned state directory,
  and a stable on-disk format.
- **qBittorrent-only seeders** can seed whole snapshots or tick per-segment
  files, and can follow updates through the RSS feed. They can't apply rules,
  verify trust or gc.

---

## 5. Abuse controls for hosts and indexers
- **Before any data is fetched:** the manifest is fetched first, then its size
  is checked against the cap.
- **Accounting and caps:** usage is tracked per publisher and per project, with
  hard caps on both.
- **Forks:** fetched only by rule. Quarantine holds new publishers.
- **Indexers:** rate limits per key, `root_commits` verification, and blocklists
  published openly.

## 6. The gitseed binary's own supply chain
Attacking the tool itself would defeat everything else, so it needs its own
defences:
- **Reproducible builds.** Releases are attested by several independent
  builders, and a release is valid only with **m-of-n maintainer signatures**.
- **Audited dependencies.** Dependencies are vendored and pinned, and audited
  with `cargo vet`. The dependency list is kept small.
- **No automatic updates.** `gitseed self-update` shows the signers and needs
  confirmation.
- **Distribution:** releases come from **gitseed itself** (gitseed is a gitseed
  project) and inside every index dump, so a GitHub ban doesn't matter.

## 7. Technology choices

| Need | Choice | Why |
|---|---|---|
| Language | **Rust** | A single static binary, memory safety on hostile input, and good P2P crates |
| BitTorrent | **librqbit** | Pure Rust, a library API, and torrent creation. Phase 0 checks custom info keys, BEP47 padding and v2. libtorrent-rasterbar is the fallback. |
| BEP44/46 | **`mainline`** (used by Pkarr) | `put_mutable` / `get_mutable_most_recent` with compare-and-swap (CAS) |
| git | The **`git` CLI** | Users already have it, `git bundle` is battle-tested, and we write no git internals |
| Signatures | `ed25519-dalek`, plus `ssh-agent` for hardware keys | Standard. Hardware support comes for free. |
| Git signature checks | `git verify-tag` / `verify-commit` with `gpg.ssh.allowedSignersFile` generated from the policy | Reuses git's own checks |
| Index | SQLite FTS5 (`rusqlite`, bundled) | One file and easy to dump |
| Local web and daemon | `axum` | Already in rqbit's dependency tree |
| Static site | Plain HTML/CSS plus small JS (sql.js-httpvfs) | No build step |

**Layout:** one crate and one binary. `git-remote-gitseed` is the same binary,
chosen by `argv[0]`. Modules: `keys`, `policy`, `snapshot`, `swarm`, `dht`,
`trust`, `seed`, `index`, `web`.

---

## 8. Phases

The on-disk **format** (layered segments, manifest, policy, `seq` rules) must
be final in Phase 1. Changing it after people start seeding is expensive.

**Phase 0. Spike.**
- One program bundles a repo into segments, makes a padded torrent with
  `x-gitseed`, seeds it with rqbit, and puts a policy record and a pointer with
  `mainline`.
- A second instance resolves them, fetches only the segments for one ref, and
  `git clone`s.
- Decide hybrid v2 versus v1 with padding. Swap libraries here if needed.

**Phase 1. Core and format.**
- Commands: `keygen` (including `--from-ssh`), `init`/`.gitseed`, `publish`
  (dry run, secret scan, confirming "forever"), `clone --ref`, `pull`, and
  `seed`, a daemon with a staggered republish loop.
- The remote helper.
- Manifest and policy signing; checks of sha256, exact ref sets and fsck; `seq`
  rules and the high-water mark.
- **Exit test:** two machines on different networks clone each other's repos,
  with only the selected refs, and no server.

**Phase 2. Survival and trust.**
- Survival: `prev` chains, never-delete, immutable tags, rewrite detection and
  retraction.
- Keys and policy: maintainers, rotation, revocation, `require_signed`.
- Identity: proofs, pins and badges, plus `refs` and `verify`.
- Releases and assets.
- **Exit tests:**
  - A stolen key's backdoor push is flagged or blocked.
  - An author who goes offline and publishes an empty update still leaves the
    full history clonable.
  - A key rotation is accepted, and a forged rotation is rejected.

**Phase 3. Hosting and index.**
- Hosting: `seed.toml` rules, quotas, gc and the survival floor, `health`,
  `--adopt`, `block`, quarantine, and the RSS export.
- Index: the indexer (announces, dump union, local seeds), SQLite FTS, the
  static site, the dump torrent with BEP46, `index follow` / `mirror` /
  `search` / `serve`, and the daemon hardening from §3.8.
- **Exit test:** kill the main indexer, and search keeps working on a second
  mirror and offline.

**Phase 4. Hardening.**
- Transports and discovery: webseeds and HTTPS, onion services,
  `export`/`import`, swarm gossip of records, the BEP51 crawler, and archive
  dumps.
- The §6 release pipeline.
- Fuzzing the manifest, bencode and bundle parsers.
- Compaction, and a file and commit browser in the web UI.

**Phase 5. Collaboration (later, optional).**
- Issues and patches as git refs inside the segments (git-bug style), so they
  replicate with the code.
- Or a bridge to Radicle.
- Until then, a "pull request" means publishing a fork, and the maintainer runs
  `pull-from` on it.

## 9. Explicitly out of scope
- Accounts, stars, CI, a web editor and private repos.
- Publishing is **public forever**. The UI says so at the first publish.

## 10. Persona review log (revision 1 → 2)

| Persona | Biggest finding | Change |
|---|---|---|
| State adversary | A stolen key could push a backdoor with no warning. `seq` could be maxed out to freeze the project. The binary's supply chain was not covered. Web mirrors could swap clone commands. | `require_signed`, pull gating, timestamp `seq`, pre-rotation (§3.1, §3.4), §6, untrusted web UI (§2, §3.5), transport independence (§3.7) |
| Developer | `--all` leaked WIP branches. No secret handling, rotation or multiple maintainers. Every push re-uploaded the whole repo. | The `.gitseed` include list, dry run and secret scan, `retract`, root/maintainer keys, layered segments moved into Phase 1 |
| Cautious user | Nothing tied a key to the author. Uploader and author were confused. No refs view. | Proofs plus TOFU pins, git-signature verification, badges, `refs` / `verify` (§3.5, §4) |
| Hoster | Couldn't pick refs. Full copies per version. Unbounded "mirror everything". No ops tooling. | Per-ref segment chains with padding dedup, `seed.toml`, survival floor, gc, `health`, quotas, proxy for all traffic (§3.2, §4, §5) |

## 11. Open questions for you
1. **Name:** is "gitseed" fine?
2. **Collaboration:** can v1 ship as "code survives", with issues and PRs later?
3. **Compatibility:** is it OK to drop wire compatibility with GitTorrent?
4. **Default for new users:** should `pull` wait out the 72h delay unless the
   project's policy uses `require_signed`? The more secure choice (on) makes
   it feel slower.
