#!/usr/bin/env bash
# End-to-end: developer publishes, user clones/verifies/pulls through a mirror directory,
# tampering and attacks are rejected. Offline (no DHT). Run: tests/e2e.sh [path/to/gitseed]
set -euo pipefail
BIN=$(realpath "${1:-target/debug/gitseed}")
T=$(mktemp -d)
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill $p 2>/dev/null || true; done; [ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT; echo "tmp: $T"
export GITSEED_NO_DHT=1 GIT_AUTHOR_NAME=dev GIT_AUTHOR_EMAIL=dev@x GIT_COMMITTER_NAME=dev GIT_COMMITTER_EMAIL=dev@x GIT_CONFIG_GLOBAL=/dev/null
dev() { GITSEED_HOME=$T/dev GITSEED_MIRRORS=$T/mirror "$BIN" "$@"; }
usr() { GITSEED_HOME=$T/usr GITSEED_MIRRORS=$T/mirror "$BIN" "$@"; }
ok() { echo "  ✔ $*"; }
fail() { echo "  ✖ $*"; exit 1; }

echo "== developer: keys, repo, signing"
dev keygen >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$T/sign" -C dev@x
mkdir "$T/proj" && cd "$T/proj" && git init -q -b main
git config gpg.format ssh && git config user.signingkey "$T/sign"
echo "hello" >README.md && git add . && git commit -qm init
git checkout -qb wip && echo wip >wip.txt && git add . && git commit -qm wip && git checkout -q main
echo "api_key = 'abcdefghijklmnopqrstuvwxyz123456'" >config.py && git add . && git commit -qm "oops secret"
dev init --name demo --include main --include 'v*' --require-signed tags --git-signer "dev@x=$T/sign.pub" --description "demo project" >/dev/null

echo "== secret scan blocks first publish"
if dev publish --yes-forever 2>"$T/err"; then fail "secret not caught"; fi
grep -q "hard-coded secret" "$T/err" && ok "secret detected"
git reset -q --hard HEAD~1
git tag -s v1.0 -m "release 1.0"

echo "== dry run shows what is (not) published"
dev publish --dry-run >"$T/dry" 2>&1; grep -q "NOT publishing.*wip" "$T/dry" && ok "wip branch excluded"
dev publish --yes-forever >"$T/pub" 2>&1 || { cat "$T/pub"; fail publish; }
ADDR=$(grep -o 'gitseed://[0-9a-f]*/demo' "$T/pub" | head -1)
ok "published $ADDR"
dev export "$T/mirror" >/dev/null && ok "exported mirror"

echo "== user: unknown key is refused without consent"
cd "$T"
if usr clone "$ADDR" c0 </dev/null 2>"$T/err"; then fail "unknown key accepted silently"; fi
grep -q "not trusted" "$T/err" && ok "unknown key needs consent"

echo "== user: clone + verify"
usr clone "$ADDR" c1 --trust-new-key >"$T/clone" 2>&1 || { cat "$T/clone"; fail clone; }
grep -q "v1.0.*dev@x.*SIGNED" "$T/clone" && ok "tag v1.0 signature verified"
[ -f c1/README.md ] && ok "working tree checked out"
git -C c1 rev-parse -q --verify refs/remotes/origin/wip >/dev/null && fail "wip leaked" || ok "wip not present"
usr verify "$ADDR" --ref v1.0 >"$T/v" 2>&1 && grep -q "RESULT: OK" "$T/v" && ok "verify OK"

echo "== developer pushes an update; user pulls"
cd "$T/proj" && echo more >>README.md && git commit -qam more && git tag -s v1.1 -m 1.1
dev publish >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
cd "$T/c1" && usr pull --yes >"$T/pull" 2>&1 || { cat "$T/pull"; fail pull; }
grep -q "v1.1" "$T/pull" && [ "$(git -C "$T/c1" log -1 --format=%s)" = more ] && ok "pulled update (only the new segment downloaded)"
N=$(ls "$T/mirror/blobs" | wc -l); ok "mirror holds $N blobs"

echo "== attack: moving a published tag is refused at publish time"
cd "$T/proj" && V10=$(git rev-parse v1.0) && git tag -f -s v1.0 -m evil HEAD >/dev/null 2>&1
if dev publish 2>"$T/err"; then fail "tag move published"; fi
grep -q immutable "$T/err" && ok "tag move refused"
git update-ref refs/tags/v1.0 "$V10"

echo "== unsigned tag when policy requires signed tags"
cd "$T/proj" && git tag v1.2-unsigned
if dev publish 2>"$T/err"; then fail "unsigned tag published"; fi
grep -q "unsigned but the project requires" "$T/err" && ok "publisher refuses refs every client would reject"
git tag -d v1.2-unsigned >/dev/null

echo "== attack: tampered mirror data"
cd "$T"
SEG=$(grep -l "^# v[23] git bundle" "$T"/mirror/blobs/* | head -1 | xargs basename)
cp "$T/mirror/blobs/$SEG" "$T/seg.bak" && printf 'X' | dd of="$T/mirror/blobs/$SEG" bs=1 seek=100 conv=notrunc 2>/dev/null
if GITSEED_HOME=$T/usr2 GITSEED_MIRRORS=$T/mirror "$BIN" clone "$ADDR" c2 --trust-new-key >"$T/err" 2>&1; then fail "tampered data accepted"; fi
grep -q "corrupt" "$T/err" && ok "tampered segment rejected"
MAN=$(python3 -c "import json;print(json.load(open('$T/mirror/index.json'))['projects'][0]['manifest'])")
cp "$T/mirror/blobs/$MAN" "$T/man.bak" && sed -i 's/demo project/hacked project/' "$T/mirror/blobs/$MAN"
if GITSEED_HOME=$T/usr3 GITSEED_MIRRORS=$T/mirror "$BIN" clone "$ADDR" c3 --trust-new-key >"$T/err" 2>&1; then fail "tampered manifest accepted"; fi
grep -q "hash mismatch\|corrupt" "$T/err" && ok "tampered manifest rejected"
cp "$T/man.bak" "$T/mirror/blobs/$MAN"
cp "$T/seg.bak" "$T/mirror/blobs/$SEG"

echo "== attack: impostor republishes the same code under their key"
GITSEED_HOME=$T/evil "$BIN" keygen >/dev/null
git clone -q "$T/proj" "$T/evilproj" && cd "$T/evilproj" && git commit -q --allow-empty -m backdoor
GITSEED_HOME=$T/evil "$BIN" init --name demo --description "demo project (official!)" >/dev/null
GITSEED_HOME=$T/evil "$BIN" publish --yes-forever >"$T/evil.out" 2>&1
EADDR=$(grep -o "gitseed://[0-9a-f]*/demo" "$T/evil.out" | head -1)
GITSEED_HOME=$T/evil "$BIN" export "$T/evilmirror" >/dev/null
cd "$T" && GITSEED_HOME=$T/usr GITSEED_MIRRORS=$T/evilmirror "$BIN" import "$T/evilmirror" >/dev/null
usr verify "$ADDR" >"$T/v2" 2>&1 || true
grep -q "OTHER PUBLISHERS" "$T/v2" && ok "impostor listed as another publisher, not the author"
GITSEED_HOME=$T/usr "$BIN" search demo >"$T/search"; head -1 "$T/search" | grep -q "\[trusted\]" && ok "search ranks the trusted author first"
set +e; GITSEED_HOME=$T/fresh GITSEED_MIRRORS=$T/evilmirror "$BIN" verify "$EADDR" >/dev/null 2>&1; rc=$?; set -e
[ $rc = 3 ] && ok "unknown publisher: verify exits 3 (authorship unproven)"

echo "== identity proof served by the author's website"
WPORT=$((20000 + RANDOM % 20000))
mkdir -p "$T/www/.well-known" && dev whoami | awk '/^key/{print "gitseed key: "$2}' >"$T/www/.well-known/gitseed"
(cd "$T/www" && exec python3 -m http.server "$WPORT" --bind 127.0.0.1 >/dev/null 2>&1) & PIDS+=($!)
sleep 1
cd "$T/proj" && sed -i "s#^proofs = \[\]#proofs = [\"http://127.0.0.1:$WPORT/.well-known/gitseed\"]#" .gitseed
dev publish >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
cd "$T/c1" && usr pull --yes >/dev/null 2>&1
usr verify "$ADDR" --ref v1.1 >"$T/v3" 2>&1; grep -q "AUTHOR .*✔ VERIFIED" "$T/v3" && grep -q "v1.1 .*VERIFIED" "$T/v3" && ok "author proven by their website; v1.1 VERIFIED"

echo "== release with files"
cd "$T/proj" && echo rel >>README.md && git commit -qam rel && echo binary >"$T/app-1.3.tar.gz"
dev release v1.3 "$T/app-1.3.tar.gz" >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
usr verify "$ADDR" --ref v1.3 >"$T/v4" 2>&1; grep -q "└ app-1.3.tar.gz" "$T/v4" && ok "release file listed under its release with its pinned sha256"
usr verify-file "$ADDR" "$T/app-1.3.tar.gz" >"$T/vf"; grep -q "MATCHES app-1.3.tar.gz of release v1.3" "$T/vf" && grep -q "signed tag v1.3 lists this file" "$T/vf" && ok "downloaded release binary verified (listed in the signed tag)"
echo tampered >"$T/fake.tar.gz"; usr verify-file "$ADDR" "$T/fake.tar.gz" >/dev/null && fail "fake binary accepted" || ok "tampered binary rejected"

echo "== second maintainer publishes"
GITSEED_HOME=$T/bob "$BIN" keygen >/dev/null
BOB=$(GITSEED_HOME=$T/bob "$BIN" whoami | awk '/^key/{print $2}')
cd "$T/proj" && dev maintainer add "$BOB" --label bob >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
git clone -q "$T/proj" "$T/bobproj" && cd "$T/bobproj" && git checkout -q main
cp "$T/proj/.gitseed" . && grep -q "^address = \"$ADDR\"" .gitseed  # the shared .gitseed carries the address
echo bob >>README.md && git commit -qam "bob's fix"
GITSEED_HOME=$T/bob GITSEED_MIRRORS=$T/mirror "$BIN" publish >"$T/bob.out" 2>&1 || { cat "$T/bob.out"; fail "bob publish"; }
GITSEED_HOME=$T/bob GITSEED_MIRRORS=$T/mirror "$BIN" export "$T/mirror" >/dev/null
cd "$T/c1" && usr pull --yes >"$T/pull3" 2>&1 || { cat "$T/pull3"; fail "pull bob"; }
grep -q "maintainer ADDED: .*bob" "$T/pull3" && [ "$(git log -1 --format=%s)" = "bob's fix" ] && ok "user saw 'maintainer added' and got bob's commit"
grep -q "bob's fix" "$T/pull3" && ok "pull lists the new commits"

echo "== a release file added to an existing release is flagged"
cd "$T/bobproj" && echo extra >"$T/extra.bin"
GITSEED_HOME=$T/bob GITSEED_MIRRORS=$T/mirror "$BIN" release v1.3 "$T/extra.bin" >/dev/null 2>&1 && GITSEED_HOME=$T/bob GITSEED_MIRRORS=$T/mirror "$BIN" export "$T/mirror" >/dev/null
cd "$T/c1"; if usr pull </dev/null >"$T/pull5" 2>&1; then fail "added release file accepted silently"; fi
grep -q "ADDED to v1.3" "$T/pull5" && ok "user is asked about a file added to v1.3 after the fact"
usr pull --yes >/dev/null 2>&1

echo "== scoped CI key cannot touch branches"
GITSEED_HOME=$T/ci "$BIN" keygen >/dev/null
CI=$(GITSEED_HOME=$T/ci "$BIN" whoami | awk '/^key/{print $2}')
cd "$T/proj" && git pull -q "$T/bobproj" main && dev maintainer add "$CI" --label ci --scope 'refs/tags/v*' >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
git clone -q "$T/proj" "$T/ciproj" && cd "$T/ciproj" && git checkout -q main && echo ci >>README.md && git commit -qam "ci tries main"
GITSEED_HOME=$T/ci "$BIN" init --address "$ADDR" --include main --include 'v*' >/dev/null
if GITSEED_HOME=$T/ci GITSEED_MIRRORS=$T/mirror "$BIN" publish >"$T/ci.out" 2>&1; then fail "scoped key moved main"; fi
grep -q "may only change refs/tags/v\*" "$T/ci.out" && ok "CI key refused to move main"

echo "== lost laptop: root key rotation"
cd "$T/proj" && git pull -q "$T/bobproj" main
dev rotate >"$T/rot" 2>&1 || { cat "$T/rot"; fail rotate; }
echo after-rotation >>README.md && git commit -qam after-rotation
dev publish >"$T/pub2" 2>&1 || { cat "$T/pub2"; fail "publish after rotation"; }
dev export "$T/mirror" >/dev/null
cd "$T/c1" && usr pull --yes >"$T/pull4" 2>&1 || { cat "$T/pull4"; fail "pull after rotation"; }
grep -q "ROTATED" "$T/pull4" && [ "$(git log -1 --format=%s)" = after-rotation ] && ok "same address keeps working; user was told the root key rotated"
usr verify "$ADDR" >"$T/v5" 2>&1; grep -q "still lists the OLD" "$T/v5" && ok "proof page still naming the rotated-away key is flagged"
dev whoami | awk '/^key/{print "gitseed key: "$2}' >"$T/www/.well-known/gitseed"
usr verify "$ADDR" >"$T/v6" 2>&1; grep -q "AUTHOR .*✔ VERIFIED" "$T/v6" && ok "identity VERIFIED again once the author updates the proof page"

echo "== attack: re-publish an old signed tag under a new name (downgrade)"
cd "$T/proj" && git update-ref refs/tags/v9.9 "$(git rev-parse v1.0)"
dev publish >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
usr verify "$ADDR" --ref v9.9 >"$T/v7" 2>&1 || true
grep -q "v9.9.*FAIL.*re-published under another name" "$T/v7" && ok "renamed tag rejected (FAIL)"
git tag -d v9.9 >/dev/null && dev publish --force >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null

echo "== developer safety: a checkout missing published refs can't silently drop them"
git clone -q "$T/proj" "$T/partial" && cd "$T/partial" && git tag -d v1.0 >/dev/null && cp "$T/proj/.gitseed" .
if dev publish >"$T/drop" 2>&1; then fail "refs dropped silently"; fi
grep -q "REMOVE published refs" "$T/drop" && ok "publishing from a partial checkout is refused"

echo "== a history rewrite still produces a clonable snapshot"
cd "$T/proj" && echo same-content >shared.txt && git add shared.txt && git commit -qm "add shared" && dev publish >/dev/null 2>&1
git reset -q --hard HEAD~1 && echo same-content >shared.txt && echo more >other.txt && git add . && git commit -qm "rewritten" && dev publish --force >/dev/null 2>&1 && dev export "$T/mirror" >/dev/null
GITSEED_HOME=$T/fresh2 GITSEED_MIRRORS=$T/mirror "$BIN" clone "$ADDR" "$T/c9" --trust-new-key >"$T/c9.out" 2>&1 && [ -f "$T/c9/other.txt" ] && ok "fresh user can clone after a rewrite" || { cat "$T/c9.out"; fail "clone after rewrite"; }

echo "== a clone never silently becomes a new project"
GITSEED_HOME=$T/usr "$BIN" keygen >/dev/null
cd "$T/c1" && if usr publish --yes-forever >"$T/np" 2>&1; then fail "clone published as a new project"; fi
grep -q "you cannot publish to $ADDR" "$T/np" && ok "non-maintainer clone refused (use --fork for your own copy)"
usr publish --fork --yes-forever >"$T/fork" 2>&1 && grep -q "published gitseed://" "$T/fork" && ! grep -q "$ADDR" "$T/fork" && ok "--fork publishes your own copy under your key"

echo "== static site and plain-file mirror"
[ -f "$T/mirror/index.html" ] && grep -q "discovery only" "$T/mirror/index.html" && ok "static site has untrusted-mirror banner"

echo "== hoster: rules + gc"
GITSEED_HOME=$T/host GITSEED_MIRRORS=$T/mirror "$BIN" seed add "$ADDR" --refs main --tags latest:1 >/dev/null
GITSEED_HOME=$T/host GITSEED_MIRRORS=$T/mirror "$BIN" seed once >"$T/host.out" 2>&1 || { cat "$T/host.out"; fail "seed once"; }
grep -q "demo: ✔" "$T/host.out" && ok "hoster fetched selected refs"
B1=$(du -s "$T/host/blobs" | cut -f1)
GITSEED_HOME=$T/host "$BIN" block "$ADDR" >/dev/null
B2=$(du -s "$T/host/blobs" | cut -f1)
[ "$B2" -lt "$B1" ] && ! GITSEED_HOME=$T/host "$BIN" export "$T/hostmirror" 2>/dev/null | grep -q demo && ok "block frees the data and drops it from the mirror"
GITSEED_HOME=$T/host "$BIN" seed rss | grep -q "magnet:" && ok "rss feed for plain torrent clients"
echo "ALL PASSED"
