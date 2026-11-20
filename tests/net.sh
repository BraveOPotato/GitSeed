#!/usr/bin/env bash
# Transport tests: BitTorrent swarm, HTTP mirror of a running seeder, git remote helper,
# and (with INTERNET=1) the public Mainline DHT. Run: tests/net.sh [path/to/gitseed]
set -euo pipefail
BIN=$(realpath "${1:-target/debug/gitseed}")
T=$(mktemp -d)
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill $p 2>/dev/null || true; done; [ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
echo "tmp: $T"
export GIT_AUTHOR_NAME=dev GIT_AUTHOR_EMAIL=dev@x GIT_COMMITTER_NAME=dev GIT_COMMITTER_EMAIL=dev@x GIT_CONFIG_GLOBAL=/dev/null GITSEED_SWARM_TIMEOUT=60
ok() { echo "  ✔ $*"; }
fail() { echo "  ✖ $*"; exit 1; }
PORT=$((20000 + RANDOM % 20000)); WEB=$((PORT + 1))

echo "== developer publishes and starts seeding (BitTorrent :$PORT, HTTP :$WEB)"
mkdir -p "$T/dev"
printf 'port = %s\ndht = false\n' "$PORT" >"$T/dev/config.toml"
printf 'listen = "127.0.0.1:%s"\ninterval_minutes = 60\n' "$WEB" >"$T/dev/seed.toml"
export GITSEED_HOME=$T/dev
"$BIN" keygen >/dev/null
mkdir "$T/proj" && cd "$T/proj" && git init -q -b main
head -c 3000000 /dev/urandom | base64 >big.txt && echo hi >README.md && git add . && git commit -qm init
"$BIN" init --name nettest --description "transport test" >/dev/null
"$BIN" publish --yes-forever >"$T/pub" 2>&1 || { cat "$T/pub"; fail publish; }
ADDR=$(grep -o 'gitseed://[0-9a-f]*/nettest' "$T/pub" | head -1)
"$BIN" seed >"$T/seed.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$WEB/index.json" >/dev/null && break; sleep 0.5; done
curl -sf "http://127.0.0.1:$WEB/index.json" >/dev/null && ok "seeder up"
sleep 2
unset GITSEED_HOME

echo "== user over HTTP mirror (the seeder doubles as a webseed)"
GITSEED_HOME=$T/u1 GITSEED_NO_DHT=1 GITSEED_MIRRORS=http://127.0.0.1:$WEB "$BIN" clone "$ADDR" "$T/c1" --trust-new-key >"$T/c1.out" 2>&1 || { cat "$T/c1.out"; fail "http clone"; }
cmp -s "$T/proj/big.txt" "$T/c1/big.txt" && ok "cloned over HTTP"

echo "== user over the BitTorrent swarm (only signed docs from a mirror, data from peers)"
mkdir -p "$T/docs/blobs"
curl -sf "http://127.0.0.1:$WEB/index.json" >"$T/docs/index.json"
python3 - "$T/docs/index.json" "$T/dev/blobs" "$T/docs/blobs" <<'EOF'
import json, shutil, sys
idx = json.load(open(sys.argv[1]))
for p in idx["projects"]:
    for d in [p["policy"], p["manifest"]]:
        shutil.copy(f"{sys.argv[2]}/{d}", f"{sys.argv[3]}/{d}")
EOF
GITSEED_HOME=$T/u2 GITSEED_NO_DHT=1 GITSEED_MIRRORS=$T/docs GITSEED_PEERS=127.0.0.1:$PORT "$BIN" clone "$ADDR" "$T/c2" --trust-new-key >"$T/c2.out" 2>&1 || { cat "$T/c2.out"; tail -20 "$T/seed.log"; fail "swarm clone"; }
cmp -s "$T/proj/big.txt" "$T/c2/big.txt" && ok "cloned over BitTorrent"

echo "== git remote helper: plain 'git clone' and 'git push'"
mkdir -p "$T/bin" && ln -sf "$BIN" "$T/bin/git-remote-gitseed"
PATH=$T/bin:$PATH GITSEED_HOME=$T/u1 GITSEED_NO_DHT=1 GITSEED_MIRRORS=http://127.0.0.1:$WEB git clone -q "$ADDR" "$T/c3" 2>"$T/c3.err" || { cat "$T/c3.err"; fail "git clone"; }
[ -f "$T/c3/README.md" ] && ok "git clone gitseed://… works"
cd "$T/proj" && echo pushed >>README.md && git commit -qam pushed
PATH=$T/bin:$PATH GITSEED_HOME=$T/dev GITSEED_NO_DHT=1 git push -q "$ADDR" main 2>"$T/push.err" || { cat "$T/push.err"; fail "git push"; }
grep -q "published" "$T/push.err" && ok "git push gitseed://… publishes"
cd "$T/c3" && PATH=$T/bin:$PATH GITSEED_HOME=$T/u1 GITSEED_NO_DHT=1 GITSEED_MIRRORS=http://127.0.0.1:$WEB git pull -q 2>"$T/pull.err" || { cat "$T/pull.err"; fail "git pull"; }
[ "$(git log -1 --format=%s)" = pushed ] && ok "git pull sees the pushed commit"

echo "== web UI"
curl -sf "http://127.0.0.1:$WEB/" | grep -q nettest && ok "search page lists project"
curl -sf -H "Host: 127.0.0.1:$WEB" "http://127.0.0.1:$WEB/p/$(echo "$ADDR" | sed 's#gitseed://##; s#/#.#').html" | grep -q "Releases, tags" && ok "project page renders"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Host: evil.example:$WEB" -H "x-gitseed-token: x" --data "$ADDR" "http://127.0.0.1:$WEB/api/follow")
[ "$code" = 403 ] && ok "cross-site / DNS-rebinding request refused"

if [ -n "${INTERNET:-}" ]; then
  echo "== public Mainline DHT (internet)"
  printf 'port = %s\n' "$PORT" >"$T/dev/config.toml"
  GITSEED_HOME=$T/dev "$BIN" seed once >"$T/dht.out" 2>&1 || { cat "$T/dht.out"; fail "republish"; }
  grep -q "republished: [1-9]" "$T/dht.out" || { cat "$T/dht.out"; fail "dht put"; }
  ok "$(grep republished "$T/dht.out")"
  GITSEED_HOME=$T/u4 GITSEED_PEERS=127.0.0.1:$PORT "$BIN" verify "$ADDR" >"$T/dht.v" 2>&1 || { cat "$T/dht.v"; fail "dht resolve"; }
  grep -q "RESULT: OK" "$T/dht.v" && ok "fresh client resolved the project from the DHT alone (no mirror)"
fi
echo "ALL PASSED"
