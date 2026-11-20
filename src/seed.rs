//! Hosting: which projects/refs to seed (seed.toml), quotas, gc, health, and the daemon loop.
use crate::core::*;
use crate::net::{self, Net};
use crate::ops;
use crate::trust;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Rule {
    /// Branch/tag patterns to keep, e.g. ["main", "release/*"]. "*" = all branches.
    pub refs: Vec<String>,
    /// "all" | "none" | "latest:N" | a glob like "v2.*"
    pub tags: String,
    /// Also keep release files (assets).
    pub assets: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Rule { refs: vec!["*".into()], tags: "all".into(), assets: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Follow {
    pub address: String,
    #[serde(flatten)]
    pub rule: Option<Rule>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct SeedConfig {
    /// Stop fetching when the store would exceed this, e.g. "400GiB".
    pub disk_quota: String,
    /// Refuse any single project larger than this.
    pub max_repo: String,
    /// How often to check for updates and republish DHT records.
    pub interval_minutes: u64,
    /// HTTP mirror + local web UI. Use "0.0.0.0:7878" to also be a public webseed.
    pub listen: String,
    pub defaults: Rule,
    pub follow: Vec<Follow>,
}

impl Default for SeedConfig {
    fn default() -> Self {
        SeedConfig { disk_quota: "50GiB".into(), max_repo: "5GiB".into(), interval_minutes: 30, listen: "127.0.0.1:7878".into(), defaults: Rule::default(), follow: vec![] }
    }
}

pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mul) = [("TiB", 1u64 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10), ("TB", 1_000_000_000_000), ("GB", 1_000_000_000), ("MB", 1_000_000), ("B", 1)]
        .iter()
        .find_map(|(u, m)| s.strip_suffix(u).map(|n| (n.trim(), *m)))
        .unwrap_or((s, 1));
    Ok((num.parse::<f64>().with_context(|| format!("bad size {s}"))? * mul as f64) as u64)
}

impl SeedConfig {
    pub fn path() -> std::path::PathBuf {
        home().join("seed.toml")
    }
    pub fn load() -> Result<Self> {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", Self::path().display())),
            Err(_) => Ok(Self::default()),
        }
    }
    pub fn save(&self) -> Result<()> {
        std::fs::write(Self::path(), toml::to_string_pretty(self)?)?;
        Ok(())
    }
    pub fn rule_for(&self, a: &Address) -> Option<Rule> {
        self.follow.iter().find(|f| f.address == a.to_string()).map(|f| f.rule.clone().unwrap_or_else(|| self.defaults.clone()))
    }
}

pub fn ensure_followed(a: &Address) -> Result<()> {
    let mut c = SeedConfig::load()?;
    if c.rule_for(a).is_none() {
        c.follow.push(Follow { address: a.to_string(), rule: None });
        c.save()?;
    }
    Ok(())
}

// ---------- blocklist (honour a takedown request for ONE repo without quitting) ----------

pub fn blocked() -> BTreeSet<String> {
    std::fs::read_to_string(home().join("blocked.txt")).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
}

pub fn block(a: &Address, on: bool) -> Result<()> {
    let mut b = blocked();
    if on {
        b.insert(a.to_string());
    } else {
        b.remove(&a.to_string());
    }
    std::fs::write(home().join("blocked.txt"), b.into_iter().collect::<Vec<_>>().join("\n") + "\n")?;
    if on {
        let mut c = SeedConfig::load()?;
        c.follow.retain(|f| f.address != a.to_string());
        c.save()?;
        // forget it entirely: pin, cache repo and catalog entry (gc then deletes its data)
        let _ = std::fs::remove_file(pin_path(a));
        let _ = std::fs::remove_dir_all(ops::cache_dir(a));
        let mut cat = Catalog::load();
        cat.entries.remove(&a.to_string());
        cat.save()?;
    }
    Ok(())
}

// ---------- catalog: projects known from indexes (not trusted, just known) ----------

#[derive(Serialize, Deserialize, Default)]
pub struct Catalog {
    pub entries: BTreeMap<String, CatEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CatEntry {
    pub policy: String,
    pub manifest: String,
    pub source: String,
    pub seen: i64,
}

impl Catalog {
    pub fn load() -> Self {
        read_json(&home().join("catalog.json")).ok().flatten().unwrap_or_default()
    }
    pub fn save(&self) -> Result<()> {
        write_json(&home().join("catalog.json"), self)
    }
    pub fn add(&mut self, a: &Address, policy: &str, manifest: &str, source: &str) {
        let newer = self.entries.get(&a.to_string()).and_then(|e| get_doc::<Manifest>(&e.manifest).ok()).map(|m| m.seq);
        let this = get_doc::<Manifest>(manifest).ok().map(|m| m.seq);
        if newer.is_none() || this > newer {
            self.entries.insert(a.to_string(), CatEntry { policy: policy.into(), manifest: manifest.into(), source: source.into(), seen: now_us() });
        }
    }
}

/// Everything searchable locally: pinned projects + catalog.
pub fn known_projects() -> Vec<(Address, Manifest)> {
    let mut out: BTreeMap<String, (Address, Manifest)> = BTreeMap::new();
    for (k, e) in Catalog::load().entries {
        if let (Ok(a), Ok(m)) = (Address::parse(&k), get_doc::<Manifest>(&e.manifest)) {
            out.insert(k, (a, m));
        }
    }
    for (a, p) in all_pins() {
        if let Some(m) = p.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok()) {
            out.insert(a.to_string(), (a, m));
        }
    }
    let b = blocked();
    out.into_values().filter(|(a, _)| !b.contains(&a.to_string())).collect()
}

/// (trusted on this machine, first time this machine saw the key). Impostors are usually seen later.
pub fn standing(a: &Address) -> (bool, i64) {
    match load_pin(a).ok().flatten() {
        Some(p) => (p.trusted, p.pinned_at),
        None => (false, Catalog::load().entries.get(&a.to_string()).map(|e| e.seen).unwrap_or(i64::MAX)),
    }
}

/// Ranked by trust, then by who this machine saw first — never by recency or claims (both are free to fake).
pub fn search(q: &str) -> Vec<(Address, Manifest)> {
    let q = q.to_lowercase();
    let mut v: Vec<(Address, Manifest)> = known_projects()
        .into_iter()
        .filter(|(a, m)| q.split_whitespace().all(|w| format!("{} {} {} {}", a.name, m.description, m.topics.join(" "), m.readme).to_lowercase().contains(w)))
        .collect();
    v.sort_by_key(|(a, _)| {
        let (t, seen) = standing(a);
        (!t, seen)
    });
    v
}

// ---------- selection ----------

/// The refs a rule selects from a manifest.
pub fn select(m: &Manifest, r: &Rule) -> Vec<String> {
    let mut out: Vec<String> = m.refs.keys().filter(|n| n.starts_with("refs/heads/") && r.refs.iter().any(|p| crate::git::glob(&format!("refs/heads/{}", p.trim_start_matches("refs/heads/")), n))).cloned().collect();
    let mut tags: Vec<&String> = m.refs.keys().filter(|n| n.starts_with("refs/tags/")).collect();
    tags.sort_by(|a, b| crate::trust::version_cmp(a, b));
    let chosen: Vec<&String> = match r.tags.as_str() {
        "all" => tags,
        "none" => vec![],
        t if t.starts_with("latest:") => {
            let n: usize = t[7..].parse().unwrap_or(1);
            tags.into_iter().rev().take(n).collect()
        }
        glob => tags.into_iter().filter(|t| crate::git::glob(&format!("refs/tags/{glob}"), t)).collect(),
    };
    out.extend(chosen.into_iter().cloned());
    out
}

/// Minimum a follower keeps so the project survives: the default branch now, the first-ever
/// snapshot (so an "empty update" can't erase history), and every signed document.
pub fn survival_floor(p: &Pin) -> BTreeSet<String> {
    let mut keep = BTreeSet::new();
    keep.insert(p.policy.clone());
    for (i, h) in p.history.iter().enumerate() {
        keep.insert(h.clone());
        if let Ok(m) = get_doc::<Manifest>(h) {
            keep.insert(m.policy.clone());
            let latest = Some(h) == p.manifest.as_ref();
            if i == 0 || latest {
                let def: Vec<String> = ["refs/heads/main", "refs/heads/master"].iter().filter(|r| m.refs.contains_key(**r)).map(|s| s.to_string()).take(1).collect();
                let refs = if i == 0 { m.refs.keys().cloned().collect() } else { def };
                keep.extend(m.segs_for(&refs).iter().map(|s| s.blob.sha256.clone()));
            }
        }
    }
    keep
}

/// Blobs a follow rule wants for the latest snapshot (on top of the floor).
pub fn wanted(m: &Manifest, r: &Rule) -> Vec<Blob> {
    let refs = select(m, r);
    let mut v: Vec<Blob> = m.segs_for(&refs).into_iter().map(|s| s.blob.clone()).collect();
    if r.assets {
        // release files follow the tag selection
        v.extend(m.assets.iter().filter(|a| a.tag.is_empty() || refs.contains(&format!("refs/tags/{}", a.tag))).map(|a| a.blob.clone()));
    }
    v
}

/// Signed docs belonging to blocked projects (so gc removes those too).
fn blocked_docs(blocked: &BTreeSet<String>) -> BTreeSet<String> {
    let mut v = BTreeSet::new();
    if blocked.is_empty() {
        return v;
    }
    for e in std::fs::read_dir(home().join("blobs")).into_iter().flatten().flatten() {
        if let Ok(b) = std::fs::read(e.path()) {
            if b.first() == Some(&b'{') {
                if let Ok(x) = serde_json::from_slice::<serde_json::Value>(&b) {
                    let (root, name) = (x["root"].as_str().unwrap_or(""), x["name"].as_str().unwrap_or(""));
                    if blocked.contains(&format!("gitseed://{root}/{name}")) || blocked.iter().any(|a| a.ends_with(&format!("/{name}")) && Address::parse(a).is_ok_and(|a| a.root == root)) {
                        v.insert(e.file_name().to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    v
}

pub fn warn_over_quota() {
    if let Ok(c) = SeedConfig::load() {
        if parse_size(&c.disk_quota).is_ok_and(|q| store_usage() > q) {
            println!("⚠ store {} is over disk_quota {}: only data protected by the survival floor remains; unfollow something or raise the quota", ops::human(store_usage()), c.disk_quota);
        }
    }
}

pub fn store_usage() -> u64 {
    std::fs::read_dir(home().join("blobs")).map(|rd| rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()).unwrap_or(0)
}

/// Delete blobs no followed project (or own project) needs. Returns bytes freed.
pub fn gc(dry_run: bool) -> Result<u64> {
    let cfg = SeedConfig::load()?;
    let mut keep = BTreeSet::new();
    let blocked = blocked();
    for (a, p) in all_pins() {
        if blocked.contains(&a.to_string()) {
            continue;
        }
        keep.extend(survival_floor(&p));
        if let (Some(rule), Some(m)) = (cfg.rule_for(&a), p.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok())) {
            keep.extend(wanted(&m, &rule).into_iter().map(|b| b.sha256));
        }
    }
    for (k, e) in Catalog::load().entries {
        if !blocked.contains(&k) {
            keep.insert(e.policy.clone());
            keep.insert(e.manifest.clone());
        }
    }
    let mut freed = 0;
    for e in std::fs::read_dir(home().join("blobs"))?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // ponytail: small signed JSON docs (policies/manifests) are always kept; they're tiny and re-fetched otherwise
        let small_doc = e.metadata().is_ok_and(|m| m.len() < 1 << 20) && std::fs::read(e.path()).is_ok_and(|b| b.first() == Some(&b'{'));
        if !keep.contains(&name) && !(small_doc && !blocked_docs(&blocked).contains(&name)) {
            freed += e.metadata().map(|m| m.len()).unwrap_or(0);
            if !dry_run {
                std::fs::remove_file(e.path())?;
            }
        }
    }
    Ok(freed)
}

// ---------- one sync pass + the daemon ----------

pub struct SyncReport {
    /// project name -> one-line status
    pub status: BTreeMap<String, String>,
    pub seeding: Vec<String>,
    pub ok: bool,
}

pub async fn sync_once(net: &Net, dry_run: bool) -> Result<SyncReport> {
    let cfg = SeedConfig::load()?;
    let quota = parse_size(&cfg.disk_quota)?;
    let max_repo = parse_size(&cfg.max_repo)?;
    let blocked = blocked();
    let mut status = BTreeMap::new();
    let mut ok = true;
    let mut seeding = BTreeSet::new();
    let mut used = store_usage();
    for f in &cfg.follow {
        let Ok(a) = Address::parse(&f.address) else { continue };
        if blocked.contains(&f.address) {
            continue;
        }
        let mut say = |s: String, good: bool| {
            ok &= good;
            status.insert(a.name.clone(), s);
        };
        let rule = f.rule.clone().unwrap_or_else(|| cfg.defaults.clone());
        match trust::resolve(net, &a).await {
            Err(e) => say(format!("✖ {e:#}"), false),
            Ok(r) if !r.failures.is_empty() => say(format!("✖ NOT updating (keeping what we have): {}", r.failures.join("; ")), false),
            Ok(mut r) => {
                if let Some(m) = r.manifest.clone() {
                    let want = wanted(&m, &rule);
                    let total: u64 = want.iter().map(|b| b.size).sum();
                    let missing: Vec<&Blob> = want.iter().filter(|b| !has_blob(&b.sha256)).collect();
                    let need: u64 = missing.iter().map(|b| b.size).sum();
                    if total > max_repo {
                        say(format!("✖ skipped: selected data is {} but max_repo = {}", ops::human(total), cfg.max_repo), false);
                    } else if dry_run {
                        say(format!("• would keep {} refs ({}), fetch {}", select(&m, &rule).len(), ops::human(total), ops::human(need)), true);
                    } else {
                        if used + need > quota && need > 0 {
                            used -= gc(false).unwrap_or(0).min(used); // free unreferenced data first
                        }
                        if used + need > quota && need > 0 {
                            say(format!("✖ needs {} to download but only {} of disk_quota {} is free (short {})", ops::human(need), ops::human(quota.saturating_sub(used)), cfg.disk_quota, ops::human(used + need - quota)), false);
                        } else {
                            let mut err = None;
                            for b in &missing {
                                if let Err(e) = net.fetch(b, &m.webseeds).await {
                                    err = Some(format!("{e:#}"));
                                    break;
                                }
                                used += b.size;
                            }
                            match err {
                                Some(e) => say(format!("✖ {e}"), false),
                                None => {
                                    r.accept(false)?;
                                    say(format!("✔ {} refs, {} ({}){}", select(&m, &rule).len(), ops::human(total), fmt_age(m.seq), if need > 0 { format!(", fetched {}", ops::human(need)) } else { String::new() }), true);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Ok(Some(p)) = load_pin(&a) {
            let mut keep = survival_floor(&p);
            if let Some(m) = p.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok()) {
                keep.extend(wanted(&m, &rule).into_iter().map(|b| b.sha256));
            }
            seeding.extend(keep.into_iter().filter(|s| has_blob(s)));
        }
    }
    Ok(SyncReport { status, seeding: seeding.into_iter().collect(), ok })
}

fn fmt_age(us: i64) -> String {
    let h = (now_us() - us) / 3_600_000_000;
    if h < 48 { format!("updated {h}h ago") } else { format!("updated {}d ago", h / 24) }
}

pub async fn republish(net: &Net) -> (usize, usize) {
    let (mut ok, mut fail) = (0, 0);
    let blocked = blocked();
    for r in net::all_records() {
        let skip = blocked.iter().any(|b| Address::parse(b).is_ok_and(|a| r.k == a.root));
        if skip || r.verify().is_err() {
            continue;
        }
        match net.dht_put(&r).await {
            Ok(()) => ok += 1,
            Err(_) => fail += 1,
        }
    }
    (ok, fail)
}

fn log(s: &str) {
    eprintln!("{} {s}", ops::fmt_time(now_us()).trim_end_matches(" UTC"));
}

pub fn last_status() -> BTreeMap<String, String> {
    read_json::<serde_json::Value>(&home().join("health.json"))
        .ok()
        .flatten()
        .and_then(|v| v.get("projects").cloned())
        .and_then(|p| serde_json::from_value(p).ok())
        .unwrap_or_default()
}

pub async fn daemon(net: std::sync::Arc<Net>) -> Result<()> {
    let cfg = SeedConfig::load()?;
    let listen = cfg.listen.clone();
    let n2 = net.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::web::serve(n2, &listen).await {
            log(&format!("web: {e:#}"));
        }
    });
    let swarm = net.swarm().await?;
    log(&format!("gitseed seeding · BitTorrent port {:?} · web/mirror http://{} · DHT {}", swarm.announce_port(), cfg.listen, if net.cfg.dht_on() { "on" } else { "off" }));
    let mut seeded: BTreeSet<String> = BTreeSet::new();
    let mut last: BTreeMap<String, String> = BTreeMap::new();
    let mut last_ok = 0i64;
    let mtime = || std::fs::metadata(SeedConfig::path()).and_then(|m| m.modified()).ok();
    loop {
        let seen_mtime = mtime();
        match sync_once(&net, false).await {
            Err(e) => {
                let msg = format!("{e:#}").replace('\n', " ");
                log(&format!("✖ config/sync error (will retry): {msg}"));
                let _ = write_json(&home().join("health.json"), &serde_json::json!({"ok": false, "error": msg, "last_ok": last_ok, "at": now_us(), "seeding": seeded.len(), "bytes": store_usage(), "projects": last}));
            }
            Ok(rep) => {
                for (name, l) in &rep.status {
                    if last.get(name) != Some(l) {
                        log(&format!("{name}: {l}"));
                    }
                }
                last = rep.status.clone();
                let want: BTreeSet<String> = rep.seeding.iter().cloned().collect();
                for s in &want {
                    if !seeded.contains(s) {
                        match net.seed(s).await {
                            Ok(()) => {
                                seeded.insert(s.clone());
                            }
                            Err(e) => log(&format!("seed {}: {e:#}", &s[..12])),
                        }
                    }
                }
                // stop seeding what is no longer wanted (unfollowed, blocked, evicted)
                for s in seeded.clone().difference(&want) {
                    if let Ok(path) = std::fs::metadata(blob_path(s)).map(|_| blob_path(s)) {
                        if let Ok((ih, _)) = net::torrent_for(&path, s) {
                            net.unseed(&ih).await;
                        }
                    }
                    seeded.remove(s);
                }
                let freed = gc(false).unwrap_or(0);
                if let Ok(c) = SeedConfig::load() {
                    if parse_size(&c.disk_quota).is_ok_and(|q| store_usage() > q) {
                        log(&format!("⚠ store {} is over disk_quota {}: only data protected by the survival floor remains; unfollow something or raise the quota", ops::human(store_usage()), c.disk_quota));
                    }
                }
                let (ok, fail) = if net.cfg.dht_on() { republish(&net).await } else { (0, 0) };
                if rep.ok {
                    last_ok = now_us();
                }
                log(&format!("seeding {} files · {}{}{}", seeded.len(), ops::human(store_usage()), if freed > 0 { format!(" · gc freed {}", ops::human(freed)) } else { String::new() }, if net.cfg.dht_on() { format!(" · DHT records republished {ok} (failed {fail})") } else { String::new() }));
                let _ = write_json(&home().join("health.json"), &serde_json::json!({"ok": rep.ok, "last_ok": last_ok, "at": now_us(), "seeding": seeded.len(), "bytes": store_usage(), "projects": rep.status}));
            }
        }
        // sleep until the interval passes or seed.toml changes (e.g. `gitseed seed add`)
        let mins = SeedConfig::load().map(|c| c.interval_minutes).unwrap_or(30).max(1);
        for _ in 0..(mins * 6) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if mtime() != seen_mtime {
                log("seed.toml changed — syncing now");
                break;
            }
        }
    }
}

/// Copies of each followed project's critical pieces, fewest first.
pub async fn health(net: &Net) -> Result<Vec<(Address, usize, String)>> {
    let mut v = vec![];
    for (a, p) in all_pins() {
        let Some(m) = p.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok()) else { continue };
        let floor = survival_floor(&p);
        let mut min = usize::MAX;
        let mut worst = String::new();
        for s in m.segs.iter().filter(|s| floor.contains(&s.blob.sha256)) {
            let n = net.dht_peer_count(&s.blob.ih).await;
            if n < min {
                min = n;
                worst = s.blob.sha256[..12].to_string();
            }
        }
        if min == usize::MAX {
            min = 0;
        }
        v.push((a, min, worst));
    }
    v.sort_by_key(|x| x.1);
    Ok(v)
}

/// Follow the least-seeded known projects that fit in `budget`.
pub async fn adopt(net: &Net, budget: u64) -> Result<Vec<String>> {
    let cfg = SeedConfig::load()?;
    let mut cands = vec![];
    for (a, m) in known_projects() {
        if cfg.rule_for(&a).is_some() {
            continue;
        }
        let size: u64 = wanted(&m, &Rule { refs: vec!["main".into(), "master".into()], tags: "latest:1".into(), assets: false }).iter().map(|b| b.size).sum();
        let copies = match m.segs.first() {
            Some(s) => net.dht_peer_count(&s.blob.ih).await,
            None => continue,
        };
        cands.push((copies, size, a));
    }
    cands.sort_by_key(|c| (c.0, c.1));
    let mut used = 0;
    let mut out = vec![];
    let mut c = SeedConfig::load()?;
    for (copies, size, a) in cands {
        if used + size > budget {
            continue;
        }
        used += size;
        c.follow.push(Follow { address: a.to_string(), rule: Some(Rule { refs: vec!["main".into(), "master".into()], tags: "latest:1".into(), assets: false }) });
        out.push(format!("{} ({} copies, {})", a.name, copies, ops::human(size)));
    }
    c.save()?;
    Ok(out)
}

/// RSS feed of magnet links so plain BitTorrent clients (qBittorrent auto-downloader) can follow updates.
pub fn rss() -> Result<String> {
    let cfg = SeedConfig::load()?;
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let base = format!("http://{}", cfg.listen.replace("0.0.0.0", "127.0.0.1"));
    let mut items = String::new();
    for (a, p) in all_pins() {
        let Some(rule) = cfg.rule_for(&a) else { continue };
        let Some(m) = p.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok()) else { continue };
        let mut named: Vec<(String, Blob)> = vec![];
        for (i, sg) in m.segs.iter().enumerate() {
            named.push((format!("{} history part {}", a.name, i + 1), sg.blob.clone()));
        }
        for x in &m.assets {
            named.push((format!("{} release {} {}", a.name, x.tag, x.path), x.blob.clone()));
        }
        let want: BTreeSet<String> = wanted(&m, &rule).into_iter().map(|b| b.sha256).collect();
        for (title, b) in named.into_iter().filter(|(_, b)| want.contains(&b.sha256)) {
            let magnet = format!("magnet:?xt=urn:btih:{}&dn={}&ws={}/blobs/{}", b.ih, b.sha256, base, b.sha256);
            items.push_str(&format!("<item><title>{}</title><link>{}</link><guid>{}</guid><enclosure url=\"{}\" type=\"application/x-bittorrent\" length=\"{}\"/></item>\n", esc(&title), esc(&magnet), b.sha256, esc(&magnet), b.size));
        }
    }
    Ok(format!("<?xml version=\"1.0\"?>\n<rss version=\"2.0\"><channel><title>gitseed follows</title><link>{base}/</link><description>Files this gitseed host seeds. Downloaded files are named by sha256; adopt them with `gitseed seed import-blobs DIR`.</description>\n{items}</channel></rss>\n"))
}

pub fn add_follow(a: &Address, rule: Option<Rule>) -> Result<()> {
    anyhow::ensure!(!blocked().contains(&a.to_string()), "{a} is blocked on this machine — run `gitseed unblock {a}` first if you really want to host it");
    let mut c = SeedConfig::load()?;
    match c.follow.iter_mut().find(|f| f.address == a.to_string()) {
        Some(f) => f.rule = rule,
        None => c.follow.push(Follow { address: a.to_string(), rule }),
    }
    c.save()
}

pub fn remove_follow(a: &Address) -> Result<()> {
    let mut c = SeedConfig::load()?;
    let before = c.follow.len();
    c.follow.retain(|f| f.address != a.to_string());
    if c.follow.len() == before {
        return Err(anyhow!("not following {a}"));
    }
    c.save()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_rules() {
        let mut m = Manifest::default();
        for r in ["refs/heads/main", "refs/heads/dev", "refs/tags/v1.9", "refs/tags/v1.10", "refs/tags/v2.0", "refs/tags/v2.1"] {
            m.refs.insert(r.into(), RefEntry { sha: "a".repeat(40), segs: vec![] });
        }
        let s = |refs: &[&str], tags: &str| select(&m, &Rule { refs: refs.iter().map(|s| s.to_string()).collect(), tags: tags.into(), assets: false });
        assert_eq!(s(&["main"], "none"), vec!["refs/heads/main"]);
        assert_eq!(s(&[], "latest:2"), vec!["refs/tags/v2.1", "refs/tags/v2.0"]);
        assert_eq!(s(&[], "v1.*"), vec!["refs/tags/v1.9", "refs/tags/v1.10"]);
        assert_eq!(s(&["*"], "none").len(), 2);
        assert_eq!(parse_size("1.5GiB").unwrap(), 1610612736);
    }
}
