//! User-facing operations: publish, clone, pull, verify, export/import.
use crate::core::*;
use crate::git::{self, SigStatus};
use crate::net::{self, Net, Pointer, Record};
use crate::trust::{self, Identity, Resolved, Verdict};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

pub const MAX_SEGS: usize = 20;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct RepoConfig {
    pub name: String,
    pub key: String,
    /// Set this when you are a maintainer but not the root key holder.
    pub address: Option<String>,
    pub include: Vec<String>,
    pub description: String,
    pub license: String,
    pub topics: Vec<String>,
    pub webseeds: Vec<String>,
    // ---- policy (applied on publish when you hold the root key) ----
    pub require_signed: String,
    pub git_signers: Vec<String>,
    /// Refs exempt from require_signed (legacy unsigned tags).
    pub unsigned_ok: Vec<String>,
    pub proofs: Vec<String>,
    pub maintainers: Vec<Maintainer>,
}

impl Default for RepoConfig {
    fn default() -> Self {
        RepoConfig {
            name: String::new(),
            key: "default".into(),
            address: None,
            include: vec!["refs/heads/*".into(), "refs/tags/*".into()],
            description: String::new(),
            license: String::new(),
            topics: vec![],
            webseeds: vec![],
            require_signed: "none".into(),
            git_signers: vec![],
            unsigned_ok: vec![],
            proofs: vec![],
            maintainers: vec![],
        }
    }
}

pub fn repo_root(dir: &Path) -> Result<PathBuf> {
    Ok(PathBuf::from(git::git(dir, &["rev-parse", "--show-toplevel"])?.trim()))
}

pub fn load_repo_config(repo: &Path) -> Result<RepoConfig> {
    let p = repo.join(".gitseed");
    if !p.exists() {
        // a clone of a gitseed project: publishing goes to that project (as a co-maintainer)
        if let Ok(a) = git::git(repo, &["config", "gitseed.address"]).map_err(anyhow::Error::from).and_then(|s| Address::parse(s.trim())) {
            return Ok(RepoConfig { name: a.name.clone(), address: Some(a.to_string()), ..Default::default() });
        }
    }
    let s = std::fs::read_to_string(&p).with_context(|| format!("{} not found — run `gitseed init` first (or `gitseed init --address <addr>` to join a project)", p.display()))?;
    let c: RepoConfig = toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))?;
    valid_name(&c.name)?;
    Ok(c)
}

pub fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).is_ok() && matches!(s.trim(), "y" | "Y" | "yes")
}

// ---------- secret scanning ----------

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("private key", r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36}"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Stripe live key", r"sk_live_[A-Za-z0-9]{20,}"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("hard-coded secret", r#"(?i)(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*['"][^'"\s]{12,}['"]"#),
];

/// Scan lines added in `new` but not reachable from `old`. Uses gitleaks if installed.
pub fn secret_scan(repo: &Path, new: &[String], old: &[String]) -> Result<Vec<String>> {
    let old: Vec<&String> = old.iter().filter(|s| git::has_object(repo, s)).collect();
    let mut range: Vec<String> = new.to_vec();
    if !old.is_empty() {
        range.push("--not".into());
        range.extend(old.iter().map(|s| s.to_string()));
    }
    if std::process::Command::new("gitleaks").arg("version").output().is_ok() {
        let o = std::process::Command::new("gitleaks")
            .args(["git", "--no-banner", "--redact", "-v", "--log-opts", &range.join(" ")])
            .arg(repo)
            .output()?;
        return Ok(if o.status.success() { vec![] } else { vec![String::from_utf8_lossy(&o.stdout).chars().take(4000).collect()] });
    }
    let mut args = vec!["log", "-p", "--no-color", "--format=commit %h"];
    args.extend(range.iter().map(|s| s.as_str()));
    let log = git::git(repo, &args)?;
    let res: Vec<(&str, regex::Regex)> = SECRET_PATTERNS.iter().map(|(n, p)| (*n, regex::Regex::new(p).unwrap())).collect();
    let (mut commit, mut file, mut hits) = (String::new(), String::new(), vec![]);
    for line in log.lines() {
        if let Some(c) = line.strip_prefix("commit ") {
            commit = c.to_string();
        } else if let Some(f) = line.strip_prefix("+++ b/") {
            file = f.to_string();
        } else if line.starts_with('+') && !line.starts_with("+++") {
            for (n, re) in &res {
                if re.is_match(line) {
                    hits.push(format!("{n} in {file} (commit {commit})"));
                }
            }
        }
    }
    hits.dedup();
    Ok(hits)
}

// ---------- publish ----------

#[derive(Default)]
pub struct PublishOpts {
    pub dry_run: bool,
    pub yes_forever: bool,
    pub allow_secrets: bool,
    pub allow_rewrite: bool,
    pub assets: Vec<PathBuf>,
    /// Tag the assets belong to.
    pub release_tag: String,
    /// For `git push`: (dst ref, new sha or None to delete). None = publish all included refs.
    pub push: Option<Vec<(String, Option<String>)>>,
    pub retract: Vec<String>,
    pub quiet: bool,
    /// Publish as a new project under my own key even though this repo is a clone of another project.
    pub fork: bool,
}

fn seg_of(repo: &Path, segs: &[Seg], x: &str) -> Option<usize> {
    segs.iter().position(|s| s.tips.iter().any(|t| t == x)).or_else(|| segs.iter().position(|s| s.tips.iter().any(|t| git::is_ancestor(repo, x, t))))
}

/// Segments needed to rebuild `sha`, in apply order.
// ponytail: O(prereqs × segs) `git merge-base` calls; bounded by MAX_SEGS compaction.
fn closure(repo: &Path, segs: &[Seg], sha: &str) -> Result<Vec<String>> {
    let mut need = BTreeSet::new();
    let mut stack = vec![sha.to_string()];
    while let Some(x) = stack.pop() {
        let i = seg_of(repo, segs, &x).ok_or_else(|| anyhow!("no segment contains {x} (missing history?)"))?;
        if need.insert(i) {
            stack.extend(segs[i].prereqs.iter().cloned());
        }
    }
    Ok(need.into_iter().map(|i| segs[i].blob.sha256.clone()).collect())
}

fn store_file(src: &Path) -> Result<Blob> {
    let b = net::blob_meta(src)?;
    if !has_blob(&b.sha256) {
        std::fs::copy(src, blob_path(&b.sha256))?;
    }
    Ok(b)
}

fn store_doc<T: Signed>(d: &T) -> Result<Pointer> {
    let bytes = d.to_blob();
    let sha = put_blob(&bytes)?;
    let (ih, _) = net::torrent_for(&blob_path(&sha), &sha)?;
    Ok(Pointer { d: sha, ih })
}

fn next_key_path(key: &str) -> PathBuf {
    home().join("keys").join(format!("{key}.next.key"))
}

pub struct Published {
    pub addr: Address,
    pub manifest_sha: String,
    pub blobs: Vec<String>,
}

pub async fn publish(net: &Net, repo: &Path, cfg: &RepoConfig, o: &PublishOpts) -> Result<Option<Published>> {
    let key = load_key(&cfg.key)?;
    let me = pk_hex(&key);
    // a clone of someone else's project publishes to THAT project (as a maintainer), never silently to a new one
    let cloned_from = git::git(repo, &["config", "gitseed.address"]).ok().and_then(|s| Address::parse(s.trim()).ok());
    let addr = match (&cfg.address, cloned_from) {
        _ if o.fork => Address { root: me.clone(), name: cfg.name.clone() },
        (Some(a), _) => Address::parse(a)?,
        (None, Some(c)) if c.root != me && !o.fork => c,
        _ => Address { root: me.clone(), name: cfg.name.clone() },
    };
    let say = |s: String| {
        if !o.quiet {
            eprintln!("{s}")
        }
    };

    // --- current state of the project (ours, or as a co-maintainer)
    let existing = match load_pin(&addr)? {
        Some(_) => Some(trust::resolve(net, &addr).await?),
        None if addr.root != me => Some(trust::resolve(net, &addr).await?),
        None => trust::resolve(net, &addr).await.ok(),
    };
    if let Some(r) = &existing {
        ensure!(r.failures.is_empty(), "project state has problems, refusing to publish:\n  {}", r.failures.join("\n  "));
    }
    let first = existing.is_none();

    // --- policy: create or update when we hold the root key
    let mut policy_ptr: Option<Pointer> = None;
    let mut policy = match &existing {
        Some(r) => r.policy.clone(),
        None => {
            let next_pk = std::fs::read_to_string(home().join("keys").join(format!("{}.next.pub", cfg.key)))
                .map(|s| s.trim().to_string())
                .or_else(|_| load_key_file(&next_key_path(&cfg.key)).map(|k| pk_hex(&k)))
                .map_err(|e| anyhow!("{e:#}\nhint: `gitseed keygen` creates a recovery key"))?;
            parse_pk(&next_pk)?;
            Policy {
                v: 1,
                name: cfg.name.clone(),
                root: me.clone(),
                seq: 0,
                next_root: next_pk,
                prev_root: None,
                maintainers: vec![],
                revoked: vec![],
                require_signed: String::new(),
                git_signers: vec![],
                unsigned_ok: vec![],
                proofs: vec![],
                sig: String::new(),
            }
        }
    };
    if policy.root == me {
        let mut want = policy.clone();
        let mut ms = vec![Maintainer { key: me.clone(), label: "root".into(), scope: None, expires: None }];
        ms.extend(cfg.maintainers.iter().filter(|m| m.key != me).cloned());
        for m in &ms {
            ensure!(!policy.revoked.iter().any(|r| r.key == m.key), "key {} was revoked earlier and can never be re-added — the maintainer must create a new key (`gitseed keygen`)", fpr(&m.key));
        }
        for old in &policy.maintainers {
            if !ms.iter().any(|m| m.key == old.key) && !want.revoked.iter().any(|r| r.key == old.key) {
                want.revoked.push(Revoked { key: old.key.clone(), after: now_us() });
            }
        }
        want.maintainers = ms;
        want.require_signed = cfg.require_signed.clone();
        want.git_signers = cfg.git_signers.clone();
        want.unsigned_ok = cfg.unsigned_ok.clone();
        want.proofs = cfg.proofs.clone();
        let changed = {
            let (mut a, mut b) = (want.clone(), policy.clone());
            a.seq = 0;
            b.seq = 0;
            a.sig.clear();
            b.sig.clear();
            a != b
        };
        if changed {
            want.seq = now_us();
            want.sign(&key);
            want.check()?;
            if !first {
                policy.allows_successor(&want)?;
            }
            say(format!("policy {} (maintainers: {}, require_signed: {})", if first { "created" } else { "updated" }, want.maintainers.len(), want.require_signed));
            policy = want;
            if !o.dry_run {
                policy_ptr = Some(store_doc(&policy)?);
            }
        }
    }
    let my_entry = policy.maintainer(&me, now_us()).map_err(|e| anyhow!("you cannot publish to {addr}: {e}"))?;

    // --- refs
    let prev: Option<Manifest> = existing.as_ref().and_then(|r| r.manifest.clone());
    let mut refs: BTreeMap<String, String> = match &o.push {
        None => git::list_refs(repo, &cfg.include)?,
        Some(updates) => {
            let mut m: BTreeMap<String, String> = prev.as_ref().map(|p| p.refs.iter().map(|(k, v)| (k.clone(), v.sha.clone())).collect()).unwrap_or_default();
            for (dst, sha) in updates {
                ensure!(ref_ok(dst), "cannot publish {dst} (only refs/heads/* and refs/tags/*)");
                match sha {
                    Some(s) => m.insert(dst.clone(), s.clone()),
                    None => m.remove(dst),
                };
            }
            m
        }
    };
    ensure!(!refs.is_empty(), "nothing to publish (no refs match include = {:?})", cfg.include);
    refs.retain(|r, _| ref_ok(r));
    let prev_refs: BTreeMap<String, String> = prev.as_ref().map(|p| p.refs.iter().map(|(k, v)| (k.clone(), v.sha.clone())).collect()).unwrap_or_default();
    for (r, old) in &prev_refs {
        if r.starts_with("refs/tags/") && refs.get(r).is_some_and(|n| n != old) {
            bail!("tag {r} already published at {} — tags are immutable; create a new tag instead", &old[..10]);
        }
        if r.starts_with("refs/heads/") && refs.get(r).is_some_and(|n| git::has_object(repo, old) && !git::is_ancestor(repo, old, n)) {
            ensure!(o.allow_rewrite, "{r} rewrites published history. The old version stays public forever anyway; pass --force to publish the rewrite");
        }
    }
    let changed: Vec<String> = refs.iter().filter(|(r, s)| prev_refs.get(*r) != Some(s)).map(|(r, _)| r.clone()).collect();
    let dropped: Vec<&String> = prev_refs.keys().filter(|r| !refs.contains_key(*r)).collect();
    if o.push.is_none() && !dropped.is_empty() && !o.allow_rewrite {
        bail!(
            "this would REMOVE published refs from the newest snapshot: {}\n(this checkout is missing them, or `include` changed). Fetch them first, or pass --force to remove them (their history stays public).",
            dropped.iter().map(|r| short_ref(r)).collect::<Vec<_>>().join(", ")
        );
    }
    if let Some(scope) = &my_entry.scope {
        let removed = prev_refs.keys().filter(|r| !refs.contains_key(*r));
        if let Some(bad) = changed.iter().chain(removed).find(|r| !git::glob(scope, r)) {
            bail!("your key may only change {scope}, but this would change {bad}. Publish only matching refs (e.g. `gitseed release <tag>`).");
        }
    }
    if o.push.is_none() && !o.quiet {
        let all = git::git(repo, &["for-each-ref", "--format=%(refname)"])?;
        let excluded: Vec<&str> = all.lines().filter(|r| !refs.contains_key(*r)).collect();
        say(format!("publishing {} refs: {}", refs.len(), refs.keys().map(|r| r.trim_start_matches("refs/heads/").trim_start_matches("refs/tags/")).collect::<Vec<_>>().join(", ")));
        if !excluded.is_empty() {
            say(format!("NOT publishing {} refs: {}", excluded.len(), excluded.iter().take(12).cloned().collect::<Vec<_>>().join(", ")));
        }
    }

    // --- refuse what every client would reject anyway
    for r in &changed {
        if policy.requires_sig(r) {
            match git::verify_sig(repo, &refs[r], r.starts_with("refs/tags/"), &policy.git_signers) {
                SigStatus::Good(_) => {}
                SigStatus::Unsigned => bail!("{} is unsigned but the project requires signatures — sign it (git tag -s / git commit -S) or list it in unsigned_ok", short_ref(r)),
                SigStatus::Bad(e) => bail!("{}: signature does not match git_signers in .gitseed: {e}", short_ref(r)),
            }
        }
    }

    // --- secrets
    let prev_tips: Vec<String> = prev.as_ref().map(|p| p.segs.iter().flat_map(|s| s.tips.clone()).collect()).unwrap_or_default();
    if !changed.is_empty() {
        let hits = secret_scan(repo, &changed.iter().map(|r| refs[r].clone()).collect::<Vec<_>>(), &prev_tips)?;
        if !hits.is_empty() {
            let msg = format!("possible secrets in what you are about to publish FOREVER:\n  {}", hits.join("\n  "));
            ensure!(o.allow_secrets, "{msg}\nRemove them from history (and rotate them!), or pass --allow-secrets if these are false positives.");
            say(format!("warning: {msg}"));
        } else {
            say("secret scan: clean".into());
        }
    }

    // --- segments
    let mut segs: Vec<Seg> = prev.as_ref().map(|p| p.segs.clone()).unwrap_or_default();
    let compact = segs.len() >= MAX_SEGS;
    let mut new_blobs = vec![];
    if !changed.is_empty() || compact {
        if compact {
            segs.clear();
        }
        let names: Vec<String> = if compact { refs.keys().cloned().collect() } else { changed.clone() };
        // one segment for the default branch + tags, then one per other branch: a hoster who seeds
        // only `main` never stores feature-branch history
        let default = ["refs/heads/main", "refs/heads/master"].into_iter().find(|r| refs.contains_key(*r)).unwrap_or("");
        let mut groups: Vec<Vec<String>> = vec![names.iter().filter(|r| *r == default || r.starts_with("refs/tags/")).cloned().collect()];
        groups.extend(names.iter().filter(|r| *r != default && r.starts_with("refs/heads/")).map(|r| vec![r.clone()]));
        let mut exclude = if compact { vec![] } else { prev_tips.clone() };
        let tmpns = format!("refs/gitseed-tmp/{}", std::process::id());
        for (gi, group) in groups.into_iter().filter(|g| !g.is_empty()).enumerate() {
            let tmp = home().join("tmp").join(format!("seg-{}-{gi}.bundle", std::process::id()));
            // bundle by sha via temporary refs so `git push` (where refs aren't local names) works too
            let mut upd = String::new();
            let mut tmprefs = vec![];
            for (i, r) in group.iter().enumerate() {
                let t = format!("{tmpns}/{gi}-{i}");
                upd.push_str(&format!("update {t} {}\n", refs[r]));
                tmprefs.push(t);
            }
            run_update_ref(repo, &upd)?;
            // only exclude tips that are ancestors of this group: then everything omitted is behind a declared
            // prerequisite, and `closure` finds the segments it lives in (unrelated tips would hide shared objects)
            let excl: Vec<String> = exclude.iter().filter(|t| git::has_object(repo, t) && group.iter().any(|r| git::is_ancestor(repo, t, &refs[r]))).cloned().collect();
            let res = git::create_bundle(repo, &tmp, &tmprefs, &excl);
            let _ = run_update_ref(repo, &tmprefs.iter().map(|t| format!("delete {t}\n")).collect::<String>());
            if let Some(info) = res? {
                let size = std::fs::metadata(&tmp)?.len();
                let what = if group.len() == 1 && group[0].starts_with("refs/heads/") { short_ref(&group[0]).to_string() } else { "default branch + tags".into() };
                say(format!("new segment: {} for {what} ({}){}", human(size), if compact { "compacted base" } else { "incremental" }, if o.dry_run { " [dry run]" } else { "" }));
                exclude.extend(info.tips.iter().cloned());
                if !o.dry_run {
                    let b = store_file(&tmp)?;
                    new_blobs.push(b.sha256.clone());
                    segs.push(Seg { blob: b, prereqs: info.prereqs, tips: info.tips });
                }
            }
            let _ = std::fs::remove_file(&tmp);
        }
    }
    if o.dry_run {
        say("dry run: nothing published".into());
        return Ok(None);
    }
    if first && !o.yes_forever {
        say(format!("\nThis publishes {addr} PUBLICLY AND PERMANENTLY.\nAnyone may mirror it; nothing can be unpublished."));
        ensure!(confirm("Type 'yes' to publish forever:"), "aborted (pass --yes-forever to confirm non-interactively)");
    }

    let mut entries = BTreeMap::new();
    for (r, sha) in &refs {
        let reuse = prev.as_ref().and_then(|p| p.refs.get(r)).filter(|e| &e.sha == sha && e.segs.iter().all(|s| segs.iter().any(|x| &x.blob.sha256 == s)));
        let segs_needed = match reuse {
            Some(e) => e.segs.clone(),
            None => closure(repo, &segs, sha)?,
        };
        entries.insert(r.clone(), RefEntry { sha: sha.clone(), segs: segs_needed });
    }

    let mut assets: Vec<Asset> = prev.as_ref().map(|p| p.assets.clone()).unwrap_or_default();
    for a in &o.assets {
        let name = a.file_name().and_then(|n| n.to_str()).ok_or_else(|| anyhow!("bad asset path"))?.to_string();
        let b = store_file(a)?;
        new_blobs.push(b.sha256.clone());
        ensure!(!assets.iter().any(|x| x.path == name && x.tag == o.release_tag && x.blob.sha256 != b.sha256), "{name} was already published for {} with different contents — release files are immutable; use a new tag", o.release_tag);
        assets.retain(|x| !(x.path == name && x.tag == o.release_tag));
        assets.push(Asset { path: name, tag: o.release_tag.clone(), blob: b });
    }

    let default = ["refs/heads/main", "refs/heads/master"].into_iter().find(|r| refs.contains_key(*r)).map(String::from).or_else(|| refs.keys().find(|r| r.starts_with("refs/heads/")).cloned());
    let all_shas: Vec<String> = refs.values().cloned().collect();
    let mut m = Manifest {
        v: 1,
        root: policy.root.clone(),
        name: cfg.name.clone(),
        policy: policy_ptr.as_ref().map(|p| p.d.clone()).or_else(|| existing.as_ref().map(|r| r.policy_sha.clone())).unwrap(),
        signer: me.clone(),
        seq: now_us(),
        prev: existing.as_ref().and_then(|r| r.manifest_sha.clone()),
        refs: entries,
        segs,
        assets,
        root_commits: git::root_commits(repo, &all_shas).unwrap_or_default(),
        retract: o.retract.clone(),
        description: cfg.description.clone(),
        license: cfg.license.clone(),
        topics: cfg.topics.clone(),
        readme: default.map(|d| git::readme_excerpt(repo, &refs[&d])).unwrap_or_default(),
        webseeds: cfg.webseeds.clone(),
        sig: String::new(),
    };
    m.sign(&key);
    m.check()?;
    let mp = store_doc(&m)?;

    // --- records: local first (mirrors/republishers read these), then the DHT
    let mut recs = vec![];
    if let Some(p) = &policy_ptr {
        recs.push(Record::new(&key, &net::policy_salt(&cfg.name), p));
    }
    recs.push(Record::new(&key, &net::pointer_salt(&cfg.name), &mp));
    for r in &recs {
        net::store_record(r)?;
    }
    if net.cfg.dht_on() {
        for r in &recs {
            if let Err(e) = net.dht_put(r).await {
                say(format!("warning: {e:#} — mirrors and `gitseed seed` will republish it"));
            }
        }
    }

    // --- pin our own project as trusted, and register it for seeding
    let mut res = Resolved {
        addr: addr.clone(),
        policy: policy.clone(),
        policy_sha: m.policy.clone(),
        manifest: Some(m.clone()),
        manifest_sha: Some(mp.d.clone()),
        identity: Identity::Pinned,
        proof_results: vec![],
        failures: vec![],
        warnings: vec![],
        pin: load_pin(&addr)?.unwrap_or_else(|| Pin { address: addr.to_string(), root: policy.root.clone(), pinned_at: now_us(), ..Default::default() }),
        roots: vec![policy.root.clone()],
    };
    res.accept(true)?;
    crate::seed::ensure_followed(&addr)?;
    let mut blobs = vec![m.policy.clone(), mp.d.clone()];
    blobs.extend(new_blobs);
    say(format!("published {addr}\n  snapshot {}  seq {}  segments {}  refs {}", &mp.d[..16], m.seq, m.segs.len(), m.refs.len()));
    if o.fork {
        let _ = git::git(repo, &["config", "gitseed.address", &addr.to_string()]);
        say(format!("this checkout now publishes to your fork {addr}"));
    }
    let cfg_file = repo.join(".gitseed");
    if cfg.address.is_none() && cfg_file.exists() && !o.fork {
        let mut c = cfg.clone();
        c.address = Some(addr.to_string());
        std::fs::write(&cfg_file, toml::to_string_pretty(&c)?)?;
        say("wrote `address` into .gitseed — commit it, so co-maintainers and a future you (e.g. `gitseed rotate` on a new machine) find the project".into());
    }
    Ok(Some(Published { addr, manifest_sha: mp.d, blobs }))
}

fn run_update_ref(repo: &Path, cmds: &str) -> Result<()> {
    use std::io::Write;
    let mut c = std::process::Command::new("git").arg("-C").arg(repo).args(["update-ref", "--stdin"]).stdin(std::process::Stdio::piped()).spawn()?;
    c.stdin.take().unwrap().write_all(cmds.as_bytes())?;
    ensure!(c.wait()?.success(), "git update-ref failed");
    Ok(())
}

pub fn human(n: u64) -> String {
    let (mut v, mut u) = (n as f64, "B");
    for unit in ["KiB", "MiB", "GiB", "TiB"] {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        u = unit;
    }
    if u == "B" { format!("{n} B") } else { format!("{v:.1} {u}") }
}

// ---------- local cache repo per project ----------

pub fn cache_dir(a: &Address) -> PathBuf {
    home().join("repos").join(format!("{}.git", a.file_id()))
}

/// Fetch the segments for `refs` and set exactly those refs (as signed) in the bare cache repo.
/// Returns the cache path and the previous tips (for rewrite detection).
pub async fn sync_cache(net: &Net, r: &Resolved, refs: &[String]) -> Result<(PathBuf, BTreeMap<String, String>)> {
    let m = r.manifest.as_ref().ok_or_else(|| anyhow!("project has no published snapshot yet"))?;
    let dir = cache_dir(&r.addr);
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        git::git(&dir, &["init", "-q", "--bare"])?;
        git::git(&dir, &["config", "gc.auto", "0"])?;
    }
    let old: BTreeMap<String, String> = git::git(&dir, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"])?
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let imported_f = dir.join("gitseed-imported");
    let mut imported: BTreeSet<String> = std::fs::read_to_string(&imported_f).unwrap_or_default().lines().map(String::from).collect();
    for s in m.segs_for(refs) {
        if imported.contains(&s.blob.sha256) {
            continue;
        }
        net.fetch(&s.blob, &m.webseeds).await?;
        git::import_bundle(&dir, &blob_path(&s.blob.sha256)).with_context(|| format!("importing segment {}", &s.blob.sha256[..12]))?;
        imported.insert(s.blob.sha256.clone());
        std::fs::write(&imported_f, imported.iter().cloned().collect::<Vec<_>>().join("\n"))?;
    }
    let mut upd = String::new();
    for (name, e) in &m.refs {
        if refs.contains(name) {
            ensure!(git::has_object(&dir, &e.sha), "segment data does not contain {name} at {} (forged manifest?)", &e.sha[..10]);
            upd.push_str(&format!("update {name} {}\n", e.sha));
        } else if old.contains_key(name) {
            upd.push_str(&format!("update {name} {}\n", e.sha)); // keep refs we already had in sync
        }
    }
    for name in old.keys() {
        if !m.refs.contains_key(name) {
            if name.starts_with("refs/heads/") {
                upd.push_str(&format!("delete {name}\n"));
            }
            // tags never deleted locally: a tag once seen is kept
        }
    }
    if !upd.is_empty() {
        let upd: String = upd.lines().filter(|l| !l.starts_with("update ") || git::has_object(&dir, l.rsplit(' ').next().unwrap())).map(|l| format!("{l}\n")).collect();
        run_update_ref(&dir, &upd)?;
    }
    if let Some(h) = ["refs/heads/main", "refs/heads/master"].into_iter().find(|r| m.refs.contains_key(*r)) {
        let _ = git::git(&dir, &["symbolic-ref", "HEAD", h]);
    }
    Ok((dir, old))
}

pub fn expand_refs(m: &Manifest, wanted: &[String]) -> Result<Vec<String>> {
    if wanted.is_empty() {
        return Ok(m.refs.keys().cloned().collect());
    }
    let mut out = vec![];
    for w in wanted {
        let hits: Vec<String> = m.refs.keys().filter(|r| *r == w || git::glob(w, r)).cloned().collect();
        ensure!(!hits.is_empty(), "no ref matches {w}. Available: {}", m.refs.keys().map(|r| short_ref(r)).collect::<Vec<_>>().join(", "));
        out.extend(hits);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn short_ref(r: &str) -> &str {
    r.trim_start_matches("refs/heads/").trim_start_matches("refs/tags/")
}

// ---------- the verification view (what the cautious user reads) ----------

pub fn identity_line(r: &Resolved) -> String {
    match &r.identity {
        Identity::Verified(d) => format!("✔ VERIFIED — the owner of {} publishes this key", d.join(", ")),
        Identity::Pinned => "● PINNED — same key you trusted before on this machine (no public proof)".into(),
        Identity::Unknown => "? UNKNOWN — never seen before and no proof: this could be anyone".into(),
    }
}

fn status_text(x: &trust::RefReport) -> String {
    let is_tag = x.name.starts_with("refs/tags/");
    match &x.verdict {
        Verdict::Verified => "✔ VERIFIED".into(),
        Verdict::Signed => "✔ SIGNED (author identity unproven)".into(),
        Verdict::Unsigned if !is_tag => "○ branch, not signed — verify a signed tag instead".into(),
        Verdict::Unsigned => "⚠ UNSIGNED".into(),
        Verdict::Unverified(_) => "⚠ signed by a key the project does not list".into(),
        Verdict::Fail(why) => format!("✖ FAIL: {why}"),
    }
}

/// The verification view (CLI). The same facts are rendered by web::project_html.
pub fn view(r: &Resolved, reports: &[trust::RefReport]) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let m = r.manifest.as_ref();
    let p = &r.policy;
    let _ = writeln!(o, "\n{}  ·  {}", r.addr.name, r.addr);
    let rotated = if p.root != r.addr.root { format!("  (rotated from {})", fpr(&r.addr.root)) } else { String::new() };
    let _ = writeln!(o, "  AUTHOR     {}", identity_line(r));
    let _ = writeln!(o, "             key {}{rotated}", fpr(&p.root));
    for (u, res) in &r.proof_results {
        let _ = writeln!(o, "             {} {u}{}", if res.is_ok() { "✔" } else { "✖" }, res.as_ref().err().map(|e| format!("  ({e})")).unwrap_or_default());
    }
    let _ = writeln!(
        o,
        "  POLICY     signatures required on: {} · maintainers: {}",
        p.require_signed,
        p.maintainers.iter().map(|m| format!("{}{}", r.signer_label(&m.key), m.scope.as_ref().map(|s| format!(" [only {s}]")).unwrap_or_default())).collect::<Vec<_>>().join(", ")
    );
    if let Some(m) = m {
        let days = (now_us() - m.seq) / 86_400_000_000;
        let _ = writeln!(o, "  SNAPSHOT   {} signed by {} on {}{}", &r.manifest_sha.as_deref().unwrap_or("")[..16], r.signer_label(&m.signer), fmt_time(m.seq), if days > 30 { format!("  (newest available is {days} days old)") } else { String::new() });
    }
    if !reports.is_empty() {
        let _ = writeln!(o, "\n  {:<22} {:<11} {:<10} {:<30} STATUS", "RELEASE / REF", "DATE", "COMMIT", "SIGNED BY");
        let mut last_kind = "";
        for x in reports {
            let is_tag = x.name.starts_with("refs/tags/");
            let kind = if is_tag { "releases & tags" } else { "branches" };
            if kind != last_kind {
                let _ = writeln!(o, "  -- {kind} --");
                last_kind = kind;
            }
            let signer = match &x.sig {
                SigStatus::Good(w) => w.clone(),
                SigStatus::Unsigned => "—".into(),
                SigStatus::Bad(_) => "✖ not a project signer".into(),
            };
            let name = format!("{}{}", short_ref(&x.name), if x.latest { " ★" } else { "" });
            let _ = writeln!(o, "  {:<22} {:<11} {:<10} {:<30} {}{}", name, x.date, &x.sha[..10], signer, status_text(x), if x.note.is_empty() { String::new() } else { format!("  ({})", x.note) });
            if let Some(m) = m {
                for a in m.assets.iter().filter(|a| is_tag && a.tag == short_ref(&x.name)) {
                    let cov = if x.tag_files.contains(&a.blob.sha256) { "✔ listed in the signed tag" } else { "⚠ NOT in the tag signature (vouched only by the snapshot signer)" };
                    let _ = writeln!(o, "     └ {:<32} {:>9}  sha256 {}  {cov}", a.path, human(a.blob.size), a.blob.sha256);
                }
            }
        }
        if let Some(m) = m {
            if reports.len() == m.refs.len() {
                for a in m.assets.iter().filter(|a| !m.refs.contains_key(&format!("refs/tags/{}", a.tag))) {
                    let _ = writeln!(o, "  ⚠ release file {} (sha256 {}) belongs to no published tag", a.path, a.blob.sha256);
                }
            }
        }
        let _ = writeln!(o, "  ★ = newest signed release. Check a downloaded file with: gitseed verify-file {} <file>", r.addr);
        if let Some(b) = reports.iter().find(|x| !x.name.starts_with("refs/tags/") && x.note.contains("past")) {
            let _ = writeln!(o, "  ⓘ {} has unsigned commits after the newest release ({}); only signed releases are covered by the author's signature", short_ref(&b.name), b.note);
        }
    }
    if let Some(m) = m {
        let others = trust::other_publishers(m, &r.roots);
        if !others.is_empty() {
            let _ = writeln!(o, "\n  OTHER PUBLISHERS of this history — different keys, NOT this author:");
            for (a, om) in others {
                let look = if trust::lookalike(&a.root, &p.root) { "  ⚠ LOOKALIKE KEY" } else { "" };
                let doms: Vec<String> = get_doc::<Policy>(&om.policy).ok().map(|pp| pp.proofs.iter().map(|u| trust::proof_domain(u)).collect()).unwrap_or_default();
                let same = match &r.identity {
                    Identity::Verified(mine) => doms.iter().any(|d| mine.contains(d)),
                    _ => false,
                };
                let claim = if doms.is_empty() { "no identity".to_string() } else { doms.join(",") };
                let flag = if same { "  ✖ claims the SAME domain as the verified author, whose page lists a different key: IMPOSTOR" } else { "" };
                let _ = writeln!(o, "    {}  {:<16} claims (unchecked): {:<20} last update {}{look}{flag}", fpr(&a.root), a.name, claim, fmt_time(om.seq));
            }
        }
    }
    for w in &r.warnings {
        let _ = writeln!(o, "  ⚠ {w}");
    }
    for f in &r.failures {
        let _ = writeln!(o, "  ✖ {f}");
    }
    o
}

pub fn print_view(r: &Resolved, reports: &[trust::RefReport]) {
    print!("{}", view(r, reports));
}

pub fn fmt_time(us: i64) -> String {
    let secs = us / 1_000_000;
    let days = secs.div_euclid(86400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    let rem = secs.rem_euclid(86400);
    format!("{y:04}-{mo:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

/// Decide whether a first-use key is acceptable.
fn gate_identity(r: &Resolved, trust_new_key: bool) -> Result<bool> {
    match r.identity {
        Identity::Verified(_) | Identity::Pinned => Ok(false),
        Identity::Unknown if trust_new_key => Ok(true),
        Identity::Unknown => {
            eprintln!("\nThis key has never been seen on this machine and publishes no identity proof.");
            eprintln!("Compare the fingerprint {} with one the author published somewhere you trust.", fpr(&r.policy.root));
            if confirm("Trust this key? [y/N]") { Ok(true) } else { bail!("not trusted (pass --trust-new-key to accept non-interactively)") }
        }
    }
}

// ---------- clone / pull / verify ----------

pub async fn clone(net: &Net, addr: &Address, dir: Option<PathBuf>, want: &[String], trust_new_key: bool) -> Result<()> {
    let mut r = trust::resolve(net, addr).await?;
    if !r.failures.is_empty() {
        print_view(&r, &[]);
        bail!("refusing to clone: verification failed");
    }
    let accepted = gate_identity(&r, trust_new_key)?;
    let m = r.manifest.clone().ok_or_else(|| anyhow!("{addr} has no valid snapshot available{}", if r.warnings.is_empty() { String::new() } else { format!(":\n  {}", r.warnings.join("\n  ")) }))?;
    let refs = expand_refs(&m, want)?;
    let (cache, _) = sync_cache(net, &r, &refs).await?;
    let reports = trust::ref_reports(&cache, &r, &BTreeMap::new());
    let dir = dir.unwrap_or_else(|| PathBuf::from(&addr.name));
    ensure!(!dir.exists(), "{} already exists", dir.display());
    let fails: Vec<&trust::RefReport> = reports.iter().filter(|x| refs.contains(&x.name) && matches!(x.verdict, Verdict::Fail(_))).collect();
    if !fails.is_empty() {
        print_view(&r, &reports);
        bail!("refusing to check out: {} ref(s) failed verification", fails.len());
    }
    git::git(Path::new("."), &["clone", "-q", "--no-hardlinks", cache.to_str().unwrap(), dir.to_str().unwrap()])?;
    git::git(&dir, &["remote", "set-url", "origin", &addr.to_string()])?;
    git::git(&dir, &["config", "gitseed.address", &addr.to_string()])?;
    git::git(&dir, &["config", "gitseed.refs", &want.join(" ")])?;
    if let [one] = want {
        if let Some(t) = refs.iter().find(|r| r.starts_with("refs/tags/") && short_ref(r) == one) {
            git::git(&dir, &["-c", "advice.detachedHead=false", "checkout", "-q", t])?;
        }
    }
    print_view(&r, &reports);
    r.accept(accepted)?;
    println!("\ncloned into {}", dir.display());
    Ok(())
}

/// What changed between two snapshots, with the new commits on each branch.
pub fn changes(cache: &Path, old: &Manifest, m: &Manifest) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    for (name, e) in &m.refs {
        match old.refs.get(name) {
            None => {
                let _ = writeln!(o, "  + {}  {}", short_ref(name), &e.sha[..10]);
            }
            Some(p) if p.sha != e.sha => {
                let stat = git::git(cache, &["diff", "--shortstat", &p.sha, &e.sha]).unwrap_or_default();
                let _ = writeln!(o, "  ~ {}  {}..{} {}", short_ref(name), &p.sha[..10], &e.sha[..10], stat.trim());
                let log = git::git(cache, &["log", "--format=      %h %G? %an: %s", "-n", "20", &format!("{}..{}", p.sha, e.sha)]).unwrap_or_default();
                o.push_str(&log);
            }
            _ => {}
        }
    }
    for name in old.refs.keys().filter(|n| !m.refs.contains_key(*n)) {
        let _ = writeln!(o, "  - {}", short_ref(name));
    }
    let seen: BTreeSet<(&String, &String)> = old.assets.iter().map(|a| (&a.tag, &a.path)).collect();
    for a in m.assets.iter().filter(|a| !seen.contains(&(&a.tag, &a.path))) {
        let _ = writeln!(o, "  + release file {}/{}  sha256 {}", a.tag, a.path, &a.blob.sha256[..16]);
    }
    o
}

pub async fn pull(net: &Net, repo: &Path, yes: bool, now: bool) -> Result<()> {
    let addr = Address::parse(git::git(repo, &["config", "gitseed.address"]).context("not a gitseed clone")?.trim())?;
    let pin = load_pin(&addr)?.ok_or_else(|| anyhow!("no pin for {addr}"))?;
    let old: Option<Manifest> = pin.manifest.as_ref().and_then(|s| get_doc(s).ok());
    let mut r = trust::resolve(net, &addr).await?;
    let m = r.manifest.clone().ok_or_else(|| anyhow!("no snapshot"))?;
    if r.manifest_sha == pin.manifest && r.failures.is_empty() && r.warnings.is_empty() {
        println!("up to date ({})", fmt_time(m.seq));
        return Ok(());
    }
    let delay_h: i64 = git::git(repo, &["config", "gitseed.delay"]).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let age_h = (now_us() - m.seq) / 3_600_000_000;
    if !now && age_h < delay_h {
        println!("a new snapshot exists but is only {age_h}h old; your waiting period is {delay_h}h (gitseed.delay). Use --now to take it anyway.");
        return Ok(());
    }
    let want: Vec<String> = git::git(repo, &["config", "gitseed.refs"]).unwrap_or_default().split_whitespace().map(String::from).collect();
    let refs = expand_refs(&m, &want).or_else(|_| expand_refs(&m, &[]))?;
    let (cache, old_tips) = sync_cache(net, &r, &refs).await?;
    let reports = trust::ref_reports(&cache, &r, &old_tips);
    println!("update for {}  (snapshot signed by {} on {})", addr.name, r.signer_label(&m.signer), fmt_time(m.seq));
    if let Some(o) = &old {
        print!("{}", changes(&cache, o, &m));
    }
    let fails: Vec<_> = reports.iter().filter(|x| matches!(x.verdict, Verdict::Fail(_))).collect();
    let rewritten: Vec<_> = reports.iter().filter(|x| x.note.starts_with("history rewritten")).collect();
    if !r.failures.is_empty() || !fails.is_empty() {
        print_view(&r, &reports);
        bail!("update REJECTED: verification failed. Your checkout is unchanged.");
    }
    if !r.warnings.is_empty() || !rewritten.is_empty() {
        print_view(&r, &reports);
        if !yes && !confirm("Accept this update? [y/N]") {
            bail!("update not accepted (use --yes to accept non-interactively). Your checkout is unchanged.");
        }
    }
    git::git(repo, &["fetch", "-q", "--no-tags", cache.to_str().unwrap(), "+refs/heads/*:refs/remotes/origin/*"])?;
    let _ = git::git(repo, &["fetch", "-q", cache.to_str().unwrap(), "refs/tags/*:refs/tags/*"]);
    if let Ok(b) = git::git(repo, &["symbolic-ref", "--short", "HEAD"]) {
        let b = b.trim();
        if git::ok(repo, &["rev-parse", "--verify", "-q", &format!("refs/remotes/origin/{b}")]) {
            if let Err(e) = git::git(repo, &["merge", "--ff-only", "-q", &format!("origin/{b}")]) {
                r.accept(false)?;
                bail!("fetched, but could not fast-forward {b} ({e:#}).\nIf upstream rewrote history: `git reset --hard origin/{b}` (your old commits stay in the reflog).");
            }
        }
    }
    r.accept(false)?;
    println!("updated.");
    Ok(())
}

/// Verification outcome. Exit codes: 0 ok, 2 failed, 3 authorship unproven (unknown key).
#[derive(PartialEq)]
pub enum Outcome {
    Ok,
    Failed,
    Unproven,
}

impl Outcome {
    pub fn code(&self) -> i32 {
        match self {
            Outcome::Ok => 0,
            Outcome::Failed => 2,
            Outcome::Unproven => 3,
        }
    }
}

fn outcome(r: &Resolved, failed: bool) -> Outcome {
    if failed || !r.failures.is_empty() {
        Outcome::Failed
    } else if r.identity == Identity::Unknown {
        Outcome::Unproven
    } else {
        Outcome::Ok
    }
}

/// Resolve + fetch + full per-ref verdicts.
pub async fn verify(net: &Net, addr: &Address, want: &[String], json: bool) -> Result<Outcome> {
    let r = trust::resolve(net, addr).await?;
    let mut reports = vec![];
    if let Some(m) = &r.manifest {
        let refs = expand_refs(m, want)?;
        let (cache, _) = sync_cache(net, &r, &refs).await?;
        reports = trust::ref_reports(&cache, &r, &BTreeMap::new());
        reports.retain(|x| refs.contains(&x.name));
    }
    let out = outcome(&r, reports.iter().any(|x| matches!(x.verdict, Verdict::Fail(_))));
    if json {
        let sig = |s: &SigStatus| match s {
            SigStatus::Good(w) => serde_json::json!({"status": "good", "signer": w}),
            SigStatus::Unsigned => serde_json::json!({"status": "unsigned"}),
            SigStatus::Bad(e) => serde_json::json!({"status": "bad", "reason": e}),
        };
        let reason = |v: &Verdict| match v {
            Verdict::Fail(w) | Verdict::Unverified(w) => w.clone(),
            _ => String::new(),
        };
        let m = r.manifest.as_ref();
        let v = serde_json::json!({
            "address": addr.to_string(),
            "result": match out { Outcome::Ok => "ok", Outcome::Failed => "failed", Outcome::Unproven => "unproven" },
            "identity": r.identity.word(),
            "proven_by": match &r.identity { Identity::Verified(d) => d.clone(), _ => vec![] },
            "root": r.policy.root, "require_signed": r.policy.require_signed,
            "snapshot": r.manifest_sha, "signed_by": m.map(|m| m.signer.clone()),
            "failures": r.failures, "warnings": r.warnings,
            "refs": reports.iter().map(|x| serde_json::json!({"ref": x.name, "sha": x.sha, "date": x.date, "verdict": x.verdict.word(), "reason": reason(&x.verdict), "signature": sig(&x.sig), "note": x.note})).collect::<Vec<_>>(),
            "release_files": m.map(|m| m.assets.iter().map(|a| serde_json::json!({"tag": a.tag, "file": a.path, "sha256": a.blob.sha256, "size": a.blob.size})).collect::<Vec<_>>()).unwrap_or_default(),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print_view(&r, &reports);
        println!(
            "\n{}",
            match out {
                Outcome::Ok if !r.warnings.is_empty() => "RESULT: OK — but read the ⚠ lines above",
                Outcome::Ok => "RESULT: OK",
                Outcome::Failed => "RESULT: FAILED — do not use this code",
                Outcome::Unproven => "RESULT: UNPROVEN — signatures check out, but nothing proves who this key belongs to",
            }
        );
    }
    Ok(out)
}

/// Is this local file a release file of the project?
pub async fn verify_file(net: &Net, addr: &Address, file: &Path) -> Result<Outcome> {
    let r = trust::resolve(net, addr).await?;
    let sha = sha256_file(file)?;
    let m = r.manifest.as_ref().ok_or_else(|| anyhow!("no snapshot"))?;
    println!("{}  sha256 {sha}", file.display());
    println!("author: {}", identity_line(&r));
    let out = match m.assets.iter().find(|a| a.blob.sha256 == sha) {
        Some(a) if r.failures.is_empty() => {
            println!("✔ MATCHES {} of release {} (snapshot signed by {} on {})", a.path, a.tag, r.signer_label(&m.signer), fmt_time(m.seq));
            let tref = format!("refs/tags/{}", a.tag);
            let mut covered = false;
            if m.refs.contains_key(&tref) {
                let (cache, _) = sync_cache(net, &r, &[tref.clone()]).await?;
                let rep = trust::ref_reports(&cache, &r, &BTreeMap::new()).into_iter().find(|x| x.name == tref);
                if let Some(x) = rep {
                    covered = x.tag_files.contains(&sha);
                    match (&x.verdict, covered) {
                        (Verdict::Verified | Verdict::Signed, true) => println!("✔ the signed tag {} lists this file ({})", a.tag, match &x.sig { SigStatus::Good(w) => w.as_str(), _ => "" }),
                        (Verdict::Fail(why), _) => {
                            println!("✖ release {} FAILED verification: {why}", a.tag);
                            return Ok(Outcome::Failed);
                        }
                        _ => {}
                    }
                }
            }
            if !covered {
                println!("⚠ the release's signed tag does not list this file: only the snapshot signer ({}) vouches for it", r.signer_label(&m.signer));
            }
            outcome(&r, false)
        }
        Some(_) => {
            println!("✖ the project failed verification: {}", r.failures.join("; "));
            Outcome::Failed
        }
        None => {
            println!("✖ NOT a release file of {} — do not trust this download", addr);
            Outcome::Failed
        }
    };
    if out == Outcome::Unproven {
        println!("⚠ the publisher's identity is UNPROVEN — the file is what this key published, but nothing proves who the key belongs to");
    }
    Ok(out)
}

pub fn addr_or_cwd(a: Option<&str>) -> Result<Address> {
    match a {
        Some(a) => Address::parse(a),
        None => {
            let here = std::env::current_dir()?;
            if let Ok(s) = git::git(&here, &["config", "gitseed.address"]) {
                return Address::parse(s.trim());
            }
            let root = repo_root(&here)?;
            let cfg = load_repo_config(&root)?;
            match cfg.address {
                Some(a) => Address::parse(&a),
                None => Ok(Address { root: pk_hex(&load_key(&cfg.key)?), name: cfg.name }),
            }
        }
    }
}

// ---------- mirror layout: export / import ----------

/// Every blob a project's history needs (policy, manifests, segments, assets).
pub fn project_blobs(p: &Pin) -> Vec<String> {
    let mut v: BTreeSet<String> = BTreeSet::new();
    v.insert(p.policy.clone());
    for h in &p.history {
        v.insert(h.clone());
        if let Ok(m) = get_doc::<Manifest>(h) {
            v.insert(m.policy.clone());
            v.extend(m.segs.iter().map(|s| s.blob.sha256.clone()));
            v.extend(m.assets.iter().map(|a| a.blob.sha256.clone()));
        }
    }
    v.into_iter().filter(|s| has_blob(s)).collect()
}

/// The mirror `index.json` for the given projects (all pinned, non-blocked ones when empty).
pub fn build_index(which: &[Address]) -> net::MirrorIndex {
    let mut idx = net::MirrorIndex { v: 1, generated: now_us(), ..Default::default() };
    let blocked = crate::seed::blocked();
    for (a, p) in all_pins() {
        if (!which.is_empty() && !which.contains(&a)) || blocked.contains(&a.to_string()) {
            continue;
        }
        let Some(ms) = p.manifest.clone() else { continue };
        idx.projects.push(net::MirrorEntry { address: a.to_string(), policy: p.policy.clone(), manifest: ms, history: p.history.clone() });
    }
    let roots: BTreeSet<String> = idx.projects.iter().filter_map(|e| Address::parse(&e.address).ok()).map(|a| a.root).collect();
    let maint: BTreeSet<String> = idx.projects.iter().filter_map(|e| get_doc::<Policy>(&e.policy).ok()).flat_map(|p| p.maintainers.into_iter().map(|m| m.key)).collect();
    idx.records = net::all_records().into_iter().filter(|r| (roots.contains(&r.k) || maint.contains(&r.k)) && r.verify().is_ok()).collect();
    idx.blocked = blocked.into_iter().collect();
    idx
}

pub fn export(dir: &Path, which: &[Address], site: bool) -> Result<usize> {
    std::fs::create_dir_all(dir.join("blobs"))?;
    let mut idx = build_index(which);
    // merge with what the directory already mirrors (several hosts can export into one mirror)
    if let Ok(Some(old)) = read_json::<net::MirrorIndex>(&dir.join("index.json")) {
        for e in old.projects {
            let seq = |m: &str| get_doc::<Manifest>(m).map(|m| m.seq).or_else(|_| std::fs::read(dir.join("blobs").join(m)).ok().and_then(|b| serde_json::from_slice::<Manifest>(&b).ok()).map(|m| m.seq).ok_or(())).unwrap_or(0);
            match idx.projects.iter().position(|x| x.address == e.address) {
                Some(i) if seq(&idx.projects[i].manifest) >= seq(&e.manifest) => {}
                Some(i) => idx.projects[i] = e,
                None if !idx.blocked.contains(&e.address) => idx.projects.push(e),
                None => {}
            }
        }
        for r in old.records {
            if !idx.records.iter().any(|x| x.target() == r.target() && x.seq >= r.seq) {
                idx.records.retain(|x| x.target() != r.target());
                idx.records.push(r);
            }
        }
    }
    let mut n = 0;
    for e in &idx.projects {
        let Ok(a) = Address::parse(&e.address) else { continue };
        let Some(p) = load_pin(&a)? else { continue };
        for b in project_blobs(&p) {
            let dst = dir.join("blobs").join(&b);
            if !dst.exists() {
                std::fs::hard_link(blob_path(&b), &dst).or_else(|_| std::fs::copy(blob_path(&b), &dst).map(|_| ()))?;
                n += 1;
            }
        }
    }
    write_json(&dir.join("index.json"), &idx)?;
    if site {
        let addrs: Vec<Address> = idx.projects.iter().filter_map(|e| Address::parse(&e.address).ok()).collect();
        crate::web::write_static_site(dir, &addrs)?;
    }
    Ok(n)
}

/// Pull everything a mirror (directory or URL) lists into the local catalog. Nothing becomes trusted.
pub async fn import(net: &Net, src: &str) -> Result<usize> {
    let idx = net.mirror_index(src)?;
    for r in &idx.records {
        let _ = net::store_record(r);
    }
    let mut n = 0;
    let mut cat = crate::seed::Catalog::load();
    for e in &idx.projects {
        let Ok(a) = Address::parse(&e.address) else { continue };
        let fetched: Result<()> = async {
            for d in std::iter::once(&e.policy).chain(std::iter::once(&e.manifest)) {
                if !has_blob(d) {
                    let bytes = mirror_blob(net, src, d)?;
                    put_blob(&bytes)?;
                }
            }
            let p: Policy = get_doc(&e.policy)?;
            p.check()?;
            let m: Manifest = get_doc(&e.manifest)?;
            m.check()?;
            // the entry's address must be the key that signed it (or the key it rotated from)
            ensure!((p.root == a.root || p.prev_root.as_deref() == Some(a.root.as_str())) && m.root == p.root && m.name == a.name && p.name == a.name, "mirror entry claims an address its keys do not own");
            Ok(())
        }
        .await;
        match fetched {
            Ok(()) => {
                cat.add(&a, &e.policy, &e.manifest, src);
                n += 1;
            }
            Err(err) => eprintln!("skipping {}: {err:#}", e.address),
        }
    }
    cat.save()?;
    Ok(n)
}

fn mirror_blob(net: &Net, src: &str, sha: &str) -> Result<Vec<u8>> {
    ensure!(is_hex(sha, 64), "mirror index contains a malformed hash");
    let p = if src.starts_with("http") {
        let agent: ureq::Agent = ureq::Agent::config_builder().proxy(net.cfg.proxy.as_deref().and_then(|p| ureq::Proxy::new(p).ok())).build().into();
        let mut r = agent.get(&format!("{}/blobs/{sha}", src.trim_end_matches('/'))).call()?;
        r.body_mut().with_config().limit(8 << 20).read_to_vec()?
    } else {
        std::fs::read(Path::new(src).join("blobs").join(sha))?
    };
    ensure!(sha256_hex(&p) == sha, "mirror served corrupt data");
    Ok(p)
}
