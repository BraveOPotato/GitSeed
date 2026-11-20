//! Resolving an address to the newest *valid* policy + manifest, and judging authorship.
//! Everything here is computed locally; indexes and mirrors are never trusted for verdicts.
use crate::core::*;
use crate::git::{self, SigStatus};
use crate::net::{self, Net, Pointer};
use anyhow::{Result, anyhow, bail, ensure};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum Identity {
    /// A domain the author controls publishes this key at /.well-known/gitseed (checked just now).
    Verified(Vec<String>),
    /// Seen and accepted before on this machine (trust on first use); no proof.
    Pinned,
    /// Never seen and no proof. Could be anyone.
    Unknown,
}

impl Identity {
    pub fn word(&self) -> &'static str {
        match self {
            Identity::Verified(_) => "verified",
            Identity::Pinned => "pinned",
            Identity::Unknown => "unknown",
        }
    }
}

pub struct Resolved {
    pub addr: Address,
    pub policy: Policy,
    pub policy_sha: String,
    pub manifest: Option<Manifest>,
    pub manifest_sha: Option<String>,
    pub identity: Identity,
    pub proof_results: Vec<(String, Result<(), String>)>,
    /// Problems that must stop a checkout (moved tags, changed release files, rollbacks...).
    pub failures: Vec<String>,
    /// Things a careful user should look at before updating.
    pub warnings: Vec<String>,
    pub pin: Pin,
    /// Root keys in the rotation chain (oldest first).
    pub roots: Vec<String>,
}

async fn load_doc<T: serde::de::DeserializeOwned>(net: &Net, p: &Pointer, webseeds: &[String]) -> Result<(T, String)> {
    let b = net.fetch_doc(p, webseeds).await?;
    Ok((serde_json::from_slice(&b)?, p.d.clone()))
}

async fn policy_from_record(net: &Net, root: &str, name: &str) -> Option<(Policy, String)> {
    let r = net.record(root, &net::policy_salt(name)).await?;
    let p = r.verify().ok()?;
    let (pol, sha): (Policy, String) = load_doc(net, &p, &[]).await.ok()?;
    (pol.root == root && pol.name == name && pol.check().is_ok()).then_some((pol, sha))
}

fn label(p: &Policy, key: &str) -> String {
    match p.maintainers.iter().find(|m| m.key == key) {
        Some(m) if !m.label.is_empty() => format!("{} ({})", m.label, &fpr(key)[..9]),
        _ => fpr(key),
    }
}

fn describe_policy_change(old: &Policy, new: &Policy, w: &mut Vec<String>) {
    if old.root != new.root {
        w.push(format!("root key ROTATED {} -> {} (authorised by the pre-committed recovery key)", fpr(&old.root), fpr(&new.root)));
    }
    for m in &new.maintainers {
        if !old.maintainers.iter().any(|o| o.key == m.key) {
            w.push(format!("maintainer ADDED: {} {}{}", fpr(&m.key), m.label, m.scope.as_ref().map(|s| format!(" (may only change {s})")).unwrap_or_default()));
        }
    }
    for m in &old.maintainers {
        if !new.maintainers.iter().any(|o| o.key == m.key) {
            w.push(format!("maintainer removed: {} {}", fpr(&m.key), m.label));
        }
    }
    for u in new.unsigned_ok.iter().filter(|u| !old.unsigned_ok.contains(u)) {
        w.push(format!("{u} was newly EXEMPTED from signature checks"));
    }
    if old.git_signers != new.git_signers {
        w.push("the list of git signing keys CHANGED".into());
    }
    if old.proofs != new.proofs {
        w.push(format!("identity proof URLs CHANGED: {:?} -> {:?}", old.proofs, new.proofs));
    }
    let rank = |s: &str| match s {
        "all" => 2,
        "tags" => 1,
        _ => 0,
    };
    if rank(&new.require_signed) < rank(&old.require_signed) {
        w.push(format!("signature requirement WEAKENED: {} -> {}", old.require_signed, new.require_signed));
    }
}

/// Is `m` acceptable under `policy`? A scoped key's snapshot must chain (via `prev`) to an
/// *authenticated* predecessor: one already accepted on this machine (`trusted`) or one that
/// itself passes this check. The signer never gets to pick an unverified baseline.
pub fn manifest_ok(m: &Manifest, policy: &Policy, roots: &[String], trusted: &[String], lookup: &dyn Fn(&str) -> Option<Manifest>, depth: usize) -> Result<()> {
    m.check()?;
    ensure!(roots.contains(&m.root) && m.name == policy.name, "manifest belongs to another project");
    let who = policy.maintainer(&m.signer, m.seq)?;
    // a revoked key's old snapshots stay valid, but it can't introduce new (backdated) ones
    if policy.revoked.iter().any(|r| r.key == m.signer) {
        ensure!(trusted.contains(&sha256_hex(&m.to_blob())), "key {} was revoked; only snapshots seen before the revocation are accepted", fpr(&m.signer));
    }
    if let Some(scope) = &who.scope {
        ensure!(depth > 0, "snapshot chain too long to authenticate");
        let psha = m.prev.as_ref().ok_or_else(|| anyhow!("scoped key {} published without a predecessor", fpr(&m.signer)))?;
        let prev = lookup(psha).ok_or_else(|| anyhow!("predecessor of a scoped-key snapshot is unavailable"))?;
        ensure!(prev.seq < m.seq, "predecessor is not older");
        if !trusted.contains(psha) {
            manifest_ok(&prev, policy, roots, trusted, lookup, depth - 1).map_err(|e| anyhow!("predecessor not authentic: {e}"))?;
        }
        let mut names: Vec<&String> = m.refs.keys().chain(prev.refs.keys()).collect();
        names.sort();
        names.dedup();
        for r in names {
            if m.refs.get(r).map(|e| &e.sha) != prev.refs.get(r).map(|e| &e.sha) && !git::glob(scope, r) {
                bail!("key {} may only change {scope}, but changed {r}", fpr(&m.signer));
            }
        }
        let pa: BTreeMap<_, _> = prev.assets.iter().map(|a| ((&a.tag, &a.path), &a.blob.sha256)).collect();
        for a in &m.assets {
            if pa.get(&(&a.tag, &a.path)) != Some(&&a.blob.sha256) && !git::glob(scope, &format!("refs/tags/{}", a.tag)) {
                bail!("key {} may only change {scope}, but changed release file {}", fpr(&m.signer), a.path);
            }
        }
    }
    Ok(())
}

/// The host part of a proof URL (what the user is told they can trust).
pub fn proof_domain(url: &str) -> String {
    url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").to_string()
}

pub fn proof_url_ok(url: &str) -> Result<(), String> {
    let dom = proof_domain(url);
    let host = if dom.starts_with('[') { dom.split(']').next().unwrap_or("").to_string() + "]" } else { dom.split(':').next().unwrap_or("").to_string() };
    let loopback = ["127.0.0.1", "localhost", "[::1]"].contains(&host.as_str()); // testing only
    let ok_host = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c)) && dom == dom.to_lowercase();
    if !ok_host {
        return Err("proof host must be a plain lowercase domain".into());
    }
    if url == format!("https://{dom}/.well-known/gitseed") || (loopback && url == format!("http://{dom}/.well-known/gitseed")) {
        Ok(())
    } else {
        Err("proofs must be exactly https://<your-domain>/.well-known/gitseed (a page anyone can comment on proves nothing)".into())
    }
}

pub async fn check_proof(net: &Net, url: &str, roots: &[String]) -> Result<(), String> {
    proof_url_ok(url)?;
    let u = url.to_string();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .max_redirects(0)
        .proxy(net.cfg.proxy.as_deref().and_then(|p| ureq::Proxy::new(p).ok()))
        .build()
        .into();
    let body = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let mut r = agent.get(&u).call().map_err(|e| e.to_string())?;
        r.body_mut().with_config().limit(1 << 16).read_to_string().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    // the key must stand on its own line: `gitseed key: <hex>` (or just `<hex>`)
    let lines: Vec<String> = body.lines().map(|l| l.trim().to_lowercase()).collect();
    if lines.iter().any(|l| roots.iter().any(|r| *l == *r || *l == format!("gitseed key: {r}"))) {
        return Ok(());
    }
    let others: Vec<String> = lines.iter().filter_map(|l| l.strip_prefix("gitseed key: ")).map(|k| fpr(k.trim())).collect();
    if others.is_empty() {
        Err("the page does not list this project's key (expected a line `gitseed key: <key>`)".into())
    } else {
        Err(format!("the page lists a DIFFERENT key ({}) — this publisher is not the owner of that domain", others.join(", ")))
    }
}

/// Resolve the newest valid state of a project from every source, relative to what we pinned.
pub async fn resolve(net: &Net, addr: &Address) -> Result<Resolved> {
    let pin = load_pin(addr)?;
    let first_use = pin.is_none();
    let mut failures = vec![];
    let mut warnings = vec![];

    // --- policy: start from the pin (or the address' root on first use), follow updates & rotations
    let (mut policy, mut policy_sha) = match &pin {
        Some(p) => (get_doc::<Policy>(&p.policy)?, p.policy.clone()),
        None => {
            let mut found = policy_from_record(net, &addr.root, &addr.name).await;
            if found.is_none() {
                found = mirror_policy(net, addr).await;
            }
            found.ok_or_else(|| anyhow!("could not find project {addr} (no DHT record and no mirror has it)"))?
        }
    };
    let start = policy.clone();
    let mut roots = vec![policy.root.clone()];
    if let Some(p) = &start.prev_root {
        roots.insert(0, p.clone());
    }
    if !roots.contains(&addr.root) {
        roots.insert(0, addr.root.clone());
    }
    for _ in 0..8 {
        let mut advanced = false;
        for root in [policy.root.clone(), policy.next_root.clone()] {
            if let Some((cand, sha)) = policy_from_record(net, &root, &addr.name).await {
                if sha == policy_sha {
                    continue;
                }
                match policy.allows_successor(&cand) {
                    Ok(()) => {
                        if cand.root != policy.root {
                            roots.push(cand.root.clone());
                        }
                        policy = cand;
                        policy_sha = sha;
                        advanced = true;
                        break;
                    }
                    Err(e) if cand.root == policy.root && cand.seq < policy.seq => warnings.push(format!("a mirror/DHT offered an OLDER policy (rollback attempt?) — ignored: {e}")),
                    Err(e) if cand.root == policy.root => failures.push(format!("INVALID policy update from the current root key: {e}")),
                    Err(_) => {}
                }
            }
        }
        if !advanced {
            break;
        }
    }
    if !first_use {
        describe_policy_change(&start, &policy, &mut warnings);
    }

    // --- manifests: every maintainer's pointer + pinned + mirrors; newest valid wins
    let pinned_manifest: Option<Manifest> = pin.as_ref().and_then(|p| p.manifest.as_ref()).and_then(|s| get_doc(s).ok());
    let mut cands: Vec<(Manifest, String)> = vec![];
    if let (Some(m), Some(s)) = (&pinned_manifest, pin.as_ref().and_then(|p| p.manifest.clone())) {
        cands.push((m.clone(), s));
    }
    for m in &policy.maintainers {
        if let Some(r) = net.record(&m.key, &net::pointer_salt(&addr.name)).await {
            if let Ok(p) = r.verify() {
                match load_doc::<Manifest>(net, &p, &[]).await {
                    Ok(x) => cands.push(x),
                    Err(e) => warnings.push(format!("snapshot from {} unavailable: {e:#}", fpr(&m.key))),
                }
            }
        }
    }
    for base in net.cfg.mirrors.clone() {
        if let Ok(idx) = net.mirror_index(&base) {
            for e in idx.projects.iter().filter(|e| roots.iter().any(|r| e.address == format!("gitseed://{r}/{}", addr.name))) {
                // fetch the claimed chain too, so scoped-key snapshots can be authenticated
                for d in std::iter::once(&e.manifest).chain(e.history.iter().rev().take(256)) {
                    match load_doc::<Manifest>(net, &Pointer { d: d.clone(), ih: "0".repeat(40) }, &[]).await {
                        Ok(x) if d == &e.manifest => cands.push(x),
                        Ok(_) => {}
                        Err(err) if d == &e.manifest => warnings.push(format!("mirror {base} offered a snapshot that failed: {err:#}")),
                        Err(_) => {}
                    }
                }
            }
        }
    }
    cands.sort_by_key(|(m, _)| -m.seq);
    cands.dedup_by(|a, b| a.1 == b.1);
    let trusted: Vec<String> = pin.as_ref().map(|p| p.history.clone()).unwrap_or_default();
    let lookup = |s: &str| get_doc::<Manifest>(s).ok();
    let mut chosen: Option<(Manifest, String)> = None;
    for (m, sha) in cands {
        if !roots.contains(&m.root) || m.name != policy.name {
            continue; // e.g. a maintainer's own unrelated project with the same name: not ours, not suspicious
        }
        match manifest_ok(&m, &policy, &roots, &trusted, &lookup, 32) {
            Ok(()) => {
                chosen = Some((m, sha));
                break;
            }
            Err(e) => warnings.push(format!("ignored snapshot {} signed by {}: {e}", &sha[..12], label(&policy, &m.signer))),
        }
    }
    if let (Some(p), Some((m, _))) = (&pin, &chosen) {
        if m.seq < p.manifest_seq {
            failures.push("newest available snapshot is OLDER than one already seen (rollback / freeze attack)".into());
        }
    }

    // --- immutability of tags and release files, and unusual updates
    if let (Some(p), Some((m, _))) = (&pin, &chosen) {
        for (t, sha) in &p.tags {
            match m.refs.get(t) {
                Some(e) if &e.sha != sha => failures.push(format!("TAG MOVED: {t} was {} and is now {} — tags are immutable", &sha[..10], &e.sha[..10])),
                None => warnings.push(format!("tag {t} disappeared from the newest snapshot (kept locally)")),
                _ => {}
            }
        }
        for a in &m.assets {
            let key = format!("{}/{}", a.tag, a.path);
            match p.assets.get(&key) {
                Some(old) if old != &a.blob.sha256 => failures.push(format!("RELEASE FILE CHANGED: {key} was {} and is now {}", &old[..12], &a.blob.sha256[..12])),
                None if p.assets.keys().any(|k| k.starts_with(&format!("{}/", a.tag))) => {
                    warnings.push(format!("release file {} was ADDED to {} after you first saw that release (by {})", a.path, a.tag, label(&policy, &m.signer)))
                }
                _ => {}
            }
        }
        if let Some(pm) = &pinned_manifest {
            if m.signer != pm.signer && !p.history.iter().filter_map(|h| get_doc::<Manifest>(h).ok()).any(|o| o.signer == m.signer) {
                warnings.push(format!("first snapshot ever signed by key {} on this machine", label(&policy, &m.signer)));
            }
            if m.seq - pm.seq > 180 * 24 * 3600 * 1_000_000 {
                warnings.push("project was silent for over 6 months before this update".into());
            }
        }
    }

    // --- identity
    let mut proof_results = vec![];
    for u in &policy.proofs {
        let mut res = check_proof(net, u, std::slice::from_ref(&policy.root)).await;
        if res.is_err() && roots.len() > 1 && check_proof(net, u, &roots).await.is_ok() {
            res = Err("the page still lists the OLD (rotated) key — the author must update it".into());
        }
        proof_results.push((u.clone(), res));
    }
    let ok: Vec<String> = proof_results.iter().filter(|(_, r)| r.is_ok()).map(|(u, _)| proof_domain(u)).collect();
    let identity = if !ok.is_empty() {
        Identity::Verified(ok)
    } else if pin.as_ref().is_some_and(|p| p.trusted) {
        Identity::Pinned
    } else {
        Identity::Unknown
    };

    let mut pin = pin.unwrap_or_else(|| Pin { address: addr.to_string(), pinned_at: now_us(), ..Default::default() });
    pin.root = policy.root.clone();
    let (manifest, manifest_sha) = match chosen {
        Some((m, s)) => (Some(m), Some(s)),
        None => (None, None),
    };
    Ok(Resolved { addr: addr.clone(), policy, policy_sha, manifest, manifest_sha, identity, proof_results, failures, warnings, pin, roots })
}

async fn mirror_policy(net: &Net, addr: &Address) -> Option<(Policy, String)> {
    for base in net.cfg.mirrors.clone() {
        let Ok(idx) = net.mirror_index(&base) else { continue };
        for r in idx.records {
            let _ = net::store_record(&r);
        }
        if let Some(e) = idx.projects.iter().find(|e| e.address == addr.to_string()) {
            if let Ok((p, s)) = load_doc::<Policy>(net, &Pointer { d: e.policy.clone(), ih: "0".repeat(40) }, &[]).await {
                // first contact: only a policy signed by the address' own key (later rotations are followed via records)
                if p.root == addr.root && p.check().is_ok() {
                    return Some((p, s));
                }
            }
        }
    }
    None
}

impl Resolved {
    /// Record what we accepted (never forgets tags, release files or history).
    pub fn accept(&mut self, trusted: bool) -> Result<()> {
        let p = &mut self.pin;
        p.policy = self.policy_sha.clone();
        p.policy_seq = self.policy.seq;
        if let (Some(m), Some(s)) = (&self.manifest, &self.manifest_sha) {
            p.manifest = Some(s.clone());
            p.manifest_seq = m.seq;
            for (r, e) in &m.refs {
                if r.starts_with("refs/tags/") {
                    p.tags.entry(r.clone()).or_insert(e.sha.clone());
                }
            }
            for a in &m.assets {
                p.assets.entry(format!("{}/{}", a.tag, a.path)).or_insert(a.blob.sha256.clone());
            }
            if !p.history.contains(s) {
                p.history.push(s.clone());
            }
        }
        p.trusted |= trusted || matches!(self.identity, Identity::Verified(_));
        save_pin(&self.addr, p)
    }

    pub fn signer_label(&self, key: &str) -> String {
        label(&self.policy, key)
    }
}

// ---------- per-ref verdicts (needs the objects locally) ----------

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Signed by a listed signer AND the author's identity is proven.
    Verified,
    /// Signed by a listed signer; identity only pinned/unknown.
    Signed,
    /// No signature.
    Unsigned,
    /// Has a signature, but not one by a signer listed in the policy (and none was required).
    Unverified(String),
    Fail(String),
}

impl Verdict {
    pub fn word(&self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Signed => "signed",
            Verdict::Unsigned => "unsigned",
            Verdict::Unverified(_) => "unverified",
            Verdict::Fail(_) => "fail",
        }
    }
}

pub struct RefReport {
    pub name: String,
    pub sha: String,
    pub date: String,
    pub sig: SigStatus,
    pub verdict: Verdict,
    pub note: String,
    pub latest: bool,
    /// sha256 values listed in the (signed) tag message: release files the tag signer vouches for.
    pub tag_files: Vec<String>,
}

fn natural_key(s: &str) -> Vec<(u64, String)> {
    let mut out = vec![];
    let (mut num, mut txt) = (String::new(), String::new());
    for c in s.chars() {
        if c.is_ascii_digit() {
            if !txt.is_empty() {
                out.push((0, std::mem::take(&mut txt)));
            }
            num.push(c);
        } else {
            if !num.is_empty() {
                out.push((num.parse().unwrap_or(0), String::new()));
                num.clear();
            }
            txt.push(c);
        }
    }
    if !num.is_empty() {
        out.push((num.parse().unwrap_or(0), String::new()));
    }
    if !txt.is_empty() {
        out.push((0, txt));
    }
    out
}

pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    natural_key(a).cmp(&natural_key(b))
}

/// Release-file hashes a tag message lists (`sha256 <hex>  <name>` lines, written by `gitseed release`).
pub fn listed_files(tag_body: &str) -> Vec<String> {
    tag_body.lines().filter_map(|l| l.trim().strip_prefix("sha256 ")).filter_map(|l| l.split_whitespace().next()).filter(|h| is_hex(h, 64)).map(str::to_lowercase).collect()
}

pub fn ref_reports(repo: &Path, r: &Resolved, old_tips: &BTreeMap<String, String>) -> Vec<RefReport> {
    let Some(m) = &r.manifest else { return vec![] };
    let mut out = vec![];
    for (name, e) in &m.refs {
        if !git::has_object(repo, &e.sha) {
            continue;
        }
        let is_tag = name.starts_with("refs/tags/");
        let sig = git::verify_sig(repo, &e.sha, is_tag, &r.policy.git_signers);
        let required = r.policy.requires_sig(name);
        let mut note = String::new();
        // an annotated tag names itself inside the signed object; it must match the ref it is published as
        let tag_body = if is_tag && git::git(repo, &["cat-file", "-t", &e.sha]).unwrap_or_default().trim() == "tag" { git::git(repo, &["cat-file", "tag", &e.sha]).unwrap_or_default() } else { String::new() };
        let inner_name = tag_body.lines().find_map(|l| l.strip_prefix("tag ")).map(str::to_string);
        let renamed = inner_name.as_ref().filter(|n| n.as_str() != name.trim_start_matches("refs/tags/")).cloned();
        let tag_files = listed_files(&tag_body);
        let mut verdict = match (&sig, required) {
            (SigStatus::Bad(why), true) => Verdict::Fail(format!("signature not valid for this project: {why}")),
            (SigStatus::Bad(why), false) => Verdict::Unverified(why.clone()),
            (SigStatus::Unsigned, true) => Verdict::Fail("unsigned, but the project requires signatures".into()),
            (SigStatus::Unsigned, false) => Verdict::Unsigned,
            (SigStatus::Good(_), _) if matches!(r.identity, Identity::Verified(_)) => Verdict::Verified,
            (SigStatus::Good(_), _) => Verdict::Signed,
        };
        if let Some(f) = r.failures.iter().find(|f| f.contains(&format!(" {name} "))) {
            verdict = Verdict::Fail(f.clone());
        }
        if let Some(inner) = renamed {
            verdict = Verdict::Fail(format!("this is the signed tag `{inner}` re-published under another name (downgrade attempt)"));
        }
        if verdict == Verdict::Unsigned && is_tag && r.policy.unsigned_ok.contains(name) {
            note = "legacy tag, exempt from signing".into();
        }
        if let Some(old) = old_tips.get(name) {
            if old != &e.sha && git::has_object(repo, old) && !git::is_ancestor(repo, old, &e.sha) {
                note = format!("history rewritten (previous tip {} kept)", &old[..10]);
            }
        }
        if !is_tag && note.is_empty() && !matches!(verdict, Verdict::Fail(_)) {
            let nearest = m.refs.iter().filter(|(n, t)| n.starts_with("refs/tags/") && git::is_ancestor(repo, &t.sha, &e.sha))
                .filter_map(|(n, t)| git::git(repo, &["rev-list", "--count", &format!("{}..{}", t.sha, e.sha)]).ok().and_then(|c| c.trim().parse::<u64>().ok()).map(|c| (c, n)))
                .min();
            note = match nearest {
                Some((0, t)) => format!("= {}", t.trim_start_matches("refs/tags/")),
                Some((c, t)) => format!("{c} commit{} past {}", if c == 1 { "" } else { "s" }, t.trim_start_matches("refs/tags/")),
                None => String::new(),
            };
        }
        let date = git::git(repo, &["log", "-1", "--format=%cs", &e.sha]).unwrap_or_default().trim().to_string();
        out.push(RefReport { name: name.clone(), sha: e.sha.clone(), date, sig, verdict, note, latest: false, tag_files });
    }
    // tags first, newest version first; then branches
    out.sort_by(|a, b| (!a.name.starts_with("refs/tags/")).cmp(&!b.name.starts_with("refs/tags/")).then(version_cmp(&b.name, &a.name)));
    if let Some(first) = out.iter_mut().find(|x| x.name.starts_with("refs/tags/") && matches!(x.verdict, Verdict::Verified | Verdict::Signed)) {
        first.latest = true;
    }
    out
}

/// Other publishers of the same history (same root commits, different key) that this machine knows of.
pub fn other_publishers(m: &Manifest, roots: &[String]) -> Vec<(Address, Manifest)> {
    let pid = m.project_id();
    crate::seed::known_projects()
        .into_iter()
        .filter(|(a, om)| !roots.contains(&a.root) && !roots.contains(&om.root) && !m.root_commits.is_empty() && om.project_id() == pid)
        .collect()
}

/// Keys that look alike at a glance (same first 4 hex) but differ.
pub fn lookalike(a: &str, b: &str) -> bool {
    a != b && a.get(..4) == b.get(..4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::policy;

    #[test]
    fn scoped_and_revoked_maintainers() {
        let (r, n, ci) = (new_key(), new_key(), new_key());
        let mut p = policy(&r, &n, &r, 1);
        p.maintainers.push(Maintainer { key: pk_hex(&ci), label: "ci".into(), scope: Some("refs/tags/v*".into()), expires: None });
        p.sign(&r);
        let roots = vec![pk_hex(&r)];
        let mk = |k: &ed25519_dalek::SigningKey, refs: &[(&str, char)], seq, prev: Option<&Manifest>| {
            let mut m = Manifest { v: 1, root: pk_hex(&r), name: "demo".into(), signer: pk_hex(k), seq, prev: prev.map(|p| sha256_hex(&p.to_blob())), ..Default::default() };
            for (n, c) in refs {
                m.refs.insert(n.to_string(), RefEntry { sha: c.to_string().repeat(40), segs: vec![] });
            }
            m.sign(k);
            m
        };
        let base = mk(&r, &[("refs/heads/main", 'a')], 1, None);
        let store: std::cell::RefCell<Vec<Manifest>> = std::cell::RefCell::new(vec![base.clone()]);
        let lookup = |s: &str| store.borrow().iter().find(|m| sha256_hex(&m.to_blob()) == s).cloned();
        manifest_ok(&base, &p, &roots, &[], &lookup, 8).unwrap();
        // CI key may add a tag...
        let tag = mk(&ci, &[("refs/heads/main", 'a'), ("refs/tags/v1", 'b')], 2, Some(&base));
        manifest_ok(&tag, &p, &roots, &[], &lookup, 8).unwrap();
        // ...but not move main
        let evil = mk(&ci, &[("refs/heads/main", 'c')], 3, Some(&base));
        assert!(manifest_ok(&evil, &p, &roots, &[], &lookup, 8).is_err());
        // ...not even by forging its own baseline (a CI-signed "prev" that already has the evil main)
        let fake_prev = mk(&ci, &[("refs/heads/main", 'c')], 2, None);
        store.borrow_mut().push(fake_prev.clone());
        let sneaky = mk(&ci, &[("refs/heads/main", 'c'), ("refs/tags/v2", 'd')], 3, Some(&fake_prev));
        assert!(manifest_ok(&sneaky, &p, &roots, &[], &lookup, 8).is_err(), "scoped key escaped via forged prev");
        // a revoked key can't mint new (backdated) snapshots, but its old ones stay valid
        let mut p2 = p.clone();
        p2.revoked.push(Revoked { key: pk_hex(&ci), after: 100 });
        p2.maintainers.retain(|m| m.key != pk_hex(&ci));
        let old = mk(&ci, &[("refs/heads/main", 'a'), ("refs/tags/v1", 'b')], 2, Some(&base));
        let old_sha = sha256_hex(&old.to_blob());
        assert!(manifest_ok(&old, &p2, &roots, &[old_sha.clone()], &lookup, 8).is_ok());
        let minted = mk(&ci, &[("refs/heads/main", 'z')], 99, Some(&base));
        assert!(manifest_ok(&minted, &p2, &roots, &[old_sha], &lookup, 8).is_err(), "revoked key minted a snapshot");
        // a stranger can't publish at all
        let s = new_key();
        assert!(manifest_ok(&mk(&s, &[("refs/heads/main", 'c')], 3, None), &p, &roots, &[], &lookup, 8).is_err());
    }

    #[test]
    fn proof_rules() {
        assert!(proof_url_ok("https://example.org/.well-known/gitseed").is_ok());
        assert!(proof_url_ok("http://127.0.0.1:8000/.well-known/gitseed").is_ok());
        assert!(proof_url_ok("http://example.org/.well-known/gitseed").is_err());
        assert!(proof_url_ok("https://github.com/someone/issues/1").is_err());
        assert!(proof_url_ok("https://evil.org/x/.well-known/gitseed").is_err());
        assert!(proof_url_ok("http://localhost.evil.com/.well-known/gitseed").is_err());
        assert!(proof_url_ok("http://127.0.0.1.evil.com/.well-known/gitseed").is_err());
    }
}
