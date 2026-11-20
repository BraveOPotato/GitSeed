//! Thin wrappers around the `git` CLI. We never parse git objects ourselves.
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").arg("-C").arg(repo).args(args).stdin(Stdio::null()).output().context("running git (is it installed?)")?;
    if !out.status.success() {
        bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn ok(repo: &Path, args: &[&str]) -> bool {
    Command::new("git").arg("-C").arg(repo).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

/// `*` matches anything (including `/`). Patterns without `refs/` match heads and tags.
pub fn glob(pat: &str, s: &str) -> bool {
    if !pat.starts_with("refs/") {
        return glob(&format!("refs/heads/{pat}"), s) || glob(&format!("refs/tags/{pat}"), s);
    }
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| m(rest, &s[i..])),
            Some((c, rest)) => s.first() == Some(c) && m(rest, &s[1..]),
        }
    }
    m(pat.as_bytes(), s.as_bytes())
}

/// Refs to publish: only heads/tags matching `include`; stash, remotes, notes, replace are never published.
pub fn list_refs(repo: &Path, include: &[String]) -> Result<BTreeMap<String, String>> {
    let out = git(repo, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"])?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(r, _)| crate::core::ref_ok(r) && include.iter().any(|p| glob(p, r)))
        .map(|(r, s)| (r.to_string(), s.to_string()))
        .collect())
}

pub fn has_object(repo: &Path, sha: &str) -> bool {
    ok(repo, &["cat-file", "-e", sha])
}

pub fn is_ancestor(repo: &Path, a: &str, b: &str) -> bool {
    a == b || ok(repo, &["merge-base", "--is-ancestor", a, b])
}

pub fn root_commits(repo: &Path, shas: &[String]) -> Result<Vec<String>> {
    if shas.is_empty() {
        return Ok(vec![]);
    }
    let mut args = vec!["rev-list", "--max-parents=0"];
    args.extend(shas.iter().map(|s| s.as_str()));
    let mut v: Vec<String> = git(repo, &args)?.lines().map(String::from).collect();
    v.sort();
    v.dedup();
    Ok(v)
}

pub struct BundleInfo {
    pub prereqs: Vec<String>,
    pub tips: Vec<String>,
}

/// Parse a v2/v3 bundle header without trusting it for anything but bookkeeping.
pub fn bundle_header(path: &Path) -> Result<BundleInfo> {
    use std::io::BufRead;
    let f = std::io::BufReader::new(std::fs::File::open(path)?);
    let (mut prereqs, mut tips) = (vec![], vec![]);
    for (i, line) in f.split(b'\n').enumerate() {
        let line = String::from_utf8_lossy(&line?).into_owned();
        if i == 0 {
            if !line.starts_with("# v2 git bundle") && !line.starts_with("# v3 git bundle") {
                bail!("not a git bundle");
            }
            continue;
        }
        if line.is_empty() {
            break;
        }
        if let Some(p) = line.strip_prefix('-') {
            prereqs.push(p.split(' ').next().unwrap_or("").to_string());
        } else if !line.starts_with('@') {
            tips.push(line.split(' ').next().unwrap_or("").to_string());
        }
    }
    prereqs.sort();
    prereqs.dedup();
    tips.sort();
    tips.dedup();
    Ok(BundleInfo { prereqs, tips })
}

/// Bundle `refs` minus everything reachable from `exclude`. None if nothing new.
pub fn create_bundle(repo: &Path, out: &Path, refs: &[String], exclude: &[String]) -> Result<Option<BundleInfo>> {
    let mut args: Vec<&str> = vec!["bundle", "create", "-q", out.to_str().unwrap()];
    args.extend(refs.iter().map(|s| s.as_str()));
    let excl: Vec<&String> = exclude.iter().filter(|s| has_object(repo, s)).collect();
    if !excl.is_empty() {
        args.push("--not");
        args.extend(excl.iter().map(|s| s.as_str()));
    }
    let o = Command::new("git").arg("-C").arg(repo).args(&args).stdin(Stdio::null()).output()?;
    if !o.status.success() {
        let e = String::from_utf8_lossy(&o.stderr);
        if e.contains("empty bundle") {
            return Ok(None);
        }
        bail!("git bundle create failed: {}", e.trim());
    }
    Ok(Some(bundle_header(out)?))
}

/// Import a bundle's objects with full fsck. Refs from the bundle are NOT kept: only
/// refs listed in the signed manifest are ever written (blocks refs/replace & friends).
pub fn import_bundle(repo: &Path, bundle: &Path) -> Result<()> {
    git(
        repo,
        &[
            "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true",
            "fetch", "-q", "--no-tags", "--no-write-fetch-head", "--no-auto-gc",
            bundle.to_str().unwrap(), "+refs/*:refs/gitseed-import/*",
        ],
    )?;
    let refs = git(repo, &["for-each-ref", "--format=delete %(refname)", "refs/gitseed-import"])?;
    let mut c = Command::new("git").arg("-C").arg(repo).args(["update-ref", "--stdin"]).stdin(Stdio::piped()).spawn()?;
    use std::io::Write;
    c.stdin.take().unwrap().write_all(refs.as_bytes())?;
    c.wait()?;
    Ok(())
}

pub fn readme_excerpt(repo: &Path, rev: &str) -> String {
    for f in ["README.md", "README", "README.txt", "readme.md"] {
        if let Ok(s) = git(repo, &["show", &format!("{rev}:{f}")]) {
            return s.chars().take(1500).collect();
        }
    }
    String::new()
}

#[derive(Debug, Clone, PartialEq)]
pub enum SigStatus {
    Good(String), // principal
    Unsigned,
    Bad(String),
}

/// Verify the SSH signature of a tag (or commit) against the project's allowed signers.
pub fn verify_sig(repo: &Path, rev: &str, is_tag: bool, allowed_signers: &[String]) -> SigStatus {
    let obj_type = git(repo, &["cat-file", "-t", rev]).unwrap_or_default();
    let raw = git(repo, &["cat-file", obj_type.trim(), rev]).unwrap_or_default();
    let signed = raw.contains("-----BEGIN SSH SIGNATURE-----") || raw.contains("-----BEGIN PGP SIGNATURE-----") || raw.contains("gpgsig ");
    if !signed {
        return SigStatus::Unsigned;
    }
    if allowed_signers.is_empty() {
        return SigStatus::Bad("signed, but the project lists no git signers to check it against".into());
    }
    let f = crate::core::home().join("tmp").join(format!("allowed_signers.{}", std::process::id()));
    if std::fs::write(&f, allowed_signers.join("\n") + "\n").is_err() {
        return SigStatus::Bad("cannot write temp file".into());
    }
    let cmd = if is_tag && obj_type.trim() == "tag" { "verify-tag" } else { "verify-commit" };
    let o = Command::new("git")
        .arg("-C").arg(repo)
        .args(["-c", &format!("gpg.ssh.allowedSignersFile={}", f.display()), cmd, "--raw", rev])
        .stdin(Stdio::null())
        .output();
    let _ = std::fs::remove_file(&f);
    match o {
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
            if o.status.success() {
                // e.g. `Good "git" signature for alice@x.org with ED25519 key SHA256:...`
                let who = err.split(" for ").nth(1).and_then(|s| s.split(" with ").next()).unwrap_or("?").to_string();
                let fp = err.split(" key ").nth(1).and_then(|s| s.split_whitespace().next()).map(|k| format!(" [{}]", k.trim_start_matches("SHA256:").chars().take(10).collect::<String>())).unwrap_or_default();
                SigStatus::Good(format!("{who}{fp}"))
            } else {
                SigStatus::Bad(err.lines().last().unwrap_or("verification failed").trim().to_string())
            }
        }
        Err(e) => SigStatus::Bad(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn globbing() {
        use super::glob;
        assert!(glob("main", "refs/heads/main"));
        assert!(glob("v*", "refs/tags/v1.2"));
        assert!(glob("refs/heads/*", "refs/heads/feat/x"));
        assert!(!glob("main", "refs/heads/main2"));
        assert!(!glob("v2.*", "refs/tags/v1.0"));
    }
}
