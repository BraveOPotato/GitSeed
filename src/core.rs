//! Signed documents (policy, manifest), the local store, keys and pins.
use anyhow::{Context, Result, anyhow, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Clients reject documents dated further than this into the future (stops `seq = MAX` freezes).
pub const MAX_FUTURE_US: i64 = 10 * 60 * 1_000_000;

pub fn now_us() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as i64
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

// ---------- addresses ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub root: String, // hex ed25519 public key
    pub name: String,
}

impl Address {
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s.strip_prefix("gitseed://").ok_or_else(|| anyhow!("address must start with gitseed://"))?;
        let (root, name) = rest.split_once('/').ok_or_else(|| anyhow!("address must be gitseed://<key>/<name>"))?;
        let name = name.trim_end_matches('/');
        parse_pk(root)?;
        valid_name(name)?;
        Ok(Self { root: root.to_lowercase(), name: name.to_string() })
    }
    pub fn file_id(&self) -> String {
        format!("{}.{}", self.root, self.name)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gitseed://{}/{}", self.root, self.name)
    }
}

pub fn valid_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 48 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && !name.starts_with('.'),
        "project name must be 1-48 chars of [A-Za-z0-9-_.]"
    );
    Ok(())
}

pub fn parse_pk(hex_pk: &str) -> Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hex_pk).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| anyhow!("bad public key {hex_pk}"))?;
    VerifyingKey::from_bytes(&b).map_err(|_| anyhow!("bad public key {hex_pk}"))
}

/// Short fingerprint for display. Long enough (80 bits) that vanity-grinding a lookalike is impractical.
pub fn fpr(pk: &str) -> String {
    let p = pk.get(..20).unwrap_or(pk);
    format!("{}-{}-{}-{}-{}", &p[0..4], &p[4..8], &p[8..12], &p[12..16], &p[16..20])
}

// ---------- signing ----------

fn sign_bytes(domain: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!("gitseed-{domain}-v1\n").into_bytes();
    v.extend_from_slice(body);
    v
}

pub trait Signed: Serialize + Clone {
    const DOMAIN: &'static str;
    fn sig_mut(&mut self) -> &mut String;
    fn signer(&self) -> &str;

    fn canonical(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.sig_mut().clear();
        sign_bytes(Self::DOMAIN, &serde_json::to_vec(&c).unwrap())
    }
    fn sign(&mut self, key: &SigningKey) {
        let s = key.sign(&self.canonical());
        *self.sig_mut() = hex::encode(s.to_bytes());
    }
    fn verify_sig(&self) -> Result<()> {
        let pk = parse_pk(self.signer())?;
        let sig: [u8; 64] = hex::decode(self.clone().sig_mut().as_str()).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| anyhow!("malformed signature"))?;
        pk.verify(&self.canonical(), &Signature::from_bytes(&sig)).map_err(|_| anyhow!("{} signature does not verify", Self::DOMAIN))
    }
    fn to_blob(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap()
    }
}

// ---------- policy ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Maintainer {
    pub key: String,
    #[serde(default)]
    pub label: String,
    /// If set, this key may only change refs matching this glob (e.g. CI key: "refs/tags/v*").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Unix microseconds after which snapshots signed by this key are invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Revoked {
    pub key: String,
    /// Snapshots by this key with seq >= after are invalid.
    pub after: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Policy {
    pub v: u32,
    pub name: String,
    pub root: String,
    pub seq: i64,
    /// Pre-committed successor root key. Only it can rotate the root; the current root cannot change it.
    pub next_root: String,
    /// Set on the first policy after a rotation: the root this one replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_root: Option<String>,
    pub maintainers: Vec<Maintainer>,
    #[serde(default)]
    pub revoked: Vec<Revoked>,
    /// "none" | "tags" | "all": which refs must carry a git signature from `git_signers`.
    pub require_signed: String,
    /// ssh allowed_signers lines, e.g. `alice@x.org ssh-ed25519 AAAA...`.
    #[serde(default)]
    pub git_signers: Vec<String>,
    /// Refs exempt from `require_signed` (e.g. old tags from before the project signed releases).
    #[serde(default)]
    pub unsigned_ok: Vec<String>,
    /// URLs whose content must contain the root key (checked by every client itself).
    #[serde(default)]
    pub proofs: Vec<String>,
    pub sig: String,
}

impl Signed for Policy {
    const DOMAIN: &'static str = "policy";
    fn sig_mut(&mut self) -> &mut String {
        &mut self.sig
    }
    fn signer(&self) -> &str {
        &self.root
    }
}

impl Policy {
    /// Must this ref carry a valid git signature?
    pub fn requires_sig(&self, r: &str) -> bool {
        !self.unsigned_ok.iter().any(|u| u == r) && (self.require_signed == "all" || (self.require_signed == "tags" && r.starts_with("refs/tags/")))
    }

    pub fn check(&self) -> Result<()> {
        ensure!(self.v == 1, "unsupported policy version");
        valid_name(&self.name)?;
        ensure!(["none", "tags", "all"].contains(&self.require_signed.as_str()), "bad require_signed");
        for u in &self.proofs {
            crate::trust::proof_url_ok(u).map_err(|e| anyhow!("proof {u:?}: {e}"))?;
        }
        for m in &self.maintainers {
            parse_pk(&m.key)?;
        }
        ensure!(!self.maintainers.is_empty(), "policy has no maintainers");
        ensure!(self.seq <= now_us() + MAX_FUTURE_US, "policy is dated in the future (seq attack?)");
        parse_pk(&self.next_root)?;
        ensure!(self.next_root != self.root, "next_root must differ from root");
        self.verify_sig()
    }

    /// Is `new` a legitimate successor of `self` (the policy we trust)?
    pub fn allows_successor(&self, new: &Policy) -> Result<()> {
        new.check()?;
        ensure!(new.name == self.name, "policy name changed");
        if new.root == self.root {
            ensure!(new.seq > self.seq, "policy is not newer");
            ensure!(new.next_root == self.next_root, "current root tried to change the pre-committed next root (only a rotation can)");
            ensure!(new.prev_root == self.prev_root, "prev_root changed");
        } else {
            ensure!(new.root == self.next_root, "policy signed by an unknown root key");
            ensure!(new.prev_root.as_deref() == Some(self.root.as_str()), "rotation must name the previous root");
        }
        Ok(())
    }

    /// The maintainer entry that authorises a snapshot by `key` at time `seq`.
    /// A revoked key's snapshots from before its revocation stay valid (history doesn't change).
    pub fn maintainer(&self, key: &str, seq: i64) -> Result<Maintainer> {
        if let Some(r) = self.revoked.iter().find(|r| r.key == key) {
            ensure!(seq < r.after, "signer key {} was revoked", fpr(key));
            if !self.maintainers.iter().any(|m| m.key == key) {
                return Ok(Maintainer { key: key.into(), label: "former maintainer".into(), scope: None, expires: None });
            }
        }
        let m = self.maintainers.iter().find(|m| m.key == key).ok_or_else(|| anyhow!("signer {} is not a maintainer", fpr(key)))?;
        if let Some(exp) = m.expires {
            ensure!(seq < exp, "signer key expired");
        }
        Ok(m.clone())
    }
}

// ---------- manifest ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RefEntry {
    pub sha: String,
    /// Segment hashes (in apply order) needed to reconstruct this ref.
    pub segs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Blob {
    pub sha256: String,
    pub size: u64,
    /// BitTorrent v1 infohash of the deterministic single-file torrent of this blob.
    pub ih: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Seg {
    #[serde(flatten)]
    pub blob: Blob,
    pub prereqs: Vec<String>,
    pub tips: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Asset {
    pub path: String,
    /// The release (tag) this file belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(flatten)]
    pub blob: Blob,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Manifest {
    pub v: u32,
    pub root: String,
    pub name: String,
    /// sha256 of the policy.json this snapshot was made under.
    pub policy: String,
    pub signer: String,
    pub seq: i64,
    /// sha256 of the previous manifest in the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub refs: BTreeMap<String, RefEntry>,
    /// Segments in creation order (each excludes everything before it).
    pub segs: Vec<Seg>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    pub root_commits: Vec<String>,
    /// Earlier manifest hashes the maintainers ask mirrors to stop listing (advisory).
    #[serde(default)]
    pub retract: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub readme: String,
    /// HTTP(S) or onion base URLs of mirrors serving `blobs/<sha256>`.
    #[serde(default)]
    pub webseeds: Vec<String>,
    pub sig: String,
}

impl Signed for Manifest {
    const DOMAIN: &'static str = "manifest";
    fn sig_mut(&mut self) -> &mut String {
        &mut self.sig
    }
    fn signer(&self) -> &str {
        &self.signer
    }
}

pub fn ref_ok(r: &str) -> bool {
    (r.starts_with("refs/heads/") || r.starts_with("refs/tags/"))
        && !r.contains("..")
        && r.split('/').all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
        && r.chars().all(|c| c.is_ascii_graphic() && !"~^:?*[\\".contains(c))
}

impl Manifest {
    /// Structural checks + signature. Does not check the policy (see trust).
    pub fn check(&self) -> Result<()> {
        ensure!(self.v == 1, "unsupported manifest version");
        valid_name(&self.name)?;
        ensure!(self.seq <= now_us() + MAX_FUTURE_US, "manifest is dated in the future (seq attack?)");
        let hex40 = |s: &str| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit());
        let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        for (r, e) in &self.refs {
            ensure!(ref_ok(r), "manifest lists a forbidden ref {r}");
            ensure!(hex40(&e.sha), "bad sha for {r}");
            for s in &e.segs {
                ensure!(self.segs.iter().any(|x| &x.blob.sha256 == s), "ref {r} needs unknown segment");
            }
        }
        for s in &self.segs {
            ensure!(hex64(&s.blob.sha256) && hex40(&s.blob.ih), "bad segment hash");
        }
        for a in &self.assets {
            ensure!(hex64(&a.blob.sha256) && hex40(&a.blob.ih), "bad asset hash");
            ensure!(!a.path.contains('/') && !a.path.starts_with('.') && !a.path.is_empty(), "bad asset name");
        }
        self.verify_sig()
    }

    pub fn project_id(&self) -> String {
        let mut r = self.root_commits.clone();
        r.sort();
        sha256_hex(r.join("\n").as_bytes())
    }

    /// Segments needed for the given refs, in apply order.
    pub fn segs_for(&self, refs: &[String]) -> Vec<&Seg> {
        let need: std::collections::BTreeSet<&String> = refs.iter().filter_map(|r| self.refs.get(r)).flat_map(|e| &e.segs).collect();
        self.segs.iter().filter(|s| need.contains(&s.blob.sha256)).collect()
    }
}

// ---------- local store ----------

pub fn home() -> PathBuf {
    let h = std::env::var_os("GITSEED_HOME").map(PathBuf::from).unwrap_or_else(|| {
        let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"));
        base.join("gitseed")
    });
    for d in ["keys", "blobs", "projects", "records", "tmp"] {
        let _ = std::fs::create_dir_all(h.join(d));
    }
    h
}

pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Path of a stored blob. Anything that is not a sha256 hex string (e.g. `../x` from a hostile
/// mirror index) maps to a path that never exists.
pub fn blob_path(sha: &str) -> PathBuf {
    if is_hex(sha, 64) { home().join("blobs").join(sha) } else { home().join("blobs").join("invalid-hash") }
}

pub fn has_blob(sha: &str) -> bool {
    blob_path(sha).exists()
}

/// Store bytes, return sha256.
pub fn put_blob(bytes: &[u8]) -> Result<String> {
    let sha = sha256_hex(bytes);
    let p = blob_path(&sha);
    if !p.exists() {
        let tmp = home().join("tmp").join(format!("{sha}.{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, &p)?;
    }
    Ok(sha)
}

/// Move a downloaded file into the store after verifying its hash.
pub fn adopt_file(path: &Path, expect_sha: &str) -> Result<()> {
    let got = sha256_file(path)?;
    ensure!(got == expect_sha, "hash mismatch: expected {expect_sha}, got {got} (corrupt or malicious source)");
    std::fs::rename(path, blob_path(expect_sha)).or_else(|_| std::fs::copy(path, blob_path(expect_sha)).map(|_| ()))?;
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn get_blob(sha: &str) -> Result<Vec<u8>> {
    let b = std::fs::read(blob_path(sha)).with_context(|| format!("blob {sha} not in local store"))?;
    ensure!(sha256_hex(&b) == sha, "local blob {sha} is corrupt");
    Ok(b)
}

pub fn get_doc<T: DeserializeOwned>(sha: &str) -> Result<T> {
    Ok(serde_json::from_slice(&get_blob(sha)?)?)
}

pub fn read_json<T: DeserializeOwned>(p: &Path) -> Result<Option<T>> {
    match std::fs::read(p) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("parsing {}", p.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

// ---------- keys ----------

pub fn key_path(name: &str) -> PathBuf {
    home().join("keys").join(format!("{name}.key"))
}

pub fn write_key(path: &Path, k: &SigningKey) -> Result<()> {
    ensure!(!path.exists(), "{} already exists, refusing to overwrite a key", path.display());
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    std::io::Write::write_all(&mut o.open(path)?, hex::encode(k.to_bytes()).as_bytes())?;
    Ok(())
}

pub fn load_key_file(path: &Path) -> Result<SigningKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading key {}", path.display()))?;
    let b: [u8; 32] = hex::decode(s.trim()).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| anyhow!("malformed key file {}", path.display()))?;
    Ok(SigningKey::from_bytes(&b))
}

/// Key named `name`, or from $GITSEED_KEY_FILE (for CI).
pub fn load_key(name: &str) -> Result<SigningKey> {
    if let Some(p) = std::env::var_os("GITSEED_KEY_FILE") {
        return load_key_file(Path::new(&p));
    }
    load_key_file(&key_path(name)).map_err(|e| anyhow!("{e:#}\nhint: run `gitseed keygen` first"))
}

pub fn new_key() -> SigningKey {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    SigningKey::from_bytes(&b)
}

pub fn pk_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

// ---------- pins: what this machine has seen and trusts ----------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Pin {
    /// Address the user first asked for (stable even after root rotation).
    pub address: String,
    /// Current trusted root (follows rotations).
    pub root: String,
    pub policy: String,
    pub policy_seq: i64,
    pub manifest: Option<String>,
    pub manifest_seq: i64,
    /// Every tag -> sha ever seen for this project. Tags are immutable.
    pub tags: BTreeMap<String, String>,
    /// Every release file ("tag/name" -> sha256) ever seen. Release files are immutable.
    #[serde(default)]
    pub assets: BTreeMap<String, String>,
    /// Every manifest hash ever accepted (never deleted).
    pub history: Vec<String>,
    pub pinned_at: i64,
    /// True once the user explicitly accepted this key or a proof verified it.
    pub trusted: bool,
}

pub fn pin_path(a: &Address) -> PathBuf {
    home().join("projects").join(format!("{}.json", a.file_id()))
}

pub fn load_pin(a: &Address) -> Result<Option<Pin>> {
    read_json(&pin_path(a))
}

pub fn save_pin(a: &Address, p: &Pin) -> Result<()> {
    write_json(&pin_path(a), p)
}

pub fn all_pins() -> Vec<(Address, Pin)> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(home().join("projects")) {
        for e in rd.flatten() {
            if let Ok(Some(p)) = read_json::<Pin>(&e.path()) {
                if let Ok(a) = Address::parse(&p.address) {
                    out.push((a, p));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn policy(root: &SigningKey, next: &SigningKey, maint: &SigningKey, seq: i64) -> Policy {
        let mut p = Policy {
            v: 1,
            name: "demo".into(),
            root: pk_hex(root),
            seq,
            next_root: pk_hex(next),
            prev_root: None,
            maintainers: vec![Maintainer { key: pk_hex(maint), label: "m".into(), scope: None, expires: None }],
            revoked: vec![],
            require_signed: "none".into(),
            git_signers: vec![],
            unsigned_ok: vec![],
            proofs: vec![],
            sig: String::new(),
        };
        p.sign(root);
        p
    }

    #[test]
    fn policy_rules() {
        let (r, n, m, thief) = (new_key(), new_key(), new_key(), new_key());
        let p1 = policy(&r, &n, &m, 1);
        p1.check().unwrap();

        // tampering breaks the signature
        let mut bad = p1.clone();
        bad.maintainers[0].key = pk_hex(&thief);
        assert!(bad.check().is_err());

        // root may update maintainers but not the next_root commitment
        let mut p2 = policy(&r, &n, &thief, 2);
        p1.allows_successor(&p2).unwrap();
        p2.next_root = pk_hex(&thief);
        p2.sign(&r);
        assert!(p1.allows_successor(&p2).is_err(), "stolen root must not hijack rotation");

        // only the pre-committed next key can rotate
        let mut rot = policy(&n, &new_key(), &m, 3);
        rot.prev_root = Some(pk_hex(&r));
        rot.sign(&n);
        p1.allows_successor(&rot).unwrap();
        let mut forged = policy(&thief, &new_key(), &thief, 3);
        forged.prev_root = Some(pk_hex(&r));
        forged.sign(&thief);
        assert!(p1.allows_successor(&forged).is_err());

        // seq far in the future is rejected
        let fut = policy(&r, &n, &m, now_us() + 3600 * 1_000_000);
        assert!(fut.check().is_err());

        // revocation
        let mut p3 = policy(&r, &n, &m, 4);
        p3.maintainers.push(Maintainer { key: pk_hex(&thief), label: String::new(), scope: None, expires: None });
        p3.revoked.push(Revoked { key: pk_hex(&thief), after: 100 });
        assert!(p3.maintainer(&pk_hex(&thief), 50).is_ok());
        assert!(p3.maintainer(&pk_hex(&thief), 150).is_err());
        assert!(p3.maintainer(&pk_hex(&new_key()), 1).is_err());
    }

    #[test]
    fn manifest_sig_and_refs() {
        let m = new_key();
        let mut man = Manifest { v: 1, root: pk_hex(&m), name: "demo".into(), signer: pk_hex(&m), seq: 1, ..Default::default() };
        man.refs.insert("refs/heads/main".into(), RefEntry { sha: "a".repeat(40), segs: vec![] });
        man.sign(&m);
        man.check().unwrap();
        let mut t = man.clone();
        t.refs.get_mut("refs/heads/main").unwrap().sha = "b".repeat(40);
        assert!(t.check().is_err());
        for bad in ["refs/replace/x", "refs/stash", "refs/heads/../x", "refs/heads/.x", "HEAD"] {
            assert!(!ref_ok(bad), "{bad}");
        }
        assert!(ref_ok("refs/tags/v1.2.3"));
    }
}
