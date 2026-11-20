//! Transports. Every blob is identified by sha256 and verified after fetching, whatever the source:
//! local store -> mirrors (directory or HTTP(S)/onion via proxy) -> BitTorrent swarm.
//! Pointers ("records") are BEP44 mutable items on the Mainline DHT and are also copied
//! into mirrors and the local store, so a DHT eclipse alone cannot hide them.
use crate::core::*;
use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use mainline::MutableItem;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;

// ---------- deterministic torrents ----------

/// Piece length for a blob: deterministic function of size (anyone holding the blob can recreate the same infohash).
pub fn piece_len(size: u64) -> u64 {
    let mut pl = 16 * 1024;
    while size.div_ceil(pl) > 1500 && pl < 16 * 1024 * 1024 {
        pl *= 2;
    }
    pl
}

/// Single-file BitTorrent v1 metainfo named after the sha256. Returns (infohash hex, .torrent bytes).
pub fn torrent_for(path: &Path, sha: &str) -> Result<(String, Vec<u8>)> {
    use std::io::Read;
    let size = std::fs::metadata(path)?.len();
    let pl = piece_len(size);
    let mut f = std::fs::File::open(path)?;
    let mut pieces = Vec::new();
    let mut buf = vec![0u8; pl as usize];
    loop {
        let mut n = 0;
        while n < buf.len() {
            let r = f.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        if n == 0 {
            break;
        }
        pieces.extend_from_slice(&sha1_smol::Sha1::from(&buf[..n]).digest().bytes());
        if n < buf.len() {
            break;
        }
    }
    let mut info = format!("d6:lengthi{size}e4:name{}:{sha}12:piece lengthi{pl}e6:pieces{}:", sha.len(), pieces.len()).into_bytes();
    info.extend_from_slice(&pieces);
    info.push(b'e');
    let ih = hex::encode(sha1_smol::Sha1::from(&info).digest().bytes());
    let mut t = b"d4:info".to_vec();
    t.extend_from_slice(&info);
    t.push(b'e');
    Ok((ih, t))
}

pub fn blob_meta(path: &Path) -> Result<Blob> {
    let sha = sha256_file(path)?;
    let (ih, _) = torrent_for(path, &sha)?;
    Ok(Blob { sha256: sha, size: std::fs::metadata(path)?.len(), ih })
}

// ---------- records (BEP44 items, portable) ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub k: String,
    pub salt: String, // hex
    pub seq: i64,
    pub v: String, // the raw value (JSON text)
    pub sig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Pointer {
    /// sha256 of the pointed-to document (policy.json or manifest.json)
    pub d: String,
    pub ih: String,
}

pub fn policy_salt(name: &str) -> Vec<u8> {
    format!("gitseed:{name}").into_bytes()
}
/// Salt of a maintainer's snapshot pointer. Independent of the root key so it survives rotations.
pub fn pointer_salt(name: &str) -> Vec<u8> {
    format!("gitseed-m:{name}").into_bytes()
}

impl Record {
    pub fn new(key: &SigningKey, salt: &[u8], p: &Pointer) -> Self {
        let v = serde_json::to_string(p).unwrap();
        let item = MutableItem::new(key.clone(), v.as_bytes(), now_us(), Some(salt));
        Self::from_item(&item)
    }
    pub fn from_item(i: &MutableItem) -> Self {
        Record {
            k: hex::encode(i.key()),
            salt: hex::encode(i.salt().unwrap_or_default()),
            seq: i.seq(),
            v: String::from_utf8_lossy(i.value()).into_owned(),
            sig: hex::encode(i.signature()),
        }
    }
    pub fn verify(&self) -> Result<Pointer> {
        let pk = parse_pk(&self.k)?;
        let salt = hex::decode(&self.salt)?;
        let sig: [u8; 64] = hex::decode(&self.sig)?.try_into().map_err(|_| anyhow!("bad record signature"))?;
        // BEP44 signable: 4:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>
        let mut signable = format!("4:salt{}:", salt.len()).into_bytes();
        signable.extend_from_slice(&salt);
        signable.extend_from_slice(format!("3:seqi{}e1:v{}:", self.seq, self.v.len()).as_bytes());
        signable.extend_from_slice(self.v.as_bytes());
        pk.verify(&signable, &Signature::from_bytes(&sig)).map_err(|_| anyhow!("record signature invalid"))?;
        ensure!(self.seq <= now_us() + MAX_FUTURE_US, "record dated in the future");
        let p: Pointer = serde_json::from_str(&self.v)?;
        ensure!(is_hex(&p.d, 64) && is_hex(&p.ih, 40), "malformed record value");
        Ok(p)
    }
    pub fn item(&self) -> Result<MutableItem> {
        let k: [u8; 32] = hex::decode(&self.k)?.try_into().map_err(|_| anyhow!("bad key"))?;
        let sig: [u8; 64] = hex::decode(&self.sig)?.try_into().map_err(|_| anyhow!("bad sig"))?;
        Ok(MutableItem::new_signed_unchecked(k, sig, self.v.as_bytes(), self.seq, Some(&hex::decode(&self.salt)?)))
    }
    pub fn target(&self) -> String {
        let k: [u8; 32] = hex::decode(&self.k).unwrap_or_default().try_into().unwrap_or([0; 32]);
        hex::encode(MutableItem::target_from_key(&k, Some(&hex::decode(&self.salt).unwrap_or_default())).as_bytes())
    }
}

pub fn record_path(target: &str) -> PathBuf {
    home().join("records").join(format!("{target}.json"))
}

/// Keep the newest valid record per target locally (for republishing and for mirrors).
pub fn store_record(r: &Record) -> Result<()> {
    r.verify()?;
    let p = record_path(&r.target());
    if let Some(old) = read_json::<Record>(&p)? {
        if old.seq >= r.seq {
            return Ok(());
        }
    }
    write_json(&p, r)
}

pub fn local_record(pk: &str, salt: &[u8]) -> Option<Record> {
    let k: [u8; 32] = hex::decode(pk).ok()?.try_into().ok()?;
    let t = hex::encode(MutableItem::target_from_key(&k, Some(salt)).as_bytes());
    read_json(&record_path(&t)).ok().flatten()
}

pub fn all_records() -> Vec<Record> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(home().join("records")) {
        for e in rd.flatten() {
            if let Ok(Some(r)) = read_json::<Record>(&e.path()) {
                v.push(r);
            }
        }
    }
    v
}

// ---------- configuration shared by client and seeder ----------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NetConfig {
    /// Mirrors to try: local directories or http(s):// base URLs (static mirror layout).
    pub mirrors: Vec<String>,
    /// Extra BitTorrent peers to always try (ip:port).
    pub peers: Vec<String>,
    /// socks5://host:port for ALL outgoing traffic (HTTP and BitTorrent). Note: DHT (UDP) cannot use SOCKS;
    /// set `dht = false` to keep all traffic on the proxy.
    pub proxy: Option<String>,
    /// Bind BitTorrent to this interface (e.g. a VPN's wg0).
    pub bind_interface: Option<String>,
    /// Use the Mainline DHT (default true).
    pub dht: Option<bool>,
    /// DHT bootstrap nodes (host:port). Defaults to the public ones.
    pub bootstrap: Vec<String>,
    /// TCP port for BitTorrent (0 = random).
    pub port: u16,
    pub up_kbps: Option<u32>,
    pub down_kbps: Option<u32>,
}

impl NetConfig {
    pub fn load() -> Result<Self> {
        let p = home().join("config.toml");
        let mut c: NetConfig = match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))?,
            Err(_) => NetConfig::default(),
        };
        if let Ok(b) = std::env::var("GITSEED_BOOTSTRAP") {
            c.bootstrap = b.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        }
        if let Ok(m) = std::env::var("GITSEED_MIRRORS") {
            c.mirrors.extend(m.split(',').filter(|s| !s.is_empty()).map(String::from));
        }
        if let Ok(p) = std::env::var("GITSEED_PEERS") {
            c.peers.extend(p.split(',').filter(|s| !s.is_empty()).map(String::from));
        }
        if std::env::var("GITSEED_NO_DHT").is_ok() {
            c.dht = Some(false);
        }
        Ok(c)
    }
    pub fn dht_on(&self) -> bool {
        self.dht.unwrap_or(true)
    }
}

// ---------- the network handle ----------

pub struct Net {
    pub cfg: NetConfig,
    dht: Option<mainline::async_dht::AsyncDht>,
    swarm: tokio::sync::OnceCell<Arc<librqbit::Session>>,
    http: ureq::Agent,
}

impl Net {
    pub fn new(cfg: NetConfig) -> Result<Self> {
        let dht = if cfg.dht_on() {
            let mut b = mainline::Dht::builder();
            if !cfg.bootstrap.is_empty() {
                b.bootstrap(&cfg.bootstrap);
            }
            Some(b.build().context("starting DHT")?.as_async())
        } else {
            None
        };
        let mut hb = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(60))).http_status_as_error(true);
        if let Some(p) = &cfg.proxy {
            hb = hb.proxy(Some(ureq::Proxy::new(p)?));
        }
        Ok(Net { cfg, dht, swarm: tokio::sync::OnceCell::new(), http: hb.build().into() })
    }

    pub fn offline() -> Self {
        let mut cfg = NetConfig::load().unwrap_or_default();
        cfg.dht = Some(false);
        Net::new(cfg).unwrap()
    }

    // ----- DHT -----

    pub async fn dht_get(&self, pk: &str, salt: &[u8]) -> Option<Record> {
        let dht = self.dht.as_ref()?;
        let k: [u8; 32] = hex::decode(pk).ok()?.try_into().ok()?;
        let item = tokio::time::timeout(Duration::from_secs(20), dht.get_mutable_most_recent(&k, Some(salt))).await.ok()??;
        let r = Record::from_item(&item);
        r.verify().ok()?;
        Some(r)
    }

    pub async fn dht_put(&self, r: &Record) -> Result<()> {
        let dht = self.dht.as_ref().ok_or_else(|| anyhow!("DHT disabled"))?;
        tokio::time::timeout(Duration::from_secs(60), dht.put_mutable(r.item()?, None)).await.map_err(|_| anyhow!("DHT put timed out"))?.map_err(|e| anyhow!("DHT put: {e}"))?;
        Ok(())
    }

    /// Best record for (pk, salt) from every source we know: DHT, local store, mirrors.
    pub async fn record(&self, pk: &str, salt: &[u8]) -> Option<Record> {
        let mut best = local_record(pk, salt);
        let mut consider = |r: Record| {
            if r.verify().is_ok() && r.k == pk && hex::decode(&r.salt).ok().as_deref() == Some(salt) && best.as_ref().is_none_or(|b| r.seq > b.seq) {
                best = Some(r);
            }
        };
        if let Some(r) = self.dht_get(pk, salt).await {
            consider(r);
        }
        for m in self.cfg.mirrors.clone() {
            if let Ok(idx) = self.mirror_index(&m) {
                for r in idx.records {
                    consider(r);
                }
            }
        }
        if let Some(b) = &best {
            let _ = store_record(b);
        }
        best
    }

    pub async fn dht_peer_count(&self, ih: &str) -> usize {
        let Some(dht) = &self.dht else { return 0 };
        let Ok(id) = mainline::Id::from_bytes(<[u8; 20]>::try_from(hex::decode(ih).unwrap_or_default().as_slice()).unwrap_or([0; 20])) else { return 0 };
        let mut s = dht.get_peers(id);
        let mut set = std::collections::HashSet::new();
        use futures::StreamExt;
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(peers) = s.next().await {
                set.extend(peers);
            }
        })
        .await;
        set.len()
    }

    // ----- mirrors -----

    fn mirror_get(&self, base: &str, rel: &str, max: u64) -> Result<Vec<u8>> {
        if base.starts_with("http://") || base.starts_with("https://") {
            let url = format!("{}/{rel}", base.trim_end_matches('/'));
            let mut r = self.http.get(&url).call().with_context(|| format!("GET {url}"))?;
            Ok(r.body_mut().with_config().limit(max).read_to_vec()?)
        } else {
            let p = Path::new(base).join(rel);
            ensure!(std::fs::metadata(&p)?.len() <= max, "mirror file too large");
            Ok(std::fs::read(p)?)
        }
    }

    pub fn mirror_index(&self, base: &str) -> Result<MirrorIndex> {
        Ok(serde_json::from_slice(&self.mirror_get(base, "index.json", 64 << 20)?)?)
    }

    // ----- swarm -----

    pub async fn swarm(&self) -> Result<Arc<librqbit::Session>> {
        self.swarm
            .get_or_try_init(|| async {
                let c = &self.cfg;
                let mut opts = librqbit::SessionOptions {
                    persistence: None,
                    fastresume: false,
                    disable_trackers: true,
                    bind_device_name: c.bind_interface.clone(),
                    listen: Some(librqbit::ListenerOptions {
                        listen_addr: (std::net::Ipv4Addr::UNSPECIFIED, c.port).into(),
                        ipv4_only: true,
                        ..Default::default()
                    }),
                    connect: Some(librqbit::ConnectionOptions { proxy_url: c.proxy.clone(), ..Default::default() }),
                    ipv4_only: true,
                    disable_local_service_discovery: !c.dht_on(),
                    ..Default::default()
                };
                if !c.dht_on() {
                    opts.dht = None;
                } else if !c.bootstrap.is_empty() {
                    opts.dht = Some(librqbit::DhtSessionConfig { bootstrap_addrs: Some(c.bootstrap.clone()), port: None, persistence: None });
                }
                opts.ratelimits.upload_bps = c.up_kbps.and_then(|k| std::num::NonZeroU32::new(k.saturating_mul(1024)));
                opts.ratelimits.download_bps = c.down_kbps.and_then(|k| std::num::NonZeroU32::new(k.saturating_mul(1024)));
                librqbit::Session::new_with_opts(home().join("blobs"), opts).await
            })
            .await
            .cloned()
    }

    fn peers(&self) -> Option<Vec<SocketAddr>> {
        let v: Vec<SocketAddr> = self.cfg.peers.iter().filter_map(|p| p.parse().ok()).collect();
        (!v.is_empty()).then_some(v)
    }

    /// Start seeding a blob that is in the local store.
    pub async fn seed(&self, sha: &str) -> Result<()> {
        let path = blob_path(sha);
        let (_, bytes) = torrent_for(&path, sha)?;
        let s = self.swarm().await?;
        s.add_torrent(
            librqbit::AddTorrent::TorrentFileBytes(bytes.into()),
            Some(librqbit::AddTorrentOptions { overwrite: true, output_folder: Some(home().join("blobs").to_string_lossy().into()), initial_peers: self.peers(), ..Default::default() }),
        )
        .await?;
        Ok(())
    }

    pub async fn unseed(&self, ih: &str) {
        if let (Some(s), Ok(id)) = (self.swarm.get(), librqbit::dht::Id20::from_str(ih)) {
            let _ = s.delete(librqbit::api::TorrentIdOrHash::Hash(id), false).await;
        }
    }

    /// One download attempt; the whole thing (magnet metadata resolution included) is time-boxed.
    async fn swarm_try(&self, b: &Blob, dir: &Path, t: Duration) -> Result<()> {
        let s = self.swarm().await?;
        let magnet = format!("magnet:?xt=urn:btih:{}", b.ih);
        let opts = librqbit::AddTorrentOptions { overwrite: true, output_folder: Some(dir.to_string_lossy().into()), initial_peers: self.peers(), ..Default::default() };
        let res = tokio::time::timeout(t, async {
            let h = s.add_torrent(librqbit::AddTorrent::Url(magnet.into()), Some(opts)).await?.into_handle().ok_or_else(|| anyhow!("torrent not added"))?;
            let r = h.wait_until_completed().await;
            Ok::<_, anyhow::Error>((h.id(), r))
        })
        .await;
        match res {
            Ok(Ok((id, r))) => {
                let _ = s.delete(librqbit::api::TorrentIdOrHash::Id(id), false).await;
                r
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                if let Ok(id) = librqbit::dht::Id20::from_str(&b.ih) {
                    let _ = s.delete(librqbit::api::TorrentIdOrHash::Hash(id), false).await;
                }
                bail!("timed out")
            }
        }
    }

    /// Retry until `timeout`: peers (and the seeder itself) may appear later.
    async fn swarm_fetch(&self, b: &Blob, timeout: Duration) -> Result<()> {
        ensure!(self.cfg.dht_on() || self.peers().is_some(), "no swarm sources (DHT off and no peers configured)");
        let dir = home().join("tmp").join(format!("dl-{}", b.sha256));
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last = anyhow!("no attempt");
        while tokio::time::Instant::now() < deadline {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir)?;
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.swarm_try(b, &dir, left.min(Duration::from_secs(20))).await {
                Ok(()) => {
                    adopt_file(&dir.join(&b.sha256), &b.sha256)?;
                    let _ = std::fs::remove_dir_all(&dir);
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        bail!("no peers delivered {} within {timeout:?} ({last:#})", &b.sha256[..12])
    }

    /// Get a blob into the local store from any source; always verified by sha256.
    pub async fn fetch(&self, b: &Blob, webseeds: &[String]) -> Result<()> {
        ensure!(is_hex(&b.sha256, 64) && is_hex(&b.ih, 40), "malformed hash");
        if has_blob(&b.sha256) {
            return Ok(());
        }
        let mut errs = vec![];
        let mut sources: Vec<String> = self.cfg.mirrors.clone();
        sources.extend(webseeds.iter().cloned());
        for m in sources {
            let r = self.mirror_get(&m, &format!("blobs/{}", b.sha256), b.size.max(1)).and_then(|bytes| {
                ensure!(sha256_hex(&bytes) == b.sha256, "mirror {m} served corrupt data");
                put_blob(&bytes).map(|_| ())
            });
            match r {
                Ok(()) => return Ok(()),
                Err(e) => errs.push(format!("{m}: {e:#}")),
            }
        }
        let t = Duration::from_secs(std::env::var("GITSEED_SWARM_TIMEOUT").ok().and_then(|s| s.parse().ok()).unwrap_or(120));
        match self.swarm_fetch(b, t).await {
            Ok(()) => Ok(()),
            Err(e) => {
                errs.push(format!("swarm: {e:#}"));
                bail!("could not fetch {}:\n  {}\nhint: a host may seed only some branches/tags — try `--ref <tag or branch>`, another mirror (GITSEED_MIRRORS), or the DHT", &b.sha256[..12], errs.join("\n  "))
            }
        }
    }

    /// Fetch a small signed document (policy/manifest) by hash, size-capped.
    pub async fn fetch_doc(&self, p: &Pointer, webseeds: &[String]) -> Result<Vec<u8>> {
        if !has_blob(&p.d) {
            self.fetch(&Blob { sha256: p.d.clone(), size: 8 << 20, ih: p.ih.clone() }, webseeds).await?;
        }
        get_blob(&p.d)
    }
}


/// `index.json` of the mirror layout: <dir>/index.json + <dir>/blobs/<sha256>.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MirrorIndex {
    pub v: u32,
    pub projects: Vec<MirrorEntry>,
    pub records: Vec<Record>,
    /// DHT bootstrap hints (ip:port of long-lived nodes), so a seized router.* name doesn't matter.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Indexer-published blocklist (manifest or project hashes), transparent by design.
    #[serde(default)]
    pub blocked: Vec<String>,
    pub generated: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MirrorEntry {
    pub address: String,
    pub policy: String,
    pub manifest: String,
    #[serde(default)]
    pub history: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn records_roundtrip_and_tamper() {
        let k = new_key();
        let r = Record::new(&k, b"gitseed:demo", &Pointer { d: "a".repeat(64), ih: "b".repeat(40) });
        assert_eq!(r.verify().unwrap().d, "a".repeat(64));
        let mut t = r.clone();
        t.v = t.v.replace('a', "c");
        assert!(t.verify().is_err());
        let it = r.item().unwrap();
        assert_eq!(Record::from_item(&it), r);
    }
    #[test]
    fn torrent_is_deterministic() {
        let d = std::env::temp_dir().join(format!("gs-t-{}", std::process::id()));
        std::fs::write(&d, vec![7u8; 100_000]).unwrap();
        let sha = sha256_file(&d).unwrap();
        let (a, _) = torrent_for(&d, &sha).unwrap();
        let (b, _) = torrent_for(&d, &sha).unwrap();
        assert_eq!(a, b);
        std::fs::remove_file(d).unwrap();
    }
}
