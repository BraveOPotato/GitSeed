mod core;
mod git;
mod net;
mod ops;
mod seed;
mod trust;
mod web;

use crate::core::*;
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "gitseed", version, about = "Peer-to-peer git hosting that survives takedowns.\n\nPublish:  gitseed init && gitseed publish\nGet:      gitseed clone gitseed://<key>/<name>\nVerify:   gitseed verify gitseed://<key>/<name> --ref v1.0\nHost:     gitseed seed add gitseed://<key>/<name> && gitseed seed")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your publishing key and a separate recovery (next) key.
    Keygen {
        #[arg(long, default_value = "default")]
        name: String,
        /// Write the recovery key here (e.g. a USB stick) instead of keeping it on this machine.
        #[arg(long)]
        recovery_out: Option<PathBuf>,
    },
    /// Show your keys and where things are stored.
    Whoami {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Write a .gitseed file for this repository.
    Init {
        #[arg(long)]
        name: Option<String>,
        /// Join an existing project as a co-maintainer (its gitseed:// address).
        #[arg(long)]
        address: Option<String>,
        /// Refs to publish (default: all branches and tags). e.g. --include main --include 'v*'
        #[arg(long)]
        include: Vec<String>,
        /// URL that will contain your key (e.g. https://example.org/.well-known/gitseed).
        #[arg(long)]
        proof: Vec<String>,
        /// none | tags | all
        #[arg(long, default_value = "none")]
        require_signed: String,
        /// ssh public key file of a git signer, as principal=path (e.g. alice@x.org=~/.ssh/id_ed25519.pub)
        #[arg(long)]
        git_signer: Vec<String>,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value = "")]
        license: String,
    },
    /// Publish (or update) this repository. Safe to run repeatedly: only new history is uploaded.
    Publish {
        #[arg(long)]
        dry_run: bool,
        /// Confirm the first publish non-interactively (it is permanent).
        #[arg(long)]
        yes_forever: bool,
        #[arg(long)]
        allow_secrets: bool,
        /// Allow publishing rewritten branch history.
        #[arg(long)]
        force: bool,
        /// Keep seeding until N other peers fetched the new data.
        #[arg(long, default_value_t = 0)]
        wait_seeders: usize,
        /// This repo is a clone of another project: publish it as a NEW project under your own key.
        #[arg(long)]
        fork: bool,
    },
    /// Publish a release: a (signed) tag plus release files, all pinned by hash in the signed snapshot.
    Release {
        tag: String,
        files: Vec<PathBuf>,
        #[arg(long)]
        yes_forever: bool,
    },
    /// Ask mirrors to stop listing an earlier snapshot (advisory; the data may already be copied).
    Retract { snapshot: String },
    /// Add or remove a maintainer key (requires the root key).
    Maintainer {
        #[command(subcommand)]
        op: MaintOp,
    },
    /// Rotate your root key to the pre-committed recovery key (e.g. after losing your laptop).
    Rotate {
        #[arg(long, default_value = "default")]
        key: String,
        /// Your offline recovery key file.
        #[arg(long)]
        recovery_key: Option<PathBuf>,
        /// The project's address (default: from .gitseed / this clone).
        #[arg(long)]
        address: Option<String>,
    },
    /// Download and verify a project.
    Clone {
        address: String,
        dir: Option<PathBuf>,
        /// Only these refs (branch, tag, or glob). Repeatable.
        #[arg(long = "ref")]
        refs: Vec<String>,
        #[arg(long)]
        trust_new_key: bool,
    },
    /// Update a clone, showing what changed and who signed it first.
    Pull {
        #[arg(long)]
        yes: bool,
        /// Ignore the waiting period (git config gitseed.delay, hours).
        #[arg(long)]
        now: bool,
    },
    /// Show every branch, tag and release with who signed it, and check authorship.
    #[command(alias = "refs")]
    Verify {
        address: Option<String>,
        #[arg(long = "ref")]
        refs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Check that a downloaded file (e.g. a release binary) is a signed release file of the project.
    VerifyFile { address: String, file: PathBuf },
    /// Search projects this machine knows (from clones, seeds and imported indexes).
    Search { query: Vec<String> },
    /// Host projects. `gitseed seed` runs the daemon; subcommands manage what it seeds.
    Seed {
        #[command(subcommand)]
        op: Option<SeedOp>,
    },
    /// Copies in the swarm of each project's critical data, least-seeded first.
    Health {
        #[arg(long)]
        needs_me: bool,
    },
    /// Delete stored data no rule needs any more.
    Gc {
        #[arg(long)]
        dry_run: bool,
    },
    /// Stop hosting a project and delete its data (e.g. after a takedown request).
    Block { address: String },
    /// Undo `block`.
    Unblock { address: String },
    /// Write a self-contained mirror (static website + data) to DIR. Copy it anywhere.
    Export {
        dir: PathBuf,
        addresses: Vec<String>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        site: bool,
    },
    /// Learn every project a mirror lists (DIR, USB stick, or URL). Nothing becomes trusted.
    Import { source: String },
    /// Local web UI + HTTP mirror without seeding.
    Serve {
        #[arg(long, default_value = "127.0.0.1:7878")]
        listen: String,
    },
}

#[derive(Subcommand)]
enum MaintOp {
    Add {
        key: String,
        #[arg(long, default_value = "")]
        label: String,
        /// Only allow this key to change matching refs, e.g. 'refs/tags/v*' for CI.
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        expires_days: Option<i64>,
    },
    Remove { key: String },
}

#[derive(Subcommand)]
enum SeedOp {
    /// Seed a project (optionally only some branches/tags).
    Add {
        address: String,
        /// Branch patterns, e.g. --refs main --refs 'release/*'. Default: all.
        #[arg(long)]
        refs: Vec<String>,
        /// all | none | latest:N | glob (e.g. 'v2.*')
        #[arg(long)]
        tags: Option<String>,
        #[arg(long)]
        no_assets: bool,
    },
    Rm { address: String },
    /// Show what is followed and the rules.
    List,
    /// Show what a sync would fetch.
    DryRun,
    /// Fetch everything once (no daemon).
    Once,
    /// Follow the least-seeded known projects within a disk budget.
    Adopt { budget: String },
    /// RSS feed of magnet links for plain BitTorrent clients.
    Rss,
    /// Print a systemd unit for running the seeder unattended.
    Systemd,
    /// Adopt files downloaded by a plain BitTorrent client (named by their sha256) into the store.
    ImportBlobs { dir: PathBuf },
}

fn main() -> Result<()> {
    // behave like a normal CLI when piped into `head` etc. (no broken-pipe panics)
    #[cfg(unix)]
    // SAFETY: setting a signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let argv0 = std::env::args().next().unwrap_or_default();
    let helper = Path::new(&argv0).file_name().is_some_and(|n| n.to_string_lossy().starts_with("git-remote-gitseed"));
    let git_dir = std::env::var_os("GIT_DIR");
    if helper {
        // git sets these for helpers; they would redirect every git call we make to the user's repo
        for v in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX"] {
            // SAFETY: single-threaded here; no runtime or threads exist yet.
            unsafe { std::env::remove_var(v) };
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    if helper {
        return rt.block_on(remote_helper(git_dir.map(PathBuf::from)));
    }
    let cli = Cli::parse();
    let r = rt.block_on(run(cli));
    if let Err(e) = &r {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn net() -> Result<Net> {
    Net::new(net::NetConfig::load()?)
}
use net::Net;

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { name, recovery_out } => {
            let k = new_key();
            let n = new_key();
            write_key(&key_path(&name), &k)?;
            std::fs::write(home().join("keys").join(format!("{name}.next.pub")), pk_hex(&n))?;
            let rec = recovery_out.unwrap_or_else(|| home().join("keys").join(format!("{name}.next.key")));
            write_key(&rec, &n)?;
            println!("publishing key  {}  (fingerprint {})", pk_hex(&k), fpr(&pk_hex(&k)));
            println!("recovery key    {}", rec.display());
            if rec.starts_with(home()) {
                println!("\nIMPORTANT: move the recovery key to offline storage (USB stick, paper) and delete it from this machine.");
                println!("A thief who gets both keys can take your projects; with only the publishing key they cannot.");
            }
            println!("If this machine is lost or stolen, run `gitseed rotate --recovery-key <file>` from a new machine.");
        }
        Cmd::Whoami { name } => {
            let k = load_key(&name)?;
            println!("key          {}\nfingerprint  {}\nhome         {}", pk_hex(&k), fpr(&pk_hex(&k)), home().display());
            let next = home().join("keys").join(format!("{name}.next.key"));
            println!("recovery key {}", if next.exists() { "ON THIS MACHINE — move it offline" } else { "not on this machine (good)" });
            println!("\nTo prove this key is yours, serve this line at https://<your-domain>/.well-known/gitseed :\n  gitseed key: {}", pk_hex(&k));
        }
        Cmd::Init { name, address, include, proof, require_signed, git_signer, description, license } => {
            let repo = ops::repo_root(&std::env::current_dir()?)?;
            let p = repo.join(".gitseed");
            let joined = address.as_deref().map(Address::parse).transpose()?;
            if p.exists() {
                // the project's shared .gitseed is already here: joining just means "publish to that address"
                let a = joined.ok_or_else(|| anyhow!(".gitseed already exists — edit it directly (or `gitseed init --address <addr>` to join that project)"))?;
                git::git(&repo, &["config", "gitseed.address", &a.to_string()])?;
                let me = load_key("default").map(|k| pk_hex(&k)).unwrap_or_default();
                println!("this checkout now publishes to {a}\nask the root key holder to run: gitseed maintainer add {me} --label <you>");
                return Ok(());
            }
            let name = name.or_else(|| joined.as_ref().map(|a| a.name.clone())).unwrap_or_else(|| repo.file_name().unwrap().to_string_lossy().to_string());
            valid_name(&name)?;
            let mut c = ops::RepoConfig { name, address: joined.map(|a| a.to_string()), description, license, require_signed, proofs: proof, ..Default::default() };
            if !include.is_empty() {
                c.include = include;
            }
            for g in git_signer {
                let (who, path) = g.split_once('=').ok_or_else(|| anyhow!("--git-signer must be principal=path/to/key.pub"))?;
                let path = path.replacen('~', &std::env::var("HOME").unwrap_or_default(), 1);
                let pk = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
                let mut parts = pk.split_whitespace();
                c.git_signers.push(format!("{who} {} {}", parts.next().unwrap_or(""), parts.next().unwrap_or("")));
            }
            if c.require_signed != "none" {
                for (r, sha) in git::list_refs(&repo, &c.include)? {
                    if (c.require_signed == "all" || r.starts_with("refs/tags/")) && !matches!(git::verify_sig(&repo, &sha, r.starts_with("refs/tags/"), &c.git_signers), git::SigStatus::Good(_)) {
                        c.unsigned_ok.push(r);
                    }
                }
                if !c.unsigned_ok.is_empty() {
                    println!("{} existing unsigned refs were added to unsigned_ok (shown to users as legacy): {}", c.unsigned_ok.len(), c.unsigned_ok.iter().map(|r| ops::short_ref(r)).collect::<Vec<_>>().join(", "));
                }
            }
            std::fs::write(&p, toml::to_string_pretty(&c)?)?;
            let me = load_key(&c.key).map(|k| pk_hex(&k)).unwrap_or_else(|_| "<run gitseed keygen>".into());
            match &c.address {
                Some(a) => println!("wrote {}\njoining {a} — ask the root key holder to run: gitseed maintainer add {me} --label <you>", p.display()),
                None => println!("wrote {}\naddress will be gitseed://{me}/{}", p.display(), c.name),
            }
            println!("commit .gitseed so it stays with the repository (it holds no secrets).");
            if c.proofs.is_empty() {
                println!("tip: prove it's you — serve `gitseed key: {me}` at https://<your-domain>/.well-known/gitseed and add that URL to `proofs`.");
            } else {
                println!("make sure each proof URL serves the line:  gitseed key: {me}");
            }
        }
        Cmd::Publish { dry_run, yes_forever, allow_secrets, force, wait_seeders, fork } => {
            let repo = ops::repo_root(&std::env::current_dir()?)?;
            let cfg = ops::load_repo_config(&repo)?;
            let net = net()?;
            let o = ops::PublishOpts { dry_run, yes_forever, allow_secrets, allow_rewrite: force, fork, ..Default::default() };
            if let Some(p) = ops::publish(&net, &repo, &cfg, &o).await? {
                after_publish(&net, &p, wait_seeders).await?;
            }
        }
        Cmd::Release { tag, files, yes_forever } => {
            let repo = ops::repo_root(&std::env::current_dir()?)?;
            let cfg = ops::load_repo_config(&repo)?;
            let t = format!("refs/tags/{tag}");
            if !git::ok(&repo, &["rev-parse", "--verify", "-q", &t]) {
                // create the signed tag ourselves, listing every release file's hash, so the tag signer vouches for them
                let mut msg = format!("{tag}\n\nRelease files (checked by `gitseed verify-file`):\n");
                for f in &files {
                    msg.push_str(&format!("sha256 {}  {}\n", sha256_file(f)?, f.file_name().unwrap_or_default().to_string_lossy()));
                }
                if !git::ok(&repo, &["tag", "-s", &tag, "-m", &msg]) {
                    ensure!(cfg.require_signed == "none", "could not create a signed tag (configure git: gpg.format=ssh and user.signingkey)");
                    git::git(&repo, &["tag", "-a", &tag, "-m", &msg])?;
                    eprintln!("warning: created an UNSIGNED tag {tag} (git signing is not configured)");
                }
                eprintln!("created tag {tag} listing {} release file(s)", files.len());
            } else {
                let body = git::git(&repo, &["cat-file", "tag", &t]).unwrap_or_default();
                let listed = trust::listed_files(&body);
                for f in &files {
                    if !listed.contains(&sha256_file(f)?) {
                        eprintln!("warning: tag {tag} already exists and does not list {} — users will see it as \"not in the tag signature\".\n  Tip: let `gitseed release {tag} FILES` create the tag (delete your unpublished local tag first).", f.display());
                    }
                }
            }
            let sig = git::verify_sig(&repo, &t, true, &cfg.git_signers);
            match &sig {
                git::SigStatus::Good(w) => eprintln!("tag {tag} signed by {w}"),
                git::SigStatus::Unsigned if cfg.require_signed != "none" => bail!("tag {tag} is unsigned but the project requires signatures (git tag -s)"),
                git::SigStatus::Unsigned => eprintln!("warning: tag {tag} is unsigned — users will see UNSIGNED. Use `git tag -s`."),
                git::SigStatus::Bad(e) => bail!("tag signature does not verify against git_signers: {e}"),
            }
            let net = net()?;
            let mut push = vec![];
            for (r, s) in git::list_refs(&repo, &cfg.include)? {
                push.push((r, Some(s)));
            }
            let o = ops::PublishOpts { yes_forever, assets: files, release_tag: tag.clone(), push: Some(push), ..Default::default() };
            if let Some(p) = ops::publish(&net, &repo, &cfg, &o).await? {
                after_publish(&net, &p, 0).await?;
            }
        }
        Cmd::Retract { snapshot } => {
            let repo = ops::repo_root(&std::env::current_dir()?)?;
            let cfg = ops::load_repo_config(&repo)?;
            let net = net()?;
            let o = ops::PublishOpts { retract: vec![snapshot], push: Some(vec![]), ..Default::default() };
            ops::publish(&net, &repo, &cfg, &o).await?;
            println!("retraction published. Well-behaved mirrors stop listing that snapshot.");
            println!("BUT: if the secret is still reachable from a published branch, every new clone still gets it. To stop that:");
            println!("  1. rotate the secret (assume it is already copied — published data cannot be recalled)");
            println!("  2. remove it from history (e.g. git filter-repo / git rebase) and run `gitseed publish --force`");
        }
        Cmd::Maintainer { op } => {
            let repo = ops::repo_root(&std::env::current_dir()?)?;
            let mut cfg = ops::load_repo_config(&repo)?;
            match op {
                MaintOp::Add { key, label, scope, expires_days } => {
                    parse_pk(&key)?;
                    cfg.maintainers.retain(|m| m.key != key);
                    cfg.maintainers.push(Maintainer { key, label, scope, expires: expires_days.map(|d| now_us() + d * 86_400_000_000) });
                }
                MaintOp::Remove { key } => {
                    let n = cfg.maintainers.len();
                    cfg.maintainers.retain(|m| m.key != key && !m.key.starts_with(&key));
                    ensure!(cfg.maintainers.len() < n, "no such maintainer");
                }
            }
            std::fs::write(repo.join(".gitseed"), toml::to_string_pretty(&cfg)?)?;
            let net = net()?;
            ops::publish(&net, &repo, &cfg, &ops::PublishOpts { push: Some(vec![]), ..Default::default() }).await?;
            println!("updated .gitseed — commit it so the team shares the same maintainer list.");
        }
        Cmd::Rotate { key, recovery_key, address } => rotate(&key, recovery_key, address).await?,
        Cmd::Clone { address, dir, refs, trust_new_key } => {
            let net = net()?;
            ops::clone(&net, &Address::parse(&address)?, dir, &refs, trust_new_key).await?;
        }
        Cmd::Pull { yes, now } => {
            let net = net()?;
            ops::pull(&net, &ops::repo_root(&std::env::current_dir()?)?, yes, now).await?;
        }
        Cmd::Verify { address, refs, json } => {
            let a = ops::addr_or_cwd(address.as_deref())?;
            let net = net()?;
            let o = ops::verify(&net, &a, &refs, json).await?;
            if o != ops::Outcome::Ok {
                std::process::exit(o.code());
            }
        }
        Cmd::VerifyFile { address, file } => {
            let net = net()?;
            let o = ops::verify_file(&net, &Address::parse(&address)?, &file).await?;
            if o != ops::Outcome::Ok {
                std::process::exit(o.code());
            }
        }
        Cmd::Search { query } => {
            let q = query.join(" ");
            let res = seed::search(&q);
            if res.is_empty() {
                println!("no matches (try `gitseed import <mirror>` to learn more projects)");
            }
            let mut by_pid: std::collections::BTreeMap<String, usize> = Default::default();
            for (_, m) in &res {
                *by_pid.entry(m.project_id()).or_default() += 1;
            }
            for (a, m) in res {
                let trusted = load_pin(&a)?.is_some_and(|p| p.trusted);
                let n = by_pid[&m.project_id()];
                println!(
                    "{}  {}{}{}\n    {}\n    {}\n",
                    a.name,
                    fpr(&a.root),
                    if trusted { "  [trusted]" } else { "" },
                    if n > 1 { format!("  [{n} publishers of this code]") } else { String::new() },
                    m.description,
                    a
                );
            }
        }
        Cmd::Seed { op } => seed_cmd(op).await?,
        Cmd::Health { needs_me } => {
            let net = net()?;
            for (a, n, worst) in seed::health(&net).await? {
                if needs_me && n > 3 {
                    continue;
                }
                let tag = match n {
                    0 => "✖ NO OTHER COPIES FOUND",
                    1..=2 => "⚠ at risk",
                    _ => "ok",
                };
                println!("{:<24} {:>3} peers  {tag}  (scarcest segment {worst})", a.name, n);
            }
        }
        Cmd::Gc { dry_run } => {
            let freed = seed::gc(dry_run)?;
            println!("{} {} · store now {}", if dry_run { "would free" } else { "freed" }, ops::human(freed), ops::human(seed::store_usage()));
        }
        Cmd::Block { address } => {
            let a = Address::parse(&address)?;
            seed::block(&a, true)?;
            let freed = seed::gc(false)?;
            println!("blocked {a}: no longer seeded, served or listed here; freed {}", ops::human(freed));
        }
        Cmd::Unblock { address } => seed::block(&Address::parse(&address)?, false)?,
        Cmd::Export { dir, addresses, site } => {
            let a: Vec<Address> = addresses.iter().map(|s| Address::parse(s)).collect::<Result<_>>()?;
            let n = ops::export(&dir, &a, site)?;
            println!("wrote mirror to {} ({n} new file{}). Serve it from any static host, onion service, or copy it to a USB stick.", dir.display(), if n == 1 { "" } else { "s" });
        }
        Cmd::Import { source } => {
            let net = net()?;
            let n = ops::import(&net, &source).await?;
            println!("learned {n} projects from {source}. They are NOT trusted until you verify them.");
        }
        Cmd::Serve { listen } => {
            let net = Arc::new(net()?);
            println!("gitseed web UI on http://{listen}");
            web::serve(net, &listen).await?;
        }
    }
    Ok(())
}

async fn after_publish(net: &Net, p: &ops::Published, wait: usize) -> Result<()> {
    println!("\n  {}\n", p.addr);
    println!("Share that address. Anyone can now run:  gitseed clone {}", p.addr);
    if wait == 0 {
        println!("Keep `gitseed seed` running (or ask a friend/seedbox to `gitseed seed add` it) so others can download it.");
        return Ok(());
    }
    let s = net.swarm().await?;
    for b in &p.blobs {
        net.seed(b).await?;
    }
    eprintln!("seeding; waiting until {wait} peer(s) downloaded the new data (Ctrl-C to stop)…");
    let total: u64 = p.blobs.iter().filter_map(|b| std::fs::metadata(blob_path(b)).ok()).map(|m| m.len()).sum();
    loop {
        let up: u64 = s.with_torrents(|it| it.map(|(_, h)| h.stats().uploaded_bytes).sum());
        if up >= total * wait as u64 {
            println!("✔ at least {wait} other cop{} exist", if wait == 1 { "y" } else { "ies" });
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn rotate(key: &str, recovery: Option<PathBuf>, address: Option<String>) -> Result<()> {
    let repo = ops::repo_root(&std::env::current_dir()?)?;
    let mut cfg = ops::load_repo_config(&repo)?;
    let next_p = recovery.clone().unwrap_or_else(|| home().join("keys").join(format!("{key}.next.key")));
    let next = load_key_file(&next_p).map_err(|e| anyhow!("{e:#}\nPass your offline recovery key with --recovery-key <file>."))?;
    let addr = match address {
        Some(a) => Address::parse(&a)?,
        None => ops::addr_or_cwd(None).map_err(|e| anyhow!("{e:#}\nPass the project's address with --address gitseed://…"))?,
    };
    let net = net()?;
    let r = trust::resolve(&net, &addr).await?;
    ensure!(r.policy.next_root == pk_hex(&next), "this recovery key is not the one this project pre-committed to");
    let old_root = r.policy.root.clone();
    let newer_next = new_key();
    let mut p = r.policy.clone();
    p.root = pk_hex(&next);
    p.next_root = pk_hex(&newer_next);
    p.prev_root = Some(old_root.clone());
    p.seq = now_us();
    p.maintainers.retain(|m| m.key != old_root);
    p.maintainers.insert(0, Maintainer { key: pk_hex(&next), label: "root".into(), scope: None, expires: None });
    p.revoked.retain(|x| x.key != old_root);
    p.revoked.push(Revoked { key: old_root.clone(), after: now_us() });
    p.sign(&next);
    r.policy.allows_successor(&p)?;
    let sha = put_blob(&p.to_blob())?;
    let (ih, _) = net::torrent_for(&blob_path(&sha), &sha)?;
    let rec = net::Record::new(&next, &net::policy_salt(&addr.name), &net::Pointer { d: sha, ih });
    net::store_record(&rec)?;
    if let Err(e) = net.dht_put(&rec).await {
        eprintln!("warning: {e:#} (mirrors / `gitseed seed` will republish)");
    }
    // delete the old key, promote the recovery key, create a fresh recovery key
    let kp = key_path(key);
    if kp.exists() {
        std::fs::remove_file(&kp)?;
    }
    write_key(&kp, &next)?;
    if recovery.is_none() {
        std::fs::remove_file(&next_p)?;
    }
    let new_rec = match &recovery {
        Some(r) => r.with_file_name(format!("{}.new", r.file_name().unwrap().to_string_lossy())),
        None => home().join("keys").join(format!("{key}.next.key")),
    };
    write_key(&new_rec, &newer_next)?;
    std::fs::write(home().join("keys").join(format!("{key}.next.pub")), pk_hex(&newer_next))?;
    cfg.address = Some(addr.to_string());
    cfg.maintainers.retain(|m| m.key != old_root);
    std::fs::write(repo.join(".gitseed"), toml::to_string_pretty(&cfg)?)?;
    // re-sign the newest snapshot with the new key: snapshots by the revoked key are only accepted by clients that saw them before
    let mut r2 = trust::resolve(&net, &addr).await?;
    if let Some(m) = r2.manifest.clone() {
        let mut nm = m.clone();
        nm.root = p.root.clone();
        nm.signer = pk_hex(&next);
        nm.seq = now_us();
        nm.prev = r2.manifest_sha.clone();
        nm.policy = r2.policy_sha.clone();
        nm.sign(&next);
        let bytes = nm.to_blob();
        let msha = put_blob(&bytes)?;
        let (mih, _) = net::torrent_for(&blob_path(&msha), &msha)?;
        let rec = net::Record::new(&next, &net::pointer_salt(&addr.name), &net::Pointer { d: msha.clone(), ih: mih });
        net::store_record(&rec)?;
        if net.cfg.dht_on() {
            let _ = net.dht_put(&rec).await;
        }
        r2.manifest = Some(nm);
        r2.manifest_sha = Some(msha);
        r2.accept(true)?;
    }
    println!("rotated {}: root {} -> {} (old key revoked; newest snapshot re-signed).", addr, fpr(&old_root), fpr(&pk_hex(&next)));
    println!("Update https://<your-domain>/.well-known/gitseed to:  gitseed key: {}", pk_hex(&next));
    println!("Your address is unchanged; clients follow the rotation automatically.");
    println!("A NEW recovery key is at {} — move it offline and destroy the old recovery key file.", new_rec.display());
    Ok(())
}

async fn seed_cmd(op: Option<SeedOp>) -> Result<()> {
    match op {
        None => seed::daemon(Arc::new(net()?)).await?,
        Some(SeedOp::Add { address, refs, tags, no_assets }) => {
            let a = Address::parse(&address)?;
            let rule = if refs.is_empty() && tags.is_none() && !no_assets {
                None
            } else {
                let d = seed::SeedConfig::load()?.defaults;
                Some(seed::Rule { refs: if refs.is_empty() { d.refs } else { refs }, tags: tags.unwrap_or(d.tags), assets: !no_assets })
            };
            seed::add_follow(&a, rule)?;
            println!("following {a}. Run `gitseed seed` (or `gitseed seed once`) to fetch and seed it.");
        }
        Some(SeedOp::Rm { address }) => {
            seed::remove_follow(&Address::parse(&address)?)?;
            println!("removed. `gitseed gc` frees the space.");
        }
        Some(SeedOp::List) => {
            let c = seed::SeedConfig::load()?;
            println!("config {}  ·  quota {}  ·  max per project {}  ·  store {}", seed::SeedConfig::path().display(), c.disk_quota, c.max_repo, ops::human(seed::store_usage()));
            seed::warn_over_quota();
            let status = seed::last_status();
            for f in &c.follow {
                let r = f.rule.clone().unwrap_or_else(|| c.defaults.clone());
                let a = Address::parse(&f.address)?;
                let size: u64 = load_pin(&a)?.map(|p| ops::project_blobs(&p).iter().filter_map(|b| std::fs::metadata(blob_path(b)).ok()).map(|m| m.len()).sum()).unwrap_or(0);
                println!("  {:<16} branches {:?}  tags {}  assets {}  · stored {}", a.name, r.refs, r.tags, r.assets, ops::human(size));
                println!("    {}", f.address);
                if let Some(s) = status.get(&a.name) {
                    println!("    last sync: {s}");
                }
            }
            let b = seed::blocked();
            if !b.is_empty() {
                println!("blocked (not hosted, served or listed here):");
                for x in b {
                    println!("  {x}");
                }
            }
        }
        Some(SeedOp::DryRun) | Some(SeedOp::Once) => {
            let dry = matches!(op, Some(SeedOp::DryRun));
            let net = net()?;
            let rep = seed::sync_once(&net, dry).await?;
            for (name, l) in &rep.status {
                println!("{name}: {l}");
            }
            if rep.status.is_empty() {
                println!("not following anything yet — `gitseed seed add <address>`");
            }
            if !dry {
                let freed = seed::gc(false)?;
                if freed > 0 {
                    println!("gc freed {}", ops::human(freed));
                }
            }
            seed::warn_over_quota();
            if !dry && net.cfg.dht_on() {
                let (ok, fail) = seed::republish(&net).await;
                println!("DHT records republished: {ok} (failed {fail})");
            }
        }
        Some(SeedOp::Adopt { budget }) => {
            let net = net()?;
            let v = seed::adopt(&net, seed::parse_size(&budget)?).await?;
            if v.is_empty() {
                println!("nothing to adopt: every project this machine knows is already followed or too big for {budget} (learn more with `gitseed import <mirror>`)");
            }
            for l in v {
                println!("adopted {l}");
            }
        }
        Some(SeedOp::Rss) => print!("{}", seed::rss()?),
        Some(SeedOp::ImportBlobs { dir }) => {
            let (mut ok, mut bad, mut ignored) = (0, 0, 0);
            for e in std::fs::read_dir(&dir)?.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if !is_hex(&n, 64) {
                    ignored += 1;
                    continue;
                }
                if has_blob(&n) {
                    continue;
                }
                let tmp = home().join("tmp").join(&n);
                match std::fs::copy(e.path(), &tmp).map_err(anyhow::Error::from).and_then(|_| adopt_file(&tmp, &n)) {
                    Ok(()) => ok += 1,
                    Err(_) => {
                        let _ = std::fs::remove_file(&tmp);
                        bad += 1
                    }
                }
            }
            println!("imported {ok} files, {bad} rejected (content does not match the sha256 name), {ignored} ignored (not named by a sha256). Run `gitseed seed` to seed them.");
        }
        Some(SeedOp::Systemd) => {
            let exe = std::env::current_exe()?;
            println!(
                "# save as ~/.config/systemd/user/gitseed.service, then:\n#   systemctl --user enable --now gitseed\n#   loginctl enable-linger $USER     # keep it running when you are logged out\n#   journalctl --user -u gitseed -f  # logs\n# Use a release build (cargo build --release) for ExecStart.\n[Unit]\nDescription=gitseed seeder\nWants=network-online.target\n\n[Service]\nExecStart={} seed\nRestart=always\nRestartSec=30\nTimeoutStopSec=20\nNice=10\nIOSchedulingClass=idle\nIOWeight=20\nCPUQuota=50%\nMemoryMax=1G\nEnvironment=GITSEED_HOME={}\n\n[Install]\nWantedBy=default.target",
                exe.display(),
                home().display()
            );
        }
    }
    Ok(())
}

// ---------- git remote helper: `git clone gitseed://...`, `git push gitseed://... main` ----------

fn read_line_raw() -> Option<String> {
    use std::io::Read;
    let mut out = vec![];
    let mut b = [0u8; 1];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut b) {
            Ok(0) => return if out.is_empty() { None } else { Some(String::from_utf8_lossy(&out).into()) },
            Ok(_) if b[0] == b'\n' => return Some(String::from_utf8_lossy(&out).into()),
            Ok(_) => out.push(b[0]),
            Err(_) => return None,
        }
    }
}

async fn remote_helper(git_dir: Option<PathBuf>) -> Result<()> {
    use std::io::Write;
    let args: Vec<String> = std::env::args().collect();
    let url = args.get(2).cloned().ok_or_else(|| anyhow!("usage: git-remote-gitseed <remote> <url>"))?;
    let addr = Address::parse(&url)?;
    let out = || std::io::stdout().lock();
    while let Some(line) = read_line_raw() {
        match line.trim() {
            "capabilities" => {
                write!(out(), "connect\n\n")?;
                out().flush()?;
            }
            "connect git-upload-pack" => {
                let net = net()?;
                let mut r = trust::resolve(&net, &addr).await?;
                if !r.failures.is_empty() {
                    eprint!("{}", ops::view(&r, &[]));
                    bail!("verification failed");
                }
                let accepted = match r.identity {
                    trust::Identity::Unknown if std::env::var("GITSEED_TRUST_NEW_KEY").is_err() => {
                        eprintln!("gitseed: {} is an UNKNOWN key (fingerprint {}).\nRun `gitseed clone {addr}` to review it, or set GITSEED_TRUST_NEW_KEY=1.", addr, fpr(&r.policy.root));
                        bail!("untrusted key");
                    }
                    trust::Identity::Unknown => true,
                    _ => false,
                };
                let m = r.manifest.clone().ok_or_else(|| anyhow!("no snapshot yet"))?;
                let refs = ops::expand_refs(&m, &[])?;
                let (cache, old) = ops::sync_cache(&net, &r, &refs).await?;
                let reports = trust::ref_reports(&cache, &r, &old);
                // everything goes to stderr: stdout is the git protocol
                if let Some(f) = reports.iter().find(|x| matches!(x.verdict, trust::Verdict::Fail(_))) {
                    eprint!("{}", ops::view(&r, &reports));
                    bail!("ref {} failed verification", f.name);
                }
                let rewritten = reports.iter().any(|x| x.note.starts_with("history rewritten"));
                if (!r.warnings.is_empty() || rewritten) && std::env::var("GITSEED_ACCEPT_WARNINGS").is_err() {
                    eprint!("{}", ops::view(&r, &reports));
                    eprintln!("gitseed: this update needs your review. Run `gitseed pull` to see it and accept, or set GITSEED_ACCEPT_WARNINGS=1.");
                    bail!("update not accepted");
                }
                if let Some(o) = r.pin.manifest.as_ref().and_then(|s| get_doc::<Manifest>(s).ok()) {
                    eprint!("{}", ops::changes(&cache, &o, &m));
                }
                eprintln!("gitseed: {} — {}", addr.name, ops::identity_line(&r));
                r.accept(accepted)?;
                write!(out(), "\n")?;
                out().flush()?;
                let st = std::process::Command::new("git").args(["upload-pack", cache.to_str().unwrap()]).status()?;
                std::process::exit(st.code().unwrap_or(1));
            }
            "connect git-receive-pack" => {
                let gd = git_dir.clone().map(|g| if g.is_absolute() { g } else { std::env::current_dir().unwrap_or_default().join(g) });
                let repo = match &gd {
                    Some(g) => PathBuf::from(git::git(Path::new("."), &["--git-dir", g.to_str().unwrap(), "rev-parse", "--show-toplevel"])?.trim()),
                    None => ops::repo_root(&std::env::current_dir()?)?,
                };
                let cfg = ops::load_repo_config(&repo)?;
                let net = net()?;
                // staging repo = the published state, sharing objects with the cache
                let staging = home().join("staging").join(format!("{}.git", addr.file_id()));
                let _ = std::fs::remove_dir_all(&staging);
                std::fs::create_dir_all(&staging)?;
                git::git(&staging, &["init", "-q", "--bare"])?;
                git::git(&staging, &["config", "receive.denyNonFastForwards", "false"])?;
                let mut before = std::collections::BTreeMap::new();
                if let Ok(r) = trust::resolve(&net, &addr).await {
                    if let Some(m) = &r.manifest {
                        let (cache, _) = ops::sync_cache(&net, &r, &ops::expand_refs(m, &[])?).await?;
                        std::fs::write(staging.join("objects/info/alternates"), format!("{}\n", cache.join("objects").display()))?;
                        for (n, e) in &m.refs {
                            git::git(&staging, &["update-ref", n, &e.sha])?;
                            before.insert(n.clone(), e.sha.clone());
                        }
                    }
                }
                write!(out(), "\n")?;
                out().flush()?;
                let st = std::process::Command::new("git").args(["receive-pack", staging.to_str().unwrap()]).status()?;
                ensure!(st.success(), "receive-pack failed");
                let after: std::collections::BTreeMap<String, String> = git::git(&staging, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"])?
                    .lines()
                    .filter_map(|l| l.split_once(' '))
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect();
                let mut push = vec![];
                for (n, s) in &after {
                    if before.get(n) != Some(s) {
                        if !cfg.include.iter().any(|p| git::glob(p, n)) {
                            eprintln!("gitseed: NOT publishing {n}: it is not in `include` in .gitseed (add it there to publish it)");
                            continue;
                        }
                        push.push((n.clone(), Some(s.clone())));
                    }
                }
                for n in before.keys().filter(|n| !after.contains_key(*n)) {
                    eprintln!("gitseed: removing {n} from the newest snapshot (its commits stay in published history)");
                    push.push((n.clone(), None));
                }
                if push.is_empty() {
                    return Ok(());
                }
                let o = ops::PublishOpts { push: Some(push), yes_forever: std::env::var("GITSEED_YES_FOREVER").is_ok(), allow_rewrite: true, ..Default::default() };
                match ops::publish(&net, &staging, &cfg, &o).await {
                    Ok(Some(p)) => eprintln!("gitseed: published {} (snapshot {})", p.addr, &p.manifest_sha[..12]),
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("gitseed: PUBLISH FAILED: {e:#}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            "" => return Ok(()),
            other => bail!("unsupported remote-helper command: {other}"),
        }
    }
    Ok(())
}
