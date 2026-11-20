//! Local web UI (verifies, because it IS the client) + HTTP mirror endpoints + static site export
//! (discovery only: a static page on someone else's server can lie, so it says so).
use crate::core::*;
use crate::git::SigStatus;
use crate::net::Net;
use crate::ops::{self, fmt_time, human, short_ref};
use crate::seed;
use crate::trust::{self, Identity, Verdict};
use anyhow::Result;
use axum::{
    Router,
    extract::{Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use std::collections::BTreeMap;
use std::sync::Arc;

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

const CSS: &str = r#"
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#e4e2dc;--card:#fff;--ok:#1f7a3d;--warn:#9a6200;--bad:#b3261e;--acc:#2b59c3}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mut:#a09e97;--line:#2e2d2a;--card:#1c1c1a;--ok:#5cc480;--warn:#e0a640;--bad:#f2766b;--acc:#8aa9ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}a{color:var(--acc)}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.badge{display:inline-block;font-weight:600;font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid currentColor}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.mut{color:var(--mut)}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--mut);font-weight:600}
.scroll{overflow-x:auto}pre{white-space:pre-wrap;word-break:break-word;margin:0}
input[type=search]{width:100%;padding:10px 12px;font-size:16px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
button{font:inherit;padding:7px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.banner{border:2px solid var(--warn);color:var(--warn);border-radius:10px;padding:10px 14px;margin-bottom:16px;font-weight:600}
.verdict{font-size:18px;font-weight:700;margin:6px 0}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
"#;

fn page(title: &str, body: &str, token: Option<&str>) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>{}<title>{}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>",
        token.map(|t| format!("<meta name=gs-token content='{t}'>")).unwrap_or_default(),
        esc(title)
    )
}

fn search_results(q: &str, base: &str) -> String {
    let res = seed::search(q); // ranked: trusted first, then first seen by this machine
    // group by project id so the user sees when several keys publish the same history
    let mut order: Vec<String> = vec![];
    let mut groups: BTreeMap<String, Vec<(Address, Manifest)>> = BTreeMap::new();
    for (a, m) in res {
        let pid = m.project_id();
        if !groups.contains_key(&pid) {
            order.push(pid.clone());
        }
        groups.entry(pid).or_default().push((a, m));
    }
    let mut out = String::new();
    for pid in order {
        let g = &groups[&pid];
        let (a, m) = &g[0];
        let (trusted, _) = seed::standing(a);
        out.push_str(&format!(
            "<div class=card><div class=row><a href='{base}p/{}.{}.html'><b>{}</b></a> <span class='mono mut'>{}</span>{}</div><div>{}</div><div class=mut>{} · updated {}{}</div>",
            a.root, esc(&a.name), esc(&a.name), fpr(&a.root),
            if trusted { " <span class='badge ok'>trusted on this machine</span>" } else { " <span class='badge warn'>not verified yet</span>" },
            esc(&m.description), esc(&m.license), fmt_time(m.seq),
            if g.len() > 1 { format!(" · <b class=warn>{} different keys publish this history — check which one is the author</b>", g.len()) } else { String::new() }
        ));
        for (a2, m2) in g.iter().skip(1) {
            out.push_str(&format!("<div class=mut>↳ other publisher <a href='{base}p/{}.{}.html' class=mono>{}</a> as “{}” ({})</div>", a2.root, esc(&a2.name), fpr(&a2.root), esc(&a2.name), fmt_time(m2.seq)));
        }
        out.push_str("</div>");
    }
    if out.is_empty() {
        out = "<p class=mut>Nothing found. Projects appear here after you clone, seed, or <code>gitseed import</code> an index.</p>".into();
    }
    out
}

/// Project page. `live` = rendered by the local client, which verified everything itself.
pub async fn project_html(net: &Net, a: &Address, live: bool, token: Option<&str>) -> String {
    let r = match trust::resolve(net, a).await {
        Ok(r) => r,
        Err(e) => return page(&a.name, &format!("<h1>{}</h1><p class=bad>{}</p>", esc(&a.name), esc(&format!("{e:#}"))), token),
    };
    let mut b = String::new();
    if !live {
        b.push_str("<div class=banner>Discovery page from a public mirror. A mirror can lie or be edited, so nothing here proves authorship. Verify with your own client: the command below re-checks every signature locally.</div>");
    }
    b.push_str(&format!("<h1>{}</h1><div class='mono mut'>{}</div>", esc(&a.name), esc(&a.to_string())));
    let m = r.manifest.as_ref();
    if let Some(m) = m {
        b.push_str(&format!("<p>{}</p>", esc(&m.description)));
    }

    // --- the one-glance verdict
    let cache = ops::cache_dir(a);
    let reports = if live && cache.exists() { trust::ref_reports(&cache, &r, &BTreeMap::new()) } else { vec![] };
    let any_fail = !r.failures.is_empty() || reports.iter().any(|x| matches!(x.verdict, Verdict::Fail(_)));
    if live {
        let (cls, msg) = if any_fail {
            ("bad", "✖ Verification FAILED — do not use this code. Details below.".to_string())
        } else {
            match &r.identity {
                Identity::Verified(u) => ("ok", format!("✔ Published by the owner of {}", u.iter().map(|x| format!("<b>{}</b>", esc(x))).collect::<Vec<_>>().join(", "))),
                Identity::Pinned => ("warn", "● Same publisher you trusted before (no public proof of who they are)".into()),
                Identity::Unknown => ("warn", "? Unknown publisher — compare the fingerprint with one the author published".into()),
            }
        };
        b.push_str(&format!("<div class='card'><div class='verdict {cls}'>{msg}</div><div class=mut>Fingerprint <b class=mono>{}</b> · maintainers: {} · signatures required on: <b>{}</b></div>", fpr(&r.policy.root),
            r.policy.maintainers.iter().map(|m| format!("{} <span class=mono>{}</span>", esc(&m.label), &fpr(&m.key)[..9])).collect::<Vec<_>>().join(", "), esc(&r.policy.require_signed)));
        for (u, res) in &r.proof_results {
            b.push_str(&format!("<div>{} <a href='{}' rel=noreferrer>{}</a> {}</div>", if res.is_ok() { "<span class=ok>✔</span>" } else { "<span class=bad>✖</span>" }, esc(u), esc(u), res.as_ref().err().map(|e| format!("<span class=mut>({})</span>", esc(e))).unwrap_or_default()));
        }
        for f in &r.failures {
            b.push_str(&format!("<div class=bad>✖ {}</div>", esc(f)));
        }
        for w in &r.warnings {
            b.push_str(&format!("<div class=warn>⚠ {}</div>", esc(w)));
        }
        b.push_str("</div>");
    } else {
        b.push_str(&format!("<div class=card>CLAIMED publisher fingerprint <b class=mono>{}</b> · claimed identity: {}<div class=mut>Everything on this page, including the commands below, comes from the mirror. Copy the address from the author's own website, not from here.</div></div>", fpr(&r.policy.root), r.policy.proofs.iter().map(|u| esc(&trust::proof_domain(u))).collect::<Vec<_>>().join(", ")));
    }

    // --- refs: branches, tags, releases in one place
    if let Some(m) = m {
        b.push_str("<h2>Releases, tags &amp; branches</h2><div class='card scroll'><table><tr><th>Release / ref</th><th>Date</th><th>Commit</th><th>Signed by</th><th>Status</th><th>Get it</th></tr>");
        let mut names: Vec<&String> = m.refs.keys().collect();
        names.sort_by(|x, y| (!x.starts_with("refs/tags/")).cmp(&!y.starts_with("refs/tags/")).then(trust::version_cmp(y, x)));
        for n in names {
            let e = &m.refs[n];
            let is_tag = n.starts_with("refs/tags/");
            let rep = reports.iter().find(|x| &x.name == n);
            let (signer, status) = match rep {
                Some(x) => (
                    match &x.sig {
                        SigStatus::Good(w) => format!("<span class=ok>✔</span> {}", esc(w)),
                        SigStatus::Unsigned => "<span class=mut>—</span>".into(),
                        SigStatus::Bad(_) => "<span class=bad>✖ not a project signer</span>".into(),
                    },
                    match &x.verdict {
                        Verdict::Verified => "<span class='badge ok'>VERIFIED</span>".to_string(),
                        Verdict::Signed => "<span class='badge warn'>SIGNED</span> <span class=mut>author unproven</span>".into(),
                        Verdict::Unsigned if !is_tag => "<span class=mut>branch, not signed</span>".into(),
                        Verdict::Unsigned => "<span class='badge warn'>UNSIGNED</span>".into(),
                        Verdict::Unverified(_) => "<span class='badge warn'>UNVERIFIED</span> <span class=mut>signed by an unlisted key</span>".into(),
                        Verdict::Fail(w) => format!("<span class='badge bad'>FAIL</span> <span class=bad>{}</span>", esc(w)),
                    } + &if x.note.is_empty() { String::new() } else { format!(" <span class=mut>{}</span>", esc(&x.note)) },
                ),
                None => ("<span class=mut>—</span>".into(), if live { "<span class=mut>not downloaded yet</span>".into() } else { "<span class=mut>verify locally</span>".into() }),
            };
            let size: u64 = m.segs_for(std::slice::from_ref(n)).iter().map(|s| s.blob.size).sum();
            let latest = rep.is_some_and(|x| x.latest);
            b.push_str(&format!(
                "<tr><td><b>{}</b>{} <span class=mut>{}</span></td><td>{}</td><td class=mono>{}</td><td>{signer}</td><td>{status}</td><td><code>gitseed clone {} --ref {}</code> <span class=mut>{}</span></td></tr>",
                esc(short_ref(n)), if latest { " ★" } else { "" }, if is_tag { "release" } else { "branch" },
                rep.map(|x| esc(&x.date)).unwrap_or_default(), &e.sha[..10], esc(&a.to_string()), esc(short_ref(n)), human(size)
            ));
            for x in m.assets.iter().filter(|x| is_tag && x.tag == short_ref(n)) {
                let cov = match rep {
                    Some(r) if r.tag_files.contains(&x.blob.sha256) => "<span class=ok>✔ listed in the signed tag</span>",
                    Some(_) => "<span class=warn>⚠ not in the tag signature</span>",
                    None => "",
                };
                b.push_str(&format!("<tr><td colspan=6 class=mut>&nbsp;&nbsp;└ {} · {} · <span class=mono>sha256 {}</span> {cov}</td></tr>", esc(&x.path), human(x.blob.size), x.blob.sha256));
            }
        }
        b.push_str(&format!("</table><p class=mut>★ newest signed release. Release-file hashes are {} — check a download with <code>gitseed verify-file</code>.</p></div>", if live { "pinned in the signed snapshot" } else { "CLAIMED by this mirror" }));
        let others = trust::other_publishers(m, &r.roots);
        if !others.is_empty() {
            b.push_str("<h2>Other publishers of the same history</h2><div class=card><p class=warn>These share this project's history but are signed by different keys — they are not the publisher of this page. Which one is the real author is decided by the identity proof above, not by this list.</p>");
            for (oa, om) in others {
                let look = if trust::lookalike(&oa.root, &r.policy.root) { " <span class='badge bad'>LOOKALIKE KEY</span>" } else { "" };
                let claim = get_doc::<Policy>(&om.policy).ok().map(|pp| pp.proofs.iter().map(|u| trust::proof_domain(u)).collect::<Vec<_>>().join(", ")).filter(|c| !c.is_empty()).unwrap_or_else(|| "no identity".into());
                b.push_str(&format!("<div><a class=mono href='/p/{}.{}.html'>{}</a> “{}” · claims: {} · {}{look}</div>", oa.root, esc(&oa.name), fpr(&oa.root), esc(&oa.name), esc(&claim), fmt_time(om.seq)));
            }
            b.push_str("</div>");
        }
        b.push_str(&format!("<h2>Get &amp; verify</h2><div class=card><div><code>gitseed clone {0}</code></div><div><code>gitseed verify {0} --ref &lt;tag&gt;</code></div><div><code>gitseed verify-file {0} &lt;downloaded file&gt;</code></div><div class=mut>Snapshot {1} · seq {2} · signed by {3} · {4} segments</div></div>",
            esc(&a.to_string()), &r.manifest_sha.as_deref().unwrap_or("")[..16], m.seq, esc(&r.signer_label(&m.signer)), m.segs.len()));
        if live {
            let following = seed::SeedConfig::load().ok().and_then(|c| c.rule_for(a)).is_some();
            b.push_str(&format!(
                "<h2>Host it</h2><div class=card><div class=row><button id=f data-a='{}'>{}</button><span class=mut>Seeds this project from this machine (branches/tags per your seed.toml rules).</span></div></div>
<script>document.getElementById('f').onclick=async e=>{{const t=document.querySelector('meta[name=gs-token]').content;const r=await fetch('/api/follow',{{method:'POST',headers:{{'x-gitseed-token':t,'content-type':'text/plain'}},body:e.target.dataset.a}});e.target.textContent=r.ok?'Seeding ✔':'Failed: '+await r.text()}}</script>",
                esc(&a.to_string()), if following { "Seeding ✔ (update rules)" } else { "Seed this project" }
            ));
        }
        if !m.readme.is_empty() {
            b.push_str(&format!("<h2>README (excerpt)</h2><div class=card><pre>{}</pre></div>", esc(&m.readme)));
        }
    }
    page(&a.name, &b, token)
}

fn home_html(q: &str, token: Option<&str>) -> String {
    let body = format!(
        "<h1>gitseed</h1><p class=mut>Source code that cannot be taken down. Search the projects this machine knows.</p>
<form><input type=search name=q value='{}' placeholder='Search projects…' autofocus></form><div style='margin-top:14px'>{}</div>
<p class=mut>Add more projects with <code>gitseed import &lt;mirror&gt;</code>. Mirror everything here with <code>gitseed export DIR --site</code>.</p>",
        esc(q), search_results(q, "/")
    );
    page("gitseed", &body, token)
}

// ---------- server ----------

struct AppState {
    net: Arc<Net>,
    token: String,
    port: u16,
}

fn token() -> String {
    let p = home().join("token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        return t.trim().to_string();
    }
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    let t = hex::encode(b);
    let _ = std::fs::write(&p, &t);
    t
}

fn local_host(h: &HeaderMap, port: u16) -> bool {
    let host = h.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].iter().any(|x| x == host)
}

pub async fn serve(net: Arc<Net>, listen: &str) -> Result<()> {
    let l = tokio::net::TcpListener::bind(listen).await?;
    let port = l.local_addr()?.port();
    let st = Arc::new(AppState { net, token: token(), port });
    let app = Router::new()
        .route("/", get(|State(s): State<Arc<AppState>>, h: HeaderMap, Query(q): Query<BTreeMap<String, String>>| async move {
            let t = local_host(&h, s.port).then_some(s.token.as_str());
            Html(home_html(q.get("q").map(String::as_str).unwrap_or(""), t))
        }))
        .route("/p/{id}", get(|State(s): State<Arc<AppState>>, h: HeaderMap, AxPath(id): AxPath<String>| async move {
            let id = id.trim_end_matches(".html");
            let Some((root, name)) = id.split_once('.') else { return (StatusCode::NOT_FOUND, "no such project").into_response() };
            let Ok(a) = Address::parse(&format!("gitseed://{root}/{name}")) else { return (StatusCode::NOT_FOUND, "bad address").into_response() };
            if seed::blocked().contains(&a.to_string()) {
                return (StatusCode::GONE, "blocked on this mirror").into_response();
            }
            let live = local_host(&h, s.port);
            Html(project_html(&s.net, &a, live, live.then_some(s.token.as_str())).await).into_response()
        }))
        .route("/api/follow", post(|State(s): State<Arc<AppState>>, h: HeaderMap, body: String| async move {
            if !local_host(&h, s.port) || h.get("x-gitseed-token").and_then(|v| v.to_str().ok()) != Some(s.token.as_str()) {
                return (StatusCode::FORBIDDEN, "forbidden".to_string());
            }
            match Address::parse(body.trim()).and_then(|a| seed::add_follow(&a, None)) {
                Ok(()) => (StatusCode::OK, "ok".into()),
                Err(e) => (StatusCode::BAD_REQUEST, format!("{e:#}")),
            }
        }))
        .route("/index.json", get(|| async { axum::Json(ops::build_index(&[])) }))
        .route("/rss.xml", get(|| async { ([(header::CONTENT_TYPE, "application/rss+xml")], seed::rss().unwrap_or_default()) }))
        .route("/health", get(|| async {
            let b = std::fs::read(home().join("health.json")).unwrap_or_else(|_| b"{}".to_vec());
            ([(header::CONTENT_TYPE, "application/json")], b)
        }))
        .route("/blobs/{sha}", get(|AxPath(sha): AxPath<String>| async move { blob_response(&sha) }))
        .with_state(st);
    axum::serve(l, app).await?;
    Ok(())
}

fn blob_response(sha: &str) -> Response {
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "bad hash").into_response();
    }
    let allowed: std::collections::BTreeSet<String> = ops::build_index(&[]).projects.iter().filter_map(|e| Address::parse(&e.address).ok()).filter_map(|a| load_pin(&a).ok().flatten()).flat_map(|p| ops::project_blobs(&p)).collect();
    if !allowed.contains(sha) {
        return (StatusCode::NOT_FOUND, "not here").into_response();
    }
    match std::fs::read(blob_path(sha)) {
        Ok(b) => ([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "public, max-age=31536000, immutable")], b).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not here").into_response(),
    }
}

/// Static, server-less mirror pages. Same layout as `/` so any file host (or file://) works.
pub fn write_static_site(dir: &std::path::Path, addrs: &[Address]) -> Result<()> {
    std::fs::create_dir_all(dir.join("p"))?;
    let net = Net::offline();
    let rt = tokio::runtime::Handle::try_current();
    let render = |a: &Address| -> String {
        let fut = project_html(&net, a, false, None);
        match &rt {
            Ok(h) => tokio::task::block_in_place(|| h.block_on(fut)),
            Err(_) => tokio::runtime::Runtime::new().unwrap().block_on(fut),
        }
    };
    let mut list = vec![];
    for a in addrs {
        let html = render(a).replace("href='/p/", "href='../p/");
        std::fs::write(dir.join("p").join(format!("{}.{}.html", a.root, a.name)), html)?;
        if let Some(m) = load_pin(a)?.and_then(|p| p.manifest).and_then(|s| get_doc::<Manifest>(&s).ok()) {
            list.push(serde_json::json!({"a": a.to_string(), "root": a.root, "n": a.name, "f": fpr(&a.root), "d": m.description, "t": m.topics, "u": fmt_time(m.seq), "pid": m.project_id()}));
        }
    }
    let data = serde_json::to_string(&list)?.replace("</", "<\\/");
    let body = format!(
        "<div class=banner>Public mirror (discovery only). Verify anything you download with the gitseed client.</div><h1>gitseed mirror</h1>
<p class=mut>{} project(s). Mirror this whole site: copy this folder anywhere, or run <code>gitseed import &lt;this URL&gt;</code>.</p>
<input type=search id=q placeholder='Search projects…' autofocus><div id=r style='margin-top:14px'></div>
<script>const D={data};const e=s=>String(s).replace(/[&<>\"']/g,c=>'&#'+c.charCodeAt(0)+';');
function draw(){{const q=document.getElementById('q').value.toLowerCase().split(/\\s+/).filter(Boolean);const c={{}};D.forEach(x=>c[x.pid]=(c[x.pid]||0)+1);
document.getElementById('r').innerHTML=D.filter(x=>q.every(w=>(x.n+' '+x.d+' '+x.t.join(' ')).toLowerCase().includes(w))).map(x=>`<div class=card><a href='p/${{e(x.root)}}.${{e(x.n)}}.html'><b>${{e(x.n)}}</b></a> <span class='mono mut'>${{e(x.f)}}</span><div>${{e(x.d)}}</div><div class=mut>updated ${{e(x.u)}}${{c[x.pid]>1?' · <b class=warn>'+c[x.pid]+' publishers of this code</b>':''}}</div></div>`).join('')||'<p class=mut>No match.</p>'}}
document.getElementById('q').oninput=draw;draw()</script>",
        list.len()
    );
    std::fs::write(dir.join("index.html"), page("gitseed mirror", &body, None))?;
    Ok(())
}
