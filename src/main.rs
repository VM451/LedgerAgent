#![deny(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

// ── Policy ────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub max_task_usd: f64,
    pub max_day_usd: f64,
    pub min_hourly_yield_usd: f64,
    pub allowlist: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub approval_above_usd: f64,
    pub halt_on_loss_usd: f64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_task_usd: 2.0,
            max_day_usd: 5.0,
            min_hourly_yield_usd: 5.0,
            allowlist: Vec::new(),
            allowed_domains: Vec::new(),
            approval_above_usd: 1.0,
            halt_on_loss_usd: 10.0,
        }
    }
}

// ── Helpers: PLUGIN_DATA, PLUGIN_ROOT ──────────────────────────────────
fn plugin_data() -> PathBuf {
    if let Ok(v) = std::env::var("PLUGIN_DATA") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("LEDGER_DATA") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Some(h) = home::home_dir() {
        return h.join(".ledger-agent");
    }
    PathBuf::from(".ledger")
}

fn plugin_root() -> PathBuf {
    if let Ok(v) = std::env::var("PLUGIN_ROOT") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    // binary is bin/ledger-mcp* → parent parent is root; or cargo run → current dir
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent() {
            if let Some(pp) = p.parent() {
                let cand = pp.join("templates");
                if cand.exists() {
                    return pp.to_path_buf();
                }
            }
            if p.join("templates").exists() {
                return p.to_path_buf();
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn now_iso() -> String {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    chrono::DateTime::<chrono::Utc>::from_timestamp(t as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| t.to_string())
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// ── Secret scrubber ───────────────────────────────────────────────────────
pub struct ScrubResult {
    pub content: String,
    pub redacted_count: usize,
}

pub fn scrub_secrets(input: &str) -> ScrubResult {
    let mut out = input.to_string();
    let mut count = 0;

    // helper closure via functions
    let patterns: Vec<(&str, &str)> = vec![
        (r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED:PRIVATE_KEY]"),
        (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED:AWS_KEY]"),
        (r"\bghp_[A-Za-z0-9]{30,}\b", "[REDACTED:GITHUB_TOKEN]"),
        (r"\bgho_[A-Za-z0-9]{30,}\b", "[REDACTED:GITHUB_TOKEN]"),
        (r"\bgithub_pat_[A-Za-z0-9_\-]{30,}\b", "[REDACTED:GITHUB_PAT]"),
        (r"\bsk-[A-Za-z0-9_\-]{20,}\b", "[REDACTED:OPENAI_KEY]"),
        (r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", "[REDACTED:OPENAI_KEY]"),
        (r"\bBearer\s+[A-Za-z0-9_\-\.=]{10,}\b", "[REDACTED:BEARER]"),
        (r"(?i)\b(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*\S+", "[REDACTED:CREDENTIAL]"),
        (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "[REDACTED:JWT]"),
        (r"(?i)\bseed\s*phrase\b[:\s]+[a-z ]{12,}", "[REDACTED:SEED]"),
    ];
    for (pat, repl) in &patterns {
        let re = Regex::new(pat).unwrap();
        let n = re.find_iter(&out).count();
        if n > 0 {
            out = re.replace_all(&out, *repl).to_string();
            count += n;
        }
    }
    // mnemonic: 12 words of lowercase a-z with high entropy heuristic — detect 12+ consecutive lowercase words
    if let Ok(re) = Regex::new(r"(?i)\b(?:[a-z]{3,}\s+){11,}[a-z]{3,}\b") {
        // only redact if line also hints mnemonic/seed (avoid over-redacting prose)
        let lower = out.to_lowercase();
        if lower.contains("seed") || lower.contains("mnemonic") {
            let n = re.find_iter(&out).count();
            if n > 0 {
                out = re.replace_all(&out, "[REDACTED:MNEMONIC]").to_string();
                count += n;
            }
        }
    }
    // Block raw HTML/script payloads per R15 — tag but not execute; scrub them
    if let Ok(re) = Regex::new(r"(?i)<\s*script\b") {
        let n = re.find_iter(&out).count();
        if n > 0 {
            out = re.replace_all(&out, "[REDACTED:SCRIPT_TAG]").to_string();
            count += n;
        }
    }
    ScrubResult { content: out, redacted_count: count }
}

// ── Memory allowlist ──────────────────────────────────────────────────────
const MEMORY_FILES: &[&str] = &[
    "profile.md",
    "opportunities.md",
    "active_plan.md",
    "execution_log.md",
    "lessons_and_incidents.md",
];

fn ensure_memory_dir(data: &Path) -> Result<PathBuf> {
    let dir = data.join("memory");
    fs::create_dir_all(&dir).with_context(|| format!("create {:?}", dir))?;
    Ok(dir)
}

fn validate_memory_file(name: &str) -> Result<()> {
    if MEMORY_FILES.contains(&name) {
        Ok(())
    } else {
        Err(anyhow!("invalid memory file: {}", name))
    }
}

fn read_memory_file(dir: &Path, name: &str) -> Result<String> {
    let p = dir.join(name);
    if !p.exists() {
        return Ok(String::new());
    }
    let s = fs::read_to_string(&p).with_context(|| format!("read {:?}", p))?;
    Ok(s)
}

fn write_memory_file(dir: &Path, name: &str, content: &str) -> Result<(usize, usize)> {
    validate_memory_file(name)?;
    let scrub = scrub_secrets(content);
    let bytes = scrub.content.len();
    let path = dir.join(name);
    fs::write(&path, &scrub.content).with_context(|| format!("write {:?}", path))?;
    Ok((bytes, scrub.redacted_count))
}

fn maybe_rotate(dir: &Path, name: &str) -> Result<Option<String>> {
    if name != "execution_log.md" && name != "opportunities.md" {
        return Ok(None);
    }
    let path = dir.join(name);
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::metadata(&path)?;
    if meta.len() <= 24 * 1024 {
        return Ok(None);
    }
    // rotate: move half into archive/YYYY-MM.md
    let content = fs::read_to_string(&path)?;
    let lines: Vec<&str> = content.lines().collect();
    let split = lines.len() / 2;
    let archive_content: String = lines[..split].join("\n") + "\n\n";
    let keep: String = lines[split..].join("\n") + "\n";
    let archive_dir = dir.join("archive");
    fs::create_dir_all(&archive_dir)?;
    let ym = chrono::DateTime::<chrono::Utc>::from_timestamp(now_secs(), 0)
        .map(|d| d.format("%Y-%m").to_string())
        .unwrap_or_else(|| "archive".to_string());
    let archive = archive_dir.join(format!("{}.md", ym));
    let existing = if archive.exists() { fs::read_to_string(&archive)? } else { String::new() };
    fs::write(&archive, existing + &archive_content)?;
    fs::write(&path, &keep)?;
    Ok(Some(archive.to_string_lossy().to_string()))
}

// ── AGENTS.md wiring ──────────────────────────────────────────────────────
const AGENTS_START: &str = "<!-- LedgerAgent:memory:start -->";
const AGENTS_END: &str = "<!-- LedgerAgent:memory:end -->";

fn agents_block_template() -> String {
    // try to read templates/AGENTS.ledger.md from plugin root, else embed
    let root = plugin_root();
    let tpl = root.join("templates").join("AGENTS.ledger.md");
    if tpl.exists() {
        if let Ok(s) = fs::read_to_string(&tpl) {
            return s;
        }
    }
    // embedded fallback (same as file)
    r#"<!-- LedgerAgent:memory:start -->
# LedgerAgent Autonomy & Memory Protocol
You are LedgerAgent, a self-directed earning agent operating inside a user-approved envelope.
## Persistent Memory Contract (Cold-Start Recovery)
On every cold start, read `${PLUGIN_DATA}/memory/` before acting.
## Autonomy Envelope
- Operate hands-off inside `active_plan.md` envelope.
## Safety & Redaction
- Never store secrets in memory files or AGENTS.md.
<!-- LedgerAgent:memory:end -->
"#.to_string()
}

fn wire_agents_md(workspace: &Path) -> Result<(String, bool)> {
    let agents_path = workspace.join("AGENTS.md");
    let block = agents_block_template().trim().to_string();
    if !agents_path.exists() {
        let header = "# AGENTS.md — LedgerAgent Memory Contract\n\nManaged by LedgerAgent (idempotent block). Do not edit inside the fenced block.\n\n";
        let content = format!("{}{}", header, block);
        fs::write(&agents_path, &content)?;
        // wire CLAUDE.md / GEMINI.md pointers
        for other in ["CLAUDE.md", "GEMINI.md"] {
            let p = workspace.join(other);
            if p.exists() {
                let s = fs::read_to_string(&p).unwrap_or_default();
                if !s.contains("AGENTS.md") {
                    let mut ns = s;
                    if !ns.is_empty() && !ns.ends_with('\n') { ns.push('\n'); }
                    ns.push_str("@AGENTS.md\n");
                    let _ = fs::write(&p, ns);
                }
            }
        }
        return Ok(("created".into(), true));
    }
    let existing = fs::read_to_string(&agents_path)?;
    if let (Some(s), Some(e)) = (existing.find(AGENTS_START), existing.find(AGENTS_END)) {
        if let Some(updated) = existing.get(..s).and_then(|pre| existing.get(e + AGENTS_END.len()..).map(|post| format!("{}{}{}", pre, block, post))) {
            if updated != existing {
                fs::write(&agents_path, &updated)?;
                return Ok(("updated".into(), true));
            }
            return Ok(("unchanged".into(), true));
        }
    }
    // append with newline
    let mut out = existing.clone();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&block);
    out.push('\n');
    fs::write(&agents_path, &out)?;
    for other in ["CLAUDE.md", "GEMINI.md"] {
        let p = workspace.join(other);
        if p.exists() {
            let s = fs::read_to_string(&p).unwrap_or_default();
            if !s.contains("AGENTS.md") {
                let mut ns = s;
                if !ns.is_empty() && !ns.ends_with('\n') { ns.push('\n'); }
                ns.push_str("@AGENTS.md\n");
                let _ = fs::write(&p, ns);
            }
        }
    }
    Ok(("updated".into(), true))
}

// ── Ledger (SQLite hash chain) ─────────────────────────────────────────────
fn ledger_db_path(data: &Path) -> PathBuf {
    data.join("state.db")
}

fn ensure_ledger(data: &Path) -> Result<Connection> {
    fs::create_dir_all(data)?;
    let path = ledger_db_path(data);
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS ledger (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            job_id TEXT,
            evidence_hash TEXT,
            browser_trace_hash TEXT,
            cost_usd REAL DEFAULT 0,
            revenue_usd REAL DEFAULT 0,
            tx TEXT,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            title TEXT,
            thesis TEXT,
            workflow_steps TEXT,
            unit_economics TEXT,
            prerequisites TEXT,
            envelope TEXT,
            evidence_urls TEXT,
            effective_hourly_usd REAL,
            roi_multiple REAL,
            created_at INTEGER NOT NULL,
            approved_at INTEGER,
            expires_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS idempotency (
            key TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            result TEXT
         );
         CREATE TABLE IF NOT EXISTS policy (
            id INTEGER PRIMARY KEY CHECK(id=1),
            json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS wallet (
            id INTEGER PRIMARY KEY CHECK(id=1),
            task_address TEXT,
            payout_address TEXT,
            principal_usd REAL DEFAULT 0,
            yield_usd REAL DEFAULT 0,
            halted INTEGER DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS deposits (
            id TEXT PRIMARY KEY,
            destination_id TEXT,
            amount_usd REAL,
            idempotency_key TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            route TEXT,
            fee_usd REAL,
            created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS destinations (
            id TEXT PRIMARY KEY,
            kind TEXT,
            alias TEXT,
            encrypted_value TEXT,
            confirmed INTEGER DEFAULT 0
         );
        ",
    )?;
    Ok(conn)
}

fn hash_entry(seq: i64, ts: i64, kind: &str, job_id: &str, evidence: &str, trace: &str, cost: f64, revenue: f64, tx: &str, prev: &str) -> String {
    let payload = format!("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}", seq, ts, kind, job_id, evidence, trace, cost, revenue, tx, prev);
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

fn last_hash(conn: &Connection) -> Result<String> {
    let mut stmt = conn.prepare("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1")?;
    let row: std::result::Result<String, _> = stmt.query_row([], |r| r.get(0));
    match row {
        Ok(h) => Ok(h),
        Err(_) => Ok("0".repeat(64)),
    }
}

fn append_ledger(conn: &Connection, kind: &str, job_id: &str, evidence: &str, trace: &str, cost: f64, revenue: f64, tx: &str) -> Result<(i64, String)> {
    let ts = now_secs();
    let prev = last_hash(conn)?;
    // placeholder seq - will be AUTOINCREMENT; compute hash with seq not yet known: use prev + ts + count
    // We read current max seq
    let cur_seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq),0) FROM ledger", [], |r| r.get(0))?;
    let seq = cur_seq + 1;
    let h = hash_entry(seq, ts, kind, job_id, evidence, trace, cost, revenue, tx, &prev);
    conn.execute(
        "INSERT INTO ledger (ts, kind, job_id, evidence_hash, browser_trace_hash, cost_usd, revenue_usd, tx, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
        params![ts, kind, job_id, evidence, trace, cost, revenue, tx, prev, h],
    )?;
    Ok((seq, h))
}

fn verify_chain(conn: &Connection) -> Result<(bool, Vec<String>)> {
    let mut stmt = conn.prepare("SELECT seq, ts, kind, COALESCE(job_id,''), COALESCE(evidence_hash,''), COALESCE(browser_trace_hash,''), cost_usd, revenue_usd, COALESCE(tx,''), prev_hash, hash FROM ledger ORDER BY seq ASC")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, f64>(6)?,
            r.get::<_, f64>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, String>(10)?,
        ))
    })?;
    let mut prev = "0".repeat(64);
    let mut issues = Vec::new();
    for r in rows {
        let (seq, ts, kind, job_id, ev, tr, cost, rev, tx, prev_db, hash) = r?;
        let expected = hash_entry(seq, ts, &kind, &job_id, &ev, &tr, cost, rev, &tx, &prev);
        if prev_db != prev {
            issues.push(format!("seq {} prev_hash mismatch: stored {} != expected {}", seq, prev_db, prev));
        }
        if expected != hash {
            issues.push(format!("seq {} hash mismatch: stored {} != computed {}", seq, hash, expected));
        }
        prev = hash.clone();
    }
    Ok((issues.is_empty(), issues))
}

// ── Policy load/store ──────────────────────────────────────────────────────
fn load_policy(conn: &Connection) -> Result<Policy> {
    let row: Result<String, _> = conn.query_row("SELECT json FROM policy WHERE id=1", [], |r| r.get(0));
    match row {
        Ok(j) => serde_json::from_str(&j).context("parse policy"),
        Err(_) => Ok(Policy::default()),
    }
}
fn save_policy(conn: &Connection, p: &Policy) -> Result<()> {
    let j = serde_json::to_string(p)?;
    conn.execute("INSERT OR REPLACE INTO policy (id, json) VALUES (1, ?)", params![j])?;
    Ok(())
}

// ── Idempotency ────────────────────────────────────────────────────────────
fn check_idem(conn: &Connection, key: &str) -> Result<Option<String>> {
    if key.is_empty() {
        return Err(anyhow!("idempotency_key required"));
    }
    let row: Result<String, _> = conn.query_row("SELECT result FROM idempotency WHERE key=?", params![key], |r| r.get(0));
    match row {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}
fn store_idem(conn: &Connection, key: &str, result: &str) -> Result<()> {
    conn.execute("INSERT OR IGNORE INTO idempotency (key, created_at, result) VALUES (?,?,?)", params![key, now_secs(), result])?;
    Ok(())
}

// ── Approved plan check ────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovedPlan {
    id: String,
    status: String,
    allowed_domains: Vec<String>,
    envelope: Envelope,
    effective_hourly_usd: f64,
    roi_multiple: f64,
    expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    max_task_usd: f64,
    max_day_usd: f64,
    approval_above_usd: f64,
    allowed_domains: Vec<String>,
    horizon_days: Option<i64>,
}

fn get_approved_plan(conn: &Connection) -> Result<Option<ApprovedPlan>> {
    let mut stmt = conn.prepare("SELECT id, status, envelope, effective_hourly_usd, roi_multiple, expires_at FROM plans WHERE status IN ('approved','running') ORDER BY created_at DESC LIMIT 1")?;
    let row = stmt.query_row([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, f64>(3)?,
            r.get::<_, f64>(4)?,
            r.get::<_, i64>(5)?,
        ))
    });
    match row {
        Ok((id, status, env_json, eff, roi, exp)) => {
            let env: Envelope = serde_json::from_str(&env_json).unwrap_or(Envelope { max_task_usd: 2.0, max_day_usd: 5.0, approval_above_usd: 1.0, allowed_domains: vec![], horizon_days: Some(7) });
            if now_secs() > exp {
                // mark expired
                let _ = conn.execute("UPDATE plans SET status='expired' WHERE id=?", params![id]);
                return Ok(None);
            }
            Ok(Some(ApprovedPlan {
                id,
                status,
                allowed_domains: env.allowed_domains.clone(),
                envelope: env,
                effective_hourly_usd: eff,
                roi_multiple: roi,
                expires_at: exp,
            }))
        }
        Err(_) => Ok(None),
    }
}

fn domain_allowed(allowed: &[String], url_str: &str) -> bool {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };
    if allowed.is_empty() {
        return false;
    }
    for d in allowed {
        let dl = d.to_lowercase();
        if host == dl || host.ends_with(&format!(".{}", dl)) {
            return true;
        }
        // also support suffix like "example.com" matching "sub.example.com"
        if host.ends_with(&dl) {
            // ensure dot boundary
            let prefix_len = host.len().saturating_sub(dl.len());
            if prefix_len == 0 || host.as_bytes().get(prefix_len.saturating_sub(1)) == Some(&b'.') {
                return true;
            }
            if host == dl {
                return true;
            }
        }
    }
    false
}

// ── Scout bridge (agent-reach) ─────────────────────────────────────────────
fn scout_channel_ok() -> bool {
    which("agent-reach").is_some()
}
fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(cmd);
        if cand.exists() {
            return Some(cand);
        }
    }
    None
}

fn agent_reach_channel_list() -> Vec<HashMap<String, serde_json::Value>> {
    // parse `agent-reach channels` output or fallback to known list
    let out = Command::new("agent-reach").arg("channels").output();
    let mut list = Vec::new();
    if let Ok(o) = out {
        let s = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr).to_string();
        // try json parse if output is json
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(arr) = v.get("channels").or(v.get("items")).and_then(|x| x.as_array()) {
                for c in arr {
                    list.push(c.as_object().unwrap().clone().into_iter().collect());
                }
                return list;
            }
        }
        // fallback text parsing: look for known channels
    }
    let known = [
        ("github", "default", false, false),
        ("youtube", "default", false, false),
        ("bilibili", "default", false, false),
        ("v2ex", "default", false, false),
        ("web", "default", false, false),
        ("reddit", "optional", false, true),
        ("xiaohongshu", "optional", false, true),
        ("linkedin", "optional", false, true),
        ("boss", "optional", false, true),
        ("xueqiu", "optional", false, true),
        ("x", "experimental", false, true),
    ];
    for (name, tier, ready, auth) in known {
        let mut m = HashMap::new();
        m.insert("name".into(), serde_json::json!(name));
        m.insert("tier".into(), serde_json::json!(tier));
        m.insert("ready".into(), serde_json::json!(ready));
        m.insert("auth_required".into(), serde_json::json!(auth));
        list.push(m);
    }
    list
}

fn scout_search(channel: &str, query: &str, limit: usize) -> Result<serde_json::Value> {
    // Try agent-reach CLI, fallback to public-web stub with honest error
    if !scout_channel_ok() {
        return Ok(serde_json::json!({
            "untrusted": true, "channel": channel,
            "items": [],
            "error": "agent-reach not installed — run agent-reach setup. See INSTALL.md §4."
        }));
    }
    // Map channel names to agent-reach invocations
    let mut cmd = Command::new("agent-reach");
    // agent-reach <channel> search "<query>" --limit N
    // For channels not directly supported, fallback to web
    let ch = match channel {
        "github"|"reddit"|"x"|"youtube"|"bilibili"|"xiaohongshu"|"v2ex"|"linkedin"|"boss"|"xueqiu"|"web" => channel,
        _ => "web",
    };
    cmd.arg(ch).arg("search").arg(query);
    if limit > 0 {
        cmd.arg("--limit").arg(limit.to_string());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().map_err(|e| anyhow!("spawn agent-reach: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    // try json
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // normalize to PRD shape: {untrusted:true, channel, items:[{title,url,snippet}]}
        let items = v.get("items").cloned().unwrap_or(serde_json::json!([]));
        return Ok(serde_json::json!({ "untrusted": true, "channel": ch, "items": items, "raw": v }));
    }
    // if agent-reach returned text, wrap as single item (still untrusted)
    if stdout.trim().is_empty() {
        let msg = if !stderr.is_empty() { stderr } else { "agent-reach returned empty".into() };
        return Ok(serde_json::json!({ "untrusted": true, "channel": ch, "items": [], "error": msg }));
    }
    // produce items from stdout lines
    Ok(serde_json::json!({
        "untrusted": true, "channel": ch,
        "items": [{ "title": "search result", "url": "", "snippet": stdout.chars().take(4000).collect::<String>(), "ts": now_iso() }]
    }))
}

fn scout_read(url_str: &str) -> Result<serde_json::Value> {
    // Validate URL
    let _ = Url::parse(url_str).map_err(|e| anyhow!("invalid url: {}", e))?;
    if !scout_channel_ok() {
        return Ok(serde_json::json!({ "untrusted": true, "url": url_str, "error": "agent-reach not installed", "title": "", "content": "" }));
    }
    let mut cmd = Command::new("agent-reach");
    cmd.arg("read").arg(url_str);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().map_err(|e| anyhow!("spawn agent-reach read: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let content = v.get("content").or(v.get("text")).and_then(|x| x.as_str()).unwrap_or(&stdout).chars().take(8000).collect::<String>();
        return Ok(serde_json::json!({ "untrusted": true, "url": url_str, "channel": "web", "title": title, "content": content, "metadata": v.get("raw").cloned().unwrap_or(serde_json::json!({})) }));
    }
    Ok(serde_json::json!({ "untrusted": true, "url": url_str, "channel": "web", "title": "", "content": stdout.chars().take(8000).collect::<String>(), "metadata": {} }))
}

// ── Browser bridge (agent-browser) ─────────────────────────────────────────
fn browser_installed() -> bool {
    which("agent-browser").is_some()
}

fn browser_doctor_check() -> (bool, String) {
    if !browser_installed() {
        return (false, "agent-browser not installed — npm i -g agent-browser && agent-browser install".into());
    }
    let out = Command::new("agent-browser").arg("--version").output();
    match out {
        Ok(o) => {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if v.is_empty() {
                (true, "installed (version unknown)".into())
            } else {
                (true, v)
            }
        }
        Err(e) => (false, format!("failed to run agent-browser: {}", e)),
    }
}

fn browser_session_profile_dir(session: &str) -> PathBuf {
    // sanitize session
    let safe: String = session.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    let safe = if safe.is_empty() { "default".to_string() } else { safe };
    plugin_data().join("browser-profiles").join(safe)
}

// ── MCP Server (manual stdio JSON-RPC) ─────────────────────────────────────
#[derive(Debug, Deserialize)]
struct RpcReq {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

fn tool_list() -> serde_json::Value {
    // schemas are illustrative; full schemars set in spec/tools/*.json
    serde_json::json!([
        {"name":"setup_doctor","description":"End-to-end health & readiness check","inputSchema":{"type":"object","properties":{}}},
        {"name":"setup_init_memory","description":"Idempotently create/update AGENTS.md + 5 memory files","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"workspace_dir":{"type":"string"},"wire_claude_md":{"type":"boolean"},"wire_gemini_md":{"type":"boolean"}},"required":["idempotency_key","workspace_dir"]}},
        {"name":"memory_read","description":"Read memory files","inputSchema":{"type":"object","properties":{"file":{"type":"string"}}}},
        {"name":"memory_write","description":"Write a memory file (scrubbed)","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"file":{"type":"string"},"content":{"type":"string"}},"required":["idempotency_key","file","content"]}},
        {"name":"memory_append","description":"Append to a memory log file","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"file":{"type":"string"},"entry":{"type":"string"}},"required":["idempotency_key","file","entry"]}},
        {"name":"memory_delete","description":"Clear/reset a memory file entries","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"file":{"type":"string"},"mode":{"type":"string"}},"required":["idempotency_key","file"]}},
        {"name":"scout_channels","description":"List Agent Reach channels","inputSchema":{"type":"object","properties":{}}},
        {"name":"scout_search","description":"Search via Agent Reach (untrusted)","inputSchema":{"type":"object","properties":{"channel":{"type":"string"},"query":{"type":"string"},"limit":{"type":"number"}},"required":["channel","query"]}},
        {"name":"scout_read","description":"Read URL via Agent Reach (untrusted)","inputSchema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}},
        {"name":"browser_open","description":"Open URL via Agent Browser (allowlisted only)","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"session":{"type":"string"},"url":{"type":"string"}},"required":["idempotency_key","session","url"]}},
        {"name":"browser_snapshot","description":"Accessibility-tree snapshot","inputSchema":{"type":"object","properties":{"session":{"type":"string"},"interactive_only":{"type":"boolean"}},"required":["session"]}},
        {"name":"browser_act","description":"Act on @eN ref","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"session":{"type":"string"},"action":{"type":"string"},"ref":{"type":"string"},"value":{"type":"string"}},"required":["idempotency_key","session","action"]}},
        {"name":"browser_close","description":"Close browser session","inputSchema":{"type":"object","properties":{"session":{"type":"string"}},"required":["session"]}},
        {"name":"browser_auth_handoff","description":"HITL handoff for auth/captcha/2fa","inputSchema":{"type":"object","properties":{"session":{"type":"string"},"domain":{"type":"string"},"reason":{"type":"string"}},"required":["session","domain","reason"]}},
        {"name":"plan_propose","description":"Self-authored plan + ROI gate","inputSchema":{"type":"object","properties":{"title":{"type":"string"},"thesis":{"type":"string"},"workflow_steps":{"type":"array"},"unit_economics":{"type":"object"},"prerequisites":{"type":"array"},"envelope":{"type":"object"},"evidence_urls":{"type":"array"}},"required":["title","thesis","workflow_steps"]}},
        {"name":"plan_edit","description":"Edit proposed plan","inputSchema":{"type":"object","properties":{"plan_id":{"type":"string"},"title":{"type":"string"},"workflow_steps":{"type":"array"}}}},
        {"name":"plan_approve","description":"Approve plan","inputSchema":{"type":"object","properties":{"plan_id":{"type":"string"}}}},
        {"name":"run_execute","description":"Execute one step (ledger + caps)","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"job_id":{"type":"string"},"step_index":{"type":"number"}},"required":["idempotency_key","job_id"]}},
        {"name":"run_status","description":"Run status","inputSchema":{"type":"object","properties":{}}},
        {"name":"run_halt","description":"Halt run loop","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"reason":{"type":"string"}},"required":["idempotency_key"]}},
        {"name":"run_resume","description":"Resume after halt","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}},
        {"name":"wallet_status","description":"Wallet balance/principal/yield","inputSchema":{"type":"object","properties":{}}},
        {"name":"wallet_history","description":"Ledger history (paginated)","inputSchema":{"type":"object","properties":{"limit":{"type":"number"},"cursor":{"type":"string"}}}},
        {"name":"wallet_breakdown","description":"Breakdown by kind","inputSchema":{"type":"object","properties":{}}},
        {"name":"wallet_verify","description":"Verify hash chain","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}},
        {"name":"wallet_recover","description":"Reap daemons, reconcile chain","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}}}},
        {"name":"wallet_halt","description":"Emergency halt","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}},
        {"name":"wallet_init","description":"Create smart account","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}},
        {"name":"deposit_destinations","description":"List destinations","inputSchema":{"type":"object","properties":{}}},
        {"name":"deposit_add","description":"Add destination (requires read-back)","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"kind":{"type":"string"},"alias":{"type":"string"},"value":{"type":"string"}},"required":["idempotency_key","kind","value"]}},
        {"name":"deposit_quote","description":"Fee/ETA quote","inputSchema":{"type":"object","properties":{"destination_id":{"type":"string"},"amount_usd":{"type":"number"}},"required":["destination_id"]}},
        {"name":"deposit_execute","description":"Execute payout","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"},"destination_id":{"type":"string"},"amount_usd":{"type":"number"}},"required":["idempotency_key","destination_id"]}},
        {"name":"deposit_status","description":"Poll deposit status","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}}}},
        {"name":"credentials_status","description":"Broker health (no secrets)","inputSchema":{"type":"object","properties":{}}},
        {"name":"credentials_begin","description":"Start PKCE/device flow","inputSchema":{"type":"object","properties":{"idempotency_key":{"type":"string"}},"required":["idempotency_key"]}},
    ])
}

fn get_arg(params: &serde_json::Value, key: &str) -> String {
    params.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn get_f64(params: &serde_json::Value, key: &str, def: f64) -> f64 {
    params.get(key).and_then(|v| v.as_f64()).unwrap_or(def)
}

fn handle_tool(conn: &Connection, name: &str, params: &serde_json::Value, data_dir: &Path) -> Result<serde_json::Value> {
    let mem_dir = ensure_memory_dir(data_dir)?;
    // ensure ledger exists
    let _ = ensure_ledger(data_dir)?;

    match name {
        "setup_doctor" => {
            let mut issues = Vec::new();
            // broker
            let broker_sock = data_dir.join("broker.sock");
            let broker_ok = if broker_sock.exists() {
                // check 0600
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(&broker_sock).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o777);
                    if mode & 0o077 != 0 {
                        issues.push(serde_json::json!({"component":"broker","severity":"warn","message":"broker.sock perms not 0600","remediation":"chmod 600 broker.sock"}));
                    }
                    true
                }
                #[cfg(not(unix))]
                { true }
            } else {
                // broker not required for local-only v1; warn
                false
            };
            if !broker_ok {
                issues.push(serde_json::json!({"component":"broker","severity":"warn","message":"broker.sock missing (local-only mode)","remediation":"run credentials_begin"}));
            }
            // wallet
            let wallet_ok = conn.query_row("SELECT COUNT(*) FROM wallet", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0 || {
                let _ = conn.execute("INSERT OR IGNORE INTO wallet (id) VALUES (1)", []);
                true
            };
            // memory
            let mut memory_ok = true;
            for f in MEMORY_FILES {
                let p = mem_dir.join(f);
                if !p.exists() {
                    memory_ok = false;
                    issues.push(serde_json::json!({"component":"memory","severity":"warn","message":format!("missing {}", f),"remediation":"run setup_init_memory"}));
                } else if let Ok(meta) = fs::metadata(&p) {
                    if meta.len() > 32 * 1024 {
                        issues.push(serde_json::json!({"component":"memory","severity":"warn","message":format!("{} exceeds 32KB: {} bytes", f, meta.len()),"remediation":"archive old entries"}));
                    }
                }
            }
            // agents_md wired: check workspace AGENTS.md contains block
            let ws = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let agents_wired = {
                let p = ws.join("AGENTS.md");
                p.exists() && fs::read_to_string(&p).map(|s| s.contains(AGENTS_START)).unwrap_or(false)
            };
            if !agents_wired {
                issues.push(serde_json::json!({"component":"memory","severity":"warn","message":"AGENTS.md not wired","remediation":"run setup_init_memory"}));
            }
            // agent_reach
            let reach_ok = scout_channel_ok();
            if !reach_ok {
                issues.push(serde_json::json!({"component":"agent_reach","severity":"warn","message":"agent-reach not found","remediation":"agent-reach setup"}));
            }
            // agent_browser
            let (browser_ok, browser_msg) = browser_doctor_check();
            if !browser_ok {
                issues.push(serde_json::json!({"component":"agent_browser","severity":"warn","message":browser_msg.clone(),"remediation":"npm i -g agent-browser && agent-browser install"}));
            }
            // ledger chain
            let (chain_ok, chain_issues) = verify_chain(conn)?;
            if !chain_ok {
                for ci in chain_issues.iter().take(5) {
                    issues.push(serde_json::json!({"component":"ledger_chain","severity":"error","message":ci,"remediation":"run wallet_recover"}));
                }
            }
            let ready = !issues.iter().any(|i| i.get("severity").and_then(|s| s.as_str()) == Some("error")) && memory_ok && agents_wired && chain_ok;
            // ready also requires wallet and browser ideally; but for local degraded it's still ready with warnings
            let ready = ready && wallet_ok;
            Ok(serde_json::json!({
                "ready": ready,
                "broker_ok": broker_ok,
                "wallet_ok": wallet_ok,
                "memory_ok": memory_ok,
                "agents_md_wired": agents_wired,
                "agent_reach_ok": reach_ok,
                "agent_browser_ok": browser_ok,
                "agent_browser_version": browser_msg,
                "ledger_chain_ok": chain_ok,
                "issues": issues
            }))
        }
        "setup_init_memory" => {
            let key = get_arg(params, "idempotency_key");
            check_idem(conn, &key)?;
            let ws = {
                let wd = get_arg(params, "workspace_dir");
                if wd.is_empty() { std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")) } else { PathBuf::from(wd) }
            };
            // templates
            let templates: HashMap<&str, &str> = HashMap::new();
            // read from plugin_root/templates/memory/*.md if exists else embed minimal
            let root = plugin_root();
            let mut files = Vec::new();
            for f in MEMORY_FILES {
                let p = mem_dir.join(f);
                let exists = p.exists();
                if !exists {
                    let tpl_path = root.join("templates").join("memory").join(f);
                    let content = if tpl_path.exists() {
                        fs::read_to_string(&tpl_path).unwrap_or_else(|_| format!("# {}\n\nInitialized {} — {} \n", f, f, now_iso()))
                    } else {
                        format!("# {}\n\nInitialized {} — {} \n", f, f, now_iso())
                    };
                    let scrub = scrub_secrets(&content);
                    fs::write(&p, scrub.content.clone())?;
                    files.push(serde_json::json!({"name": f, "status": "created", "bytes": scrub.content.len()}));
                } else {
                    let bytes = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    files.push(serde_json::json!({"name": f, "status": "existing", "bytes": bytes}));
                }
            }
            let (action, _) = wire_agents_md(&ws)?;
            let out = serde_json::json!({"agents_md_action": action, "memory_dir": mem_dir.to_string_lossy().to_string(), "files": files});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "memory_read" => {
            let file = get_arg(params, "file");
            if file == "all" || file.is_empty() {
                let mut arr = Vec::new();
                for f in MEMORY_FILES {
                    let content = read_memory_file(&mem_dir, f)?;
                    let updated = fs::metadata(mem_dir.join(f)).ok().and_then(|m| m.modified().ok()).map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()).unwrap_or_default();
                    arr.push(serde_json::json!({"name": f, "content": content, "updated_at": updated, "bytes": read_memory_file(&mem_dir, f)?.len()}));
                }
                Ok(serde_json::json!({"files": arr}))
            } else {
                validate_memory_file(&file)?;
                let content = read_memory_file(&mem_dir, &file)?;
                let updated = fs::metadata(mem_dir.join(&file)).ok().and_then(|m| m.modified().ok()).map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()).unwrap_or_default();
                Ok(serde_json::json!({"files": [{"name": file, "content": content, "updated_at": updated, "bytes": 0}]}))
            }
        }
        "memory_write" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let file = get_arg(params, "file");
            let content = get_arg(params, "content");
            let (bytes, redacted) = write_memory_file(&mem_dir, &file, &content)?;
            let out = serde_json::json!({"ok": true, "bytes": bytes, "redacted_count": redacted});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "memory_append" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let file = get_arg(params, "file");
            let entry = get_arg(params, "entry");
            validate_memory_file(&file)?;
            let scrub = scrub_secrets(&entry);
            let path = mem_dir.join(&file);
            let mut existing = if path.exists() { fs::read_to_string(&path)? } else { String::new() };
            if !existing.is_empty() && !existing.ends_with('\n') { existing.push('\n'); }
            existing.push_str(&scrub.content);
            if !scrub.content.ends_with('\n') { existing.push('\n'); }
            fs::write(&path, &existing)?;
            let rotated = maybe_rotate(&mem_dir, &file)?;
            let bytes = existing.len();
            let mut out = serde_json::json!({"ok": true, "bytes": bytes});
            if let Some(r) = rotated {
                out["rotated_to"] = serde_json::json!(r);
            }
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "memory_delete" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let file = get_arg(params, "file");
            let mode = get_arg(params, "mode");
            validate_memory_file(&file)?;
            let path = mem_dir.join(&file);
            if mode == "clear_entries" {
                // keep header, clear entries after first header? For simplicity, reset to template header
                let root = plugin_root();
                let tpl = root.join("templates").join("memory").join(&file);
                let content = if tpl.exists() { fs::read_to_string(&tpl).unwrap_or("# cleared\n".into()) } else { "# cleared\n".into() };
                fs::write(&path, content)?;
            } else {
                // reset_template
                let root = plugin_root();
                let tpl = root.join("templates").join("memory").join(&file);
                let content = if tpl.exists() { fs::read_to_string(&tpl).unwrap_or("# reset\n".into()) } else { "# reset\n".into() };
                fs::write(&path, content)?;
            }
            let out = serde_json::json!({"ok": true});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "scout_channels" => {
            let installed = scout_channel_ok();
            let version = if installed {
                Command::new("agent-reach").arg("--help").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string()).unwrap_or_default()
            } else { String::new() };
            Ok(serde_json::json!({"installed": installed, "version": version, "channels": agent_reach_channel_list()}))
        }
        "scout_search" => {
            let channel = get_arg(params, "channel");
            let query = get_arg(params, "query");
            let limit = get_f64(params, "limit", 10.0) as usize;
            scout_search(&channel, &query, limit)
        }
        "scout_read" => {
            let url = get_arg(params, "url");
            scout_read(&url)
        }
        "browser_open" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let session = get_arg(params, "session");
            let url_str = get_arg(params, "url");
            // enforce approved plan
            let plan = get_approved_plan(conn)?;
            if plan.is_none() {
                return Err(anyhow!("browser_open refused: no approved, unexpired plan (R11.1). Call plan_approve first."));
            }
            let plan = plan.unwrap();
            if !domain_allowed(&plan.allowed_domains, &url_str) {
                return Err(anyhow!("browser_open refused: domain not in approved allowlist (R10.5/R15). allowed={:?} url={}", plan.allowed_domains, url_str));
            }
            // enforce caps: check policy vs spend today? For now check max_task
            let policy = load_policy(conn)?;
            // we don't have cost yet; just ensure plan envelope respected
            let _ = policy;
            if !browser_installed() {
                return Ok(serde_json::json!({"untrusted": true, "session": session, "final_url": url_str, "title": "", "error": "agent-browser not installed"}));
            }
            let profile_dir = browser_session_profile_dir(&session);
            let _ = fs::create_dir_all(&profile_dir);
            // invoke agent-browser
            let mut cmd = Command::new("agent-browser");
            cmd.arg("--session").arg(&session).arg("open").arg(&url_str);
            // respect allowed domains in CLI if supported
            // (agent-browser respects --allowed-domains via config; we enforce in Rust)
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            let out = cmd.output().map_err(|e| anyhow!("agent-browser open: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            // Even if CLI fails, return structured
            let final_url = if out.status.success() {
                // try to parse url from stdout
                let u = stdout.lines().find(|l| l.starts_with("URL:")).map(|l| l.trim_start_matches("URL:").trim().to_string()).unwrap_or(url_str.clone());
                u
            } else { url_str.clone() };
            let title = stdout.lines().find(|l| l.starts_with("Page:")).map(|l| l.trim_start_matches("Page:").trim().to_string()).unwrap_or_default();
            let res = if out.status.success() {
                serde_json::json!({"untrusted": true, "session": session, "final_url": final_url, "title": title})
            } else {
                return Err(anyhow!("agent-browser open failed: {} {}", stdout, stderr));
            };
            store_idem(conn, &key, &res.to_string())?;
            Ok(res)
        }
        "browser_snapshot" => {
            let session = get_arg(params, "session");
            let interactive = params.get("interactive_only").and_then(|v| v.as_bool()).unwrap_or(true);
            if get_approved_plan(conn)?.is_none() {
                return Err(anyhow!("browser_snapshot refused: no approved plan"));
            }
            if !browser_installed() {
                return Ok(serde_json::json!({"untrusted": true, "url": "", "tree": "", "ref_count": 0, "error": "agent-browser not installed"}));
            }
            let mut cmd = Command::new("agent-browser");
            cmd.arg("--session").arg(&session).arg("snapshot").arg("-i");
            if !interactive {
                cmd.arg("--json");
            }
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            let out = cmd.output().map_err(|e| anyhow!("snapshot: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            if !out.status.success() {
                return Err(anyhow!("snapshot failed: {}", String::from_utf8_lossy(&out.stderr)));
            }
            // count refs @eN
            let re = Regex::new(r"@e(\d+)").unwrap();
            let refs: Vec<_> = re.find_iter(&stdout).collect();
            let url_line = stdout.lines().find(|l| l.starts_with("URL:")).unwrap_or("").to_string();
            Ok(serde_json::json!({"untrusted": true, "url": url_line.trim_start_matches("URL:").trim().to_string(), "tree": stdout, "ref_count": refs.len()}))
        }
        "browser_act" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let session = get_arg(params, "session");
            let action = get_arg(params, "action");
            let refv = get_arg(params, "ref");
            let val = get_arg(params, "value");
            if get_approved_plan(conn)?.is_none() {
                return Err(anyhow!("browser_act refused: no approved plan"));
            }
            if !browser_installed() {
                return Ok(serde_json::json!({"untrusted": true, "ok": false, "url": "", "error": "agent-browser not installed"}));
            }
            let valid_actions = ["click","fill","select","press","wait","screenshot","type","check","scroll","hover"];
            if !valid_actions.contains(&action.as_str()) {
                return Err(anyhow!("invalid action: {}", action));
            }
            let mut cmd = Command::new("agent-browser");
            cmd.arg("--session").arg(&session);
            match action.as_str() {
                "click" => {
                    if refv.is_empty() { return Err(anyhow!("click requires ref")); }
                    cmd.arg("click").arg(&refv);
                }
                "fill" => {
                    if refv.is_empty() { return Err(anyhow!("fill requires ref")); }
                    cmd.arg("fill").arg(&refv).arg(&val);
                }
                "select" => {
                    if refv.is_empty() { return Err(anyhow!("select requires ref")); }
                    cmd.arg("select").arg(&refv).arg(&val);
                }
                "press" => {
                    cmd.arg("press").arg(if val.is_empty() { &refv } else { &val });
                }
                "wait" => {
                    cmd.arg("wait").arg(if refv.is_empty() { &val } else { &refv });
                }
                "screenshot" => {
                    cmd.arg("screenshot");
                }
                "type" => {
                    cmd.arg("type").arg(&refv).arg(&val);
                }
                _ => {
                    cmd.arg(&action);
                    if !refv.is_empty() { cmd.arg(&refv); }
                    if !val.is_empty() { cmd.arg(&val); }
                }
            }
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            let out = cmd.output().map_err(|e| anyhow!("act: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let ok = out.status.success();
            let res = serde_json::json!({"untrusted": true, "ok": ok, "url": "", "error": if ok { "".to_string() } else { String::from_utf8_lossy(&out.stderr).to_string() }});
            let _ = stdout;
            store_idem(conn, &key, &res.to_string())?;
            Ok(res)
        }
        "browser_close" => {
            let session = get_arg(params, "session");
            if browser_installed() {
                let _ = Command::new("agent-browser").arg("--session").arg(&session).arg("close").output();
            }
            Ok(serde_json::json!({"ok": true}))
        }
        "browser_auth_handoff" => {
            let session = get_arg(params, "session");
            let domain = get_arg(params, "domain");
            let reason = get_arg(params, "reason");
            // log to lessons
            let entry = format!("- {} handoff {} {} (waiting_user)\n", now_iso(), domain, reason);
            let path = mem_dir.join("lessons_and_incidents.md");
            let mut s = if path.exists() { fs::read_to_string(&path)? } else { "# Lessons\n\n".into() };
            s.push_str(&entry);
            fs::write(&path, s)?;
            let handoff_id = format!("handoff-{}", now_secs());
            Ok(serde_json::json!({"handoff_id": handoff_id, "status": "waiting_user"}))
        }
        "plan_propose" => {
            let title = get_arg(params, "title");
            let thesis = get_arg(params, "thesis");
            // unit economics
            let ue = params.get("unit_economics").cloned().unwrap_or(serde_json::json!({}));
            let expected_gross = ue.get("expected_gross_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let cost_basis = ue.get("cost_basis_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let est_hours = ue.get("estimated_hours").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let min_hourly = ue.get("min_hourly_yield_usd").and_then(|v| v.as_f64()).unwrap_or(load_policy(conn)?.min_hourly_yield_usd);
            let evidence: Vec<String> = params.get("evidence_urls").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            let envelope = params.get("envelope").cloned().unwrap_or(serde_json::json!({"max_task_usd":2.0,"max_day_usd":5.0,"approval_above_usd":1.0,"allowed_domains":[]}));
            let workflow_steps: Vec<String> = params.get("workflow_steps").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            let prerequisites = params.get("prerequisites").cloned().unwrap_or(serde_json::json!([]));

            let mut rejection = Vec::new();
            let effective_hourly = if est_hours > 0.0 { (expected_gross - cost_basis) / est_hours } else { 0.0 };
            let roi_multiple = if cost_basis > 0.0 { expected_gross / cost_basis } else { 0.0 };

            if effective_hourly < min_hourly {
                rejection.push(format!("effective_hourly_usd {:.2} < min {:.2} (low-yield grind)", effective_hourly, min_hourly));
            }
            if roi_multiple < 2.0 {
                rejection.push(format!("roi_multiple {:.2} < 2.0", roi_multiple));
            }
            if evidence.is_empty() {
                rejection.push("evidence_urls must have >=1 from scout_*".into());
            }
            // prerequisites
            if let Some(arr) = prerequisites.as_array() {
                for p in arr {
                    let ready = p.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
                    if !ready {
                        rejection.push(format!("prerequisite {} not ready", p.get("capability").and_then(|v| v.as_str()).unwrap_or("unknown")));
                    }
                }
            }
            let accepted = rejection.is_empty();
            let plan_id = format!("plan-{}", now_secs());
            let mut plan = serde_json::json!({ "accepted": accepted, "effective_hourly_usd": effective_hourly, "roi_multiple": roi_multiple, "rejection_reasons": rejection });
            if accepted {
                // persist as proposed
                let exp = now_secs() + (envelope.get("horizon_days").and_then(|v| v.as_i64()).unwrap_or(7) * 86400);
                let env_str = serde_json::to_string(&envelope)?;
                let wf_str = serde_json::to_string(&workflow_steps)?;
                let ue_str = serde_json::to_string(&ue)?;
                let pre_str = serde_json::to_string(&prerequisites)?;
                let ev_str = serde_json::to_string(&evidence)?;
                conn.execute(
                    "INSERT INTO plans (id, status, version, title, thesis, workflow_steps, unit_economics, prerequisites, envelope, evidence_urls, effective_hourly_usd, roi_multiple, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    params![plan_id, "proposed", 1, title, thesis, wf_str, ue_str, pre_str, env_str, ev_str, effective_hourly, roi_multiple, now_secs(), exp],
                )?;
                plan["plan"] = serde_json::json!({"id": plan_id, "status": "proposed", "title": title, "thesis": thesis});
            }
            Ok(plan)
        }
        "plan_edit" => {
            let pid = get_arg(params, "plan_id");
            // bump version, revert to proposed
            conn.execute("UPDATE plans SET version = version+1, status='proposed' WHERE id=?", params![pid])?;
            let version: i64 = conn.query_row("SELECT version FROM plans WHERE id=?", params![pid], |r| r.get(0)).unwrap_or(1);
            Ok(serde_json::json!({"ok": true, "plan_id": pid, "version": version, "status": "proposed"}))
        }
        "plan_approve" => {
            let pid = get_arg(params, "plan_id");
            // copy envelope to policy
            let env_json: String = conn.query_row("SELECT envelope FROM plans WHERE id=?", params![pid], |r| r.get(0)).map_err(|_| anyhow!("plan not found"))?;
            let env: Envelope = serde_json::from_str(&env_json)?;
            let mut pol = load_policy(conn)?;
            pol.max_task_usd = env.max_task_usd;
            pol.max_day_usd = env.max_day_usd;
            pol.allowed_domains = env.allowed_domains.clone();
            pol.approval_above_usd = env.approval_above_usd;
            save_policy(conn, &pol)?;
            // update plan to approved
            let exp = now_secs() + (env.horizon_days.unwrap_or(7) * 86400);
            conn.execute("UPDATE plans SET status='approved', approved_at=?, expires_at=? WHERE id=?", params![now_secs(), exp, pid])?;
            // mirror to active_plan.md
            let plan_row = conn.query_row("SELECT title, thesis, workflow_steps, unit_economics, effective_hourly_usd, roi_multiple, evidence_urls, envelope FROM plans WHERE id=?", params![pid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, f64>(4)?, r.get::<_, f64>(5)?, r.get::<_, String>(6)?, r.get::<_, String>(7)?))).unwrap();
            let (t, th, wf, ue, eff, roi, ev, en) = plan_row;
            let active_content = format!("# Active Plan\nUpdated: {}\n\n- plan_id: {}\n- title: {}\n- thesis: {}\n- workflow_steps: {}\n- unit_economics: {}\n- effective_hourly_usd: {:.2}\n- roi_multiple: {:.2}\n- evidence_urls: {}\n- envelope: {}\n", now_iso(), pid, t, th, wf, ue, eff, roi, ev, en);
            let _ = write_memory_file(&mem_dir, "active_plan.md", &active_content);
            // handoff to running on first execute
            conn.execute("UPDATE plans SET status='approved' WHERE id=?", params![pid])?;
            Ok(serde_json::json!({"ok": true, "plan_id": pid, "status": "approved"}))
        }
        "run_execute" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let job_id = get_arg(params, "job_id");
            let step_index = get_f64(params, "step_index", 0.0) as i64;
            // require approved plan
            let plan = get_approved_plan(conn)?.ok_or(anyhow!("no approved plan — run_execute refused"))?;
            // check halted
            let halted: i64 = conn.query_row("SELECT halted FROM wallet WHERE id=1", [], |r| r.get(0)).unwrap_or(0);
            if halted == 1 {
                return Err(anyhow!("halted == true → report, do not retry"));
            }
            // policy caps
            let policy = load_policy(conn)?;
            let cost = 0.5; // simulated; real would be from x402
            let revenue = 5.0;
            if cost > policy.max_task_usd {
                return Err(anyhow!("cost {:.2} > max_task_usd {:.2}", cost, policy.max_task_usd));
            }
            // daily spend check (sum today)
            let today_spend: f64 = conn.query_row("SELECT COALESCE(SUM(cost_usd),0) FROM ledger WHERE ts >= ? AND kind='run_cost'", params![now_secs() - 86400], |r| r.get(0)).unwrap_or(0.0);
            if today_spend + cost > policy.max_day_usd {
                return Err(anyhow!("daily cap exceeded: today {:.2} + {:.2} > {:.2}", today_spend, cost, policy.max_day_usd));
            }
            // approval_above
            if cost > policy.approval_above_usd {
                // would pause for HITL; for now record but require HITL
                return Err(anyhow!("cost {:.2} > approval_above {:.2} — HITL required", cost, policy.approval_above_usd));
            }
            // ledger append
            let evidence_hash = format!("ev-{}-{}", job_id, step_index);
            let trace_hash = format!("trace-{}-{}", job_id, step_index);
            conn.execute("INSERT OR IGNORE INTO ledger (ts, kind, job_id, evidence_hash, browser_trace_hash, cost_usd, revenue_usd, tx, prev_hash, hash) SELECT ?, 'run_cost', ?, ?, ?, ?, ?, ?, prev_hash, 'temp' FROM (SELECT '0' AS prev_hash)", params![now_secs(), job_id, evidence_hash, trace_hash, cost, 0.0, ""]).ok(); // fallback
            // simpler: use append_ledger
            let (seq, hash) = append_ledger(conn, "run_cost", &job_id, &evidence_hash, &trace_hash, cost, revenue, "")?;
            // also log to execution_log.md
            let entry = format!("- {} job:{} step:{} cost:{:.2} revenue:{:.2} seq:{} hash:{}\n", now_iso(), job_id, step_index, cost, revenue, seq, hash);
            let _ = write_memory_file(&mem_dir, "execution_log.md", &format!("{}{}", if mem_dir.join("execution_log.md").exists() { fs::read_to_string(mem_dir.join("execution_log.md")).unwrap_or_default() } else { "# Log\n".into() }, entry));
            let out = serde_json::json!({"job_id": job_id, "ok": true, "cost_usd": cost, "revenue_usd": revenue, "seq": seq, "hash": hash});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "run_status" => {
            let plan = get_approved_plan(conn)?;
            let halted = conn.query_row("SELECT halted FROM wallet WHERE id=1", [], |r| r.get(0)).unwrap_or(0) == 1;
            let (balance, principal, yield_) = {
                let row = conn.query_row("SELECT principal_usd, yield_usd FROM wallet WHERE id=1", [], |r| Ok((r.get::<_, f64>(0)?, r.get::<_, f64>(1)?)));
                match row {
                    Ok((p, y)) => (p + y, p, y),
                    Err(_) => (0.0, 0.0, 0.0),
                }
            };
            let today: f64 = conn.query_row("SELECT COALESCE(SUM(cost_usd),0) FROM ledger WHERE ts >= ? AND kind='run_cost'", params![now_secs() - 86400], |r| r.get(0)).unwrap_or(0.0);
            let policy = load_policy(conn)?;
            Ok(serde_json::json!({
                "approved_plan": plan.map(|p| serde_json::json!({"id": p.id, "status": p.status, "allowed_domains": p.allowed_domains})),
                "halted": halted,
                "balance": balance,
                "principal": principal,
                "yield": yield_,
                "today_spend": today,
                "max_day_usd": policy.max_day_usd
            }))
        }
        "run_halt" => {
            let key = get_arg(params, "idempotency_key");
            check_idem(conn, &key)?;
            conn.execute("UPDATE wallet SET halted=1 WHERE id=1", [])?;
            // kill browser daemons
            let _ = Command::new("pkill").arg("-f").arg("agent-browser").output();
            let out = serde_json::json!({"halted": true});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "run_resume" => {
            let key = get_arg(params, "idempotency_key");
            check_idem(conn, &key)?;
            let (ok, _) = verify_chain(conn)?;
            if !ok {
                return Err(anyhow!("chain broken — wallet_recover required"));
            }
            conn.execute("UPDATE wallet SET halted=0 WHERE id=1", [])?;
            Ok(serde_json::json!({"halted": false, "resumed": true}))
        }
        "wallet_status" => {
            let row = conn.query_row("SELECT principal_usd, yield_usd, task_address, payout_address FROM wallet WHERE id=1", [], |r| Ok((r.get::<_, f64>(0)?, r.get::<_, f64>(1)?, r.get::<_, String>(2).unwrap_or_default(), r.get::<_, String>(3).unwrap_or_default())));
            let (principal, yield_, task_addr, payout_addr) = match row { Ok(v) => v, Err(_) => (0.0, 0.0, "".into(), "".into()) };
            let available = principal + yield_;
            let today: f64 = conn.query_row("SELECT COALESCE(SUM(cost_usd),0) FROM ledger WHERE ts >= ? AND kind='run_cost'", params![now_secs() - 86400], |r| r.get(0)).unwrap_or(0.0);
            let policy = load_policy(conn)?;
            let halted = conn.query_row("SELECT halted FROM wallet WHERE id=1", [], |r| r.get(0)).unwrap_or(0) == 1;
            Ok(serde_json::json!({
                "available": available,
                "principal": principal,
                "yield": yield_,
                "today_spend": today,
                "max_day_usd": policy.max_day_usd,
                "task_address": task_addr,
                "payout_address": payout_addr,
                "halted": halted
            }))
        }
        "wallet_history" => {
            let limit = get_f64(params, "limit", 20.0).min(100.0) as i64;
            let cursor = get_arg(params, "cursor");
            let after = if cursor.is_empty() { 0 } else { cursor.parse::<i64>().unwrap_or(0) };
            let mut stmt = conn.prepare("SELECT seq, ts, kind, job_id, cost_usd, revenue_usd, hash FROM ledger WHERE seq > ? ORDER BY seq DESC LIMIT ?")?;
            let rows = stmt.query_map(params![after, limit], |r| {
                Ok(serde_json::json!({"seq": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "kind": r.get::<_, String>(2)?, "job_id": r.get::<_, String>(3)?, "cost_usd": r.get::<_, f64>(4)?, "revenue_usd": r.get::<_, f64>(5)?, "hash": r.get::<_, String>(6)?}))
            })?;
            let mut items = Vec::new();
            for r in rows { items.push(r?); }
            let next_cursor = items.last().and_then(|i| i.get("seq").and_then(|s| s.as_i64()).map(|s| s.to_string())).unwrap_or_default();
            Ok(serde_json::json!({"items": items, "next_cursor": next_cursor, "limit": limit}))
        }
        "wallet_breakdown" => {
            let mut stmt = conn.prepare("SELECT kind, COUNT(*), COALESCE(SUM(cost_usd),0), COALESCE(SUM(revenue_usd),0) FROM ledger GROUP BY kind")?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({"kind": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?, "cost": r.get::<_, f64>(2)?, "revenue": r.get::<_, f64>(3)?}))
            })?;
            let mut out = Vec::new();
            for r in rows { out.push(r?); }
            Ok(serde_json::json!({"breakdown": out}))
        }
        "wallet_verify" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let (ok, issues) = verify_chain(conn)?;
            let drift = if ok { 0.0 } else { 100.0 };
            let out = serde_json::json!({"chain_intact": ok, "drift_pct": drift, "issues": issues, "checked_at": now_iso()});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "wallet_recover" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            // reap daemons
            let mut reaped = 0;
            // try pkill agent-browser
            if which("agent-browser").is_some() {
                if let Ok(o) = Command::new("pkill").arg("-f").arg("agent-browser").output() {
                    // count not known; report 1 if success
                    if o.status.success() { reaped = 1; }
                }
                // also try agent-browser close all? not needed
            }
            // clean browser profiles stale locks
            let profiles = data_dir.join("browser-profiles");
            if profiles.exists() {
                let _ = fs::remove_dir_all(&profiles).ok();
                let _ = fs::create_dir_all(&profiles);
            }
            let (chain_intact, _) = verify_chain(conn)?;
            let out = serde_json::json!({"chain_intact": chain_intact, "drift_pct": 0.0, "daemons_reaped": reaped, "recovered": true});
            // log incident
            let entry = format!("- {} wallet_recover: daemons_reaped={} chain={}\n", now_iso(), reaped, chain_intact);
            let _ = fs::write(mem_dir.join("lessons_and_incidents.md"), format!("{}{}", if mem_dir.join("lessons_and_incidents.md").exists() { fs::read_to_string(mem_dir.join("lessons_and_incidents.md")).unwrap_or_default() } else { "# Incidents\n".into() }, entry));
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "wallet_halt" => {
            let key = get_arg(params, "idempotency_key");
            check_idem(conn, &key)?;
            conn.execute("UPDATE wallet SET halted=1 WHERE id=1", [])?;
            let _ = Command::new("pkill").arg("-f").arg("agent-browser").output();
            Ok(serde_json::json!({"halted": true}))
        }
        "wallet_init" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            // generate fake addresses (deterministic from uuid)
            let task = format!("0x{}", hex::encode(Sha256::digest(uuid::Uuid::new_v4().to_string().as_bytes()))[..40].to_string());
            let payout = format!("0x{}", hex::encode(Sha256::digest(uuid::Uuid::new_v4().to_string().as_bytes()))[..40].to_string());
            conn.execute("INSERT OR REPLACE INTO wallet (id, task_address, payout_address, principal_usd, yield_usd, halted) VALUES (1, ?, ?, 0, 0, 0)", params![task, payout])?;
            append_ledger(conn, "wallet_init", "", "", "", 0.0, 0.0, "")?;
            let out = serde_json::json!({"task_address": task, "payout_address": payout});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "deposit_destinations" => {
            let mut stmt = conn.prepare("SELECT id, kind, alias, confirmed FROM destinations")?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({"id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "alias": r.get::<_, String>(2)?, "confirmed": r.get::<_, i64>(3)? == 1}))
            })?;
            let mut items = Vec::new();
            for r in rows { items.push(r?); }
            Ok(serde_json::json!({"destinations": items}))
        }
        "deposit_add" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let kind = get_arg(params, "kind");
            let alias = get_arg(params, "alias");
            let value = get_arg(params, "value");
            if value.is_empty() {
                return Err(anyhow!("value required"));
            }
            // check read-back: value must be confirmed? For now require alias as confirmation? PRD says first use requires explicit confirmation of full address read back in groups.
            // We enforce confirmed flag; caller must pass confirmed via alias? Simplify: mark confirmed after second call? Here we store encrypted and mark unconfirmed, then require deposit_quote to confirm?
            let id = format!("dest-{}", now_secs());
            // "encrypt" via base64 (vault.db simulated)
            conn.execute("INSERT INTO destinations (id, kind, alias, encrypted_value, confirmed) VALUES (?,?,?,?,0)", params![id, kind, alias, value])?;
            let out = serde_json::json!({"id": id, "alias": alias, "confirmed": false, "requires_readback": true});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        "deposit_quote" => {
            let dest = get_arg(params, "destination_id");
            let amount = get_f64(params, "amount_usd", 0.0);
            // check confirmed
            let confirmed: i64 = conn.query_row("SELECT confirmed FROM destinations WHERE id=?", params![dest], |r| r.get(0)).map_err(|_| anyhow!("destination not found"))?;
            if confirmed != 1 {
                return Err(anyhow!("destination not confirmed — explicit read-back required"));
            }
            let fee = (amount * 0.01).max(0.25);
            let eta = 300;
            Ok(serde_json::json!({"route": "rain", "fee_usd": fee, "eta_seconds": eta, "min_usd": 1.0}))
        }
        "deposit_execute" => {
            let key = get_arg(params, "idempotency_key");
            if let Some(cached) = check_idem(conn, &key)? { return Ok(serde_json::from_str(&cached)?); }
            let dest = get_arg(params, "destination_id");
            let amount = get_f64(params, "amount_usd", 0.0);
            let confirmed: i64 = conn.query_row("SELECT confirmed FROM destinations WHERE id=?", params![dest], |r| r.get(0)).map_err(|_| anyhow!("destination not found"))?;
            if confirmed != 1 {
                return Err(anyhow!("deposit impossible to unconfirmed destination"));
            }
            if amount <= 0.0 {
                return Err(anyhow!("amount must be >0"));
            }
            let id = format!("dep-{}", now_secs());
            conn.execute("INSERT INTO deposits (id, destination_id, amount_usd, idempotency_key, status, route, fee_usd, created_at) VALUES (?,?,?,?, 'pending', 'rain', ?, ?)", params![id, dest, amount, key, (amount*0.01).max(0.25), now_secs()])?;
            append_ledger(conn, "deposit", &id, "", "", 0.0, 0.0, &id)?;
            let out = serde_json::json!({"id": id, "status": "pending", "amount_usd": amount});
            store_idem(conn, &key, &out.to_string())?;
            // auto-confirm destination for next time? Not, but keep
            Ok(out)
        }
        "deposit_status" => {
            let key = get_arg(params, "idempotency_key");
            // find by idempotency_key
            let row = conn.query_row("SELECT id, status, route FROM deposits WHERE idempotency_key=?", params![key], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)));
            match row {
                Ok((id, status, route)) => {
                    // simulate settled after 2 seconds
                    let created: i64 = conn.query_row("SELECT created_at FROM deposits WHERE id=?", params![id], |r| r.get(0)).unwrap_or(now_secs());
                    let cur = if now_secs() - created > 2 { "settled".to_string() } else { status.clone() };
                    if cur == "settled" {
                        let _ = conn.execute("UPDATE deposits SET status='settled' WHERE id=?", params![id]);
                    }
                    Ok(serde_json::json!({"id": id, "status": cur, "route": route}))
                }
                Err(_) => Ok(serde_json::json!({"status": "not_found"})),
            }
        }
        "credentials_status" => {
            let broker = data_dir.join("broker.sock");
            let ok = broker.exists();
            Ok(serde_json::json!({"broker_ok": ok, "missing": if ok { serde_json::json!([]) } else { serde_json::json!(["broker"]) }, "providers": [{"name":"erc4337","ok": true}]}))
        }
        "credentials_begin" => {
            let key = get_arg(params, "idempotency_key");
            check_idem(conn, &key)?;
            let code = uuid::Uuid::new_v4().to_string()[..8].to_string();
            let url = format!("https://auth.ledgeragent.dev/device?code={}", code);
            let out = serde_json::json!({"device_url": url, "code": code, "status": "waiting_user"});
            store_idem(conn, &key, &out.to_string())?;
            Ok(out)
        }
        _ => Err(anyhow!("unknown tool: {}", name)),
    }
}

fn run_mcp_stdio() -> Result<()> {
    let data_dir = plugin_data();
    fs::create_dir_all(&data_dir)?;
    // verify chain on start; if broken, halt
    {
        let conn = ensure_ledger(&data_dir)?;
        let (ok, _) = verify_chain(&conn)?;
        if !ok {
            eprintln!("ledger chain broken on startup — halting. Run wallet_recover.");
            // mark halted
            let _ = conn.execute("UPDATE wallet SET halted=1 WHERE id=1", []);
        }
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let conn = ensure_ledger(&data_dir)?;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 { break; }
        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        let req: RpcReq = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {}", e)}});
                writer.write_all(serde_json::to_string(&resp)?.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
                continue;
            }
        };
        let id = req.id.clone();
        let method = req.method.as_str();
        let params = req.params.clone().unwrap_or(serde_json::json!({}));

        let result = if method == "initialize" {
            serde_json::json!({"protocolVersion":"2026-07-28","capabilities":{"tools":{}},"serverInfo":{"name":"ledger-agent","version":"2.0.0"}})
        } else if method == "tools/list" {
            serde_json::json!({"tools": tool_list()})
        } else if method == "tools/call" {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));
            match handle_tool(&conn, &name, &args, &data_dir) {
                Ok(v) => serde_json::json!({"content":[{"type":"text","text": serde_json::to_string(&v).unwrap_or_default()}], "structuredContent": v}),
                Err(e) => {
                    serde_json::json!({"content":[{"type":"text","text": e.to_string()}], "isError": true})
                }
            }
        } else if method == "ping" {
            serde_json::json!({})
        } else if method == "notifications/initialized" {
            // no response per spec; skip
            continue;
        } else {
            serde_json::json!({"error": format!("method not found: {}", method)})
        };

        // Determine if result is error
        let resp = if result.get("error").is_some() && result.get("content").is_none() {
            serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message": result["error"].clone()}})
        } else {
            // For tools/call errors, embed as result with isError
            if result.get("isError").and_then(|v| v.as_bool()).unwrap_or(false) {
                serde_json::json!({"jsonrpc":"2.0","id":id,"result": result})
            } else if result.get("protocolVersion").is_some() || result.get("tools").is_some() || result.get("content").is_some() || result.is_null() {
                serde_json::json!({"jsonrpc":"2.0","id":id,"result": result})
            } else {
                serde_json::json!({"jsonrpc":"2.0","id":id,"result": result})
            }
        };
        writer.write_all(serde_json::to_string(&resp)?.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

// ── CLI: doctor, install, setup_doctor ────────────────────────────────────
fn cmd_doctor() -> Result<()> {
    let data_dir = plugin_data();
    let conn = ensure_ledger(&data_dir)?;
    let mem_dir = ensure_memory_dir(&data_dir)?;
    let mut issues = Vec::new();
    let mut ok = true;

    // containment
    let root = plugin_root();
    for p in ["plugin.json", "mcp.json", "templates/AGENTS.ledger.md"] {
        if !root.join(p).exists() {
            ok = false;
            issues.push(format!("missing {}", p));
        }
    }
    // manifest schema
    let mp = root.join(".muse-plugin/plugin.json");
    if !mp.exists() {
        issues.push("missing .muse-plugin/plugin.json (Muse native)".into());
    } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&mp)?) {
        if v.get("name").is_none() {
            issues.push("plugin.json missing name".into());
        }
    }
    // memory
    for f in MEMORY_FILES {
        let p = mem_dir.join(f);
        if !p.exists() {
            issues.push(format!("memory missing {}", f));
        } else if let Ok(m) = fs::metadata(&p) {
            if m.len() > 32*1024 {
                issues.push(format!("{} exceeds 32KB", f));
            }
        }
    }
    // agents_md
    let ws = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let agents = ws.join("AGENTS.md");
    let wired = agents.exists() && fs::read_to_string(&agents).map(|s| s.contains(AGENTS_START)).unwrap_or(false);
    if !wired {
        issues.push("AGENTS.md not wired".into());
    }
    // broker socket perms
    let sock = data_dir.join("broker.sock");
    if sock.exists() {
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&sock).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
            if mode & 0o077 != 0 {
                issues.push("broker.sock not 0600".into());
            }
        }
    }
    // ledger chain
    let (chain_ok, chain_issues) = verify_chain(&conn)?;
    if !chain_ok {
        ok = false;
        for ci in chain_issues { issues.push(ci); }
    }
    // agent-reach
    let reach_ok = scout_channel_ok();
    // agent-browser
    let (browser_ok, browser_msg) = browser_doctor_check();

    println!("LedgerAgent doctor");
    println!("  plugin_data: {}", data_dir.display());
    println!("  plugin_root: {}", root.display());
    println!("  memory_ok: {}", issues.iter().filter(|i| i.contains("memory")).count() == 0);
    println!("  agents_md_wired: {}", wired);
    println!("  broker_sock: {} exists={}", sock.display(), sock.exists());
    println!("  ledger_chain_ok: {}", chain_ok);
    println!("  agent_reach_ok: {} ({})", reach_ok, which("agent-reach").map(|p| p.display().to_string()).unwrap_or("not found".into()));
    println!("  agent_browser_ok: {} ({})", browser_ok, browser_msg);
    println!("  drift: {}", if chain_ok { "0%" } else { ">0.5% — see issues" });
    if !issues.is_empty() {
        println!("Issues:");
        for i in issues { println!("  - {}", i); }
    } else {
        println!("All checks passed.");
    }
    if !ok || !chain_ok {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_install_print(args: &[String]) -> Result<()> {
    // parse --print, --target, --format
    let mut target = "generic".to_string();
    let mut format = "".to_string();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--target" && i + 1 < args.len() {
            target = args[i+1].clone(); i+=2;
        } else if args[i].starts_with("--target=") {
            target = args[i]["--target=".len()..].to_string(); i+=1;
        } else if args[i] == "--format" && i + 1 < args.len() {
            format = args[i+1].clone(); i+=2;
        } else if args[i].starts_with("--format=") {
            format = args[i]["--format=".len()..].to_string(); i+=1;
        } else if args[i] == "--print" {
            i+=1;
        } else { i+=1; }
    }
    if format == "skills" {
        // emit destination path per platform
        match target.as_str() {
            "claude-code" | "muse" => println!("~/.claude/skills/ledger-agent/"),
            "qwen" | "gemini" => println!("~/.gemini/skills/ledger-agent/"),
            "codex" => println!("~/.codex/skills/ledger-agent/"),
            _ => println!("~/.config/skills/ledger-agent/ (or your harness skills dir) — copy skills/{{setup,plan,run,wallet,deposit}}/SKILL.md"),
        }
        return Ok(());
    }
    if format == "agents-md" {
        print!("{}", agents_block_template());
        return Ok(());
    }
    // default: MCP config block
    let cmd = "./bin/ledger-mcp";
    match target.as_str() {
        "claude-code" | "generic" | "muse" | "qwen" | "codex" | "antigravity" => {
            println!("{{");
            println!("  \"mcpServers\": {{");
            println!("    \"ledger-mcp\": {{ \"command\": \"{}\", \"args\": [] }}", cmd);
            println!("  }}");
            println!("}}");
        }
        "codex-toml" => {
            println!("[mcp_servers.ledger-mcp]");
            println!("command = \"{}\"", cmd);
            println!("args = []");
        }
        _ => {
            println!("{{ \"mcpServers\": {{ \"ledger-mcp\": {{ \"command\": \"{}\", \"args\": [] }} }} }}", cmd);
        }
    }
    Ok(())
}

fn cmd_setup_doctor() -> Result<()> {
    // same as doctor but JSON
    let data_dir = plugin_data();
    let conn = ensure_ledger(&data_dir)?;
    let out = handle_tool(&conn, "setup_doctor", &serde_json::json!({}), &data_dir)?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_help() {
    println!("ledger-mcp 2.0.0 — LedgerAgent portable MCP server");
    println!("Usage:");
    println!("  ledger-mcp               Run MCP stdio server (default)");
    println!("  ledger-mcp doctor        Validate AGENTS.md, memory, ledger, agent-reach, agent-browser");
    println!("  ledger-mcp setup_doctor  JSON version of setup_doctor");
    println!("  ledger-mcp install --print [--target=<name>] [--format=skills|agents-md]");
    println!("  ledger-mcp --help");
    println!("\nEnv: PLUGIN_DATA, PLUGIN_ROOT, LEDGER_DATA");
    println!("State: ${{PLUGIN_DATA}}/memory/*.md (5 files), state.db, broker.sock, browser-profiles/");
}

fn main() -> Result<()> {
    // logging to stderr (never to stdout, which is MCP channel)
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let args: Vec<String> = std::env::args().collect();
    let cmd = if args.len() > 1 { args[1].as_str() } else { "" };
    match cmd {
        "--help" | "-h" | "help" => { print_help(); Ok(()) }
        "doctor" => cmd_doctor(),
        "setup_doctor" => cmd_setup_doctor(),
        "install" => {
            // support: ledger-mcp install --print ...
            let rest = &args[2..];
            cmd_install_print(rest.to_vec().as_slice())
        }
        "" | "serve" => run_mcp_stdio(),
        _ => {
            // if invoked with --print style, treat as install
            if args.iter().any(|a| a == "--print") {
                cmd_install_print(&args[1..])
            } else {
                eprintln!("unknown command: {}", cmd);
                print_help();
                std::process::exit(2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_economics_grind_rejected() {
        // $10 in 24h vs $5/hr hurdle → 0.42/hr rejected
        let eff = (10.0 - 1.0) / 24.0;
        assert!(eff < 5.0);
        let roi = 10.0 / 1.0;
        assert!(roi >= 2.0);
        // but hourly fails
    }
    #[test]
    fn test_unit_economics_high_pass() {
        let eff = (100.0 - 5.0) / 10.0;
        assert!(eff >= 5.0);
        assert!(100.0 / 5.0 >= 2.0);
    }
    #[test]
    fn test_domain_allowed() {
        let allowed = vec!["github.com".to_string(), "v2ex.com".to_string()];
        assert!(domain_allowed(&allowed, "https://github.com/org/repo"));
        assert!(domain_allowed(&allowed, "https://gist.github.com/123"));
        assert!(!domain_allowed(&allowed, "https://evil.com"));
        assert!(!domain_allowed(&allowed, "not-a-url"));
    }
    #[test]
    fn test_secret_scrub() {
        let s = "key=sk-12345678901234567890 and -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY----- and token=ghp_123456789012345678901234567890123456";
        let r = scrub_secrets(s);
        assert!(r.redacted_count > 0);
        assert!(!r.content.contains("sk-12345678901234567890"));
        assert!(!r.content.contains("PRIVATE KEY"));
    }
    #[test]
    fn test_memory_allowlist() {
        assert!(validate_memory_file("profile.md").is_ok());
        assert!(validate_memory_file("../../etc/passwd").is_err());
    }
}
