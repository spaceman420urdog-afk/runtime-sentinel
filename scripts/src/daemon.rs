use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc;
use tokio::fs;
use tracing::{error, info, warn};

use crate::audit;
use crate::egress;
use crate::payment;

const DAEMON_PID_FILE: &str = "~/.sentinel/daemon.pid";
const DAEMON_LOG_FILE: &str = "~/.sentinel/daemon.log";

#[derive(Debug, Serialize, Deserialize)]
struct DaemonState {
    pid: u32,
    started_at: String,
    premium_until: Option<String>,
}

pub async fn start(offline: bool) -> Result<()> {
    let pid_path = resolve_home(DAEMON_PID_FILE);

    if pid_path.exists() {
        let state: DaemonState = serde_json::from_str(&fs::read_to_string(&pid_path).await?)?;
        if process_running(state.pid) {
            println!(
                "Daemon already running (PID {}). Use `sentinel daemon stop` first.",
                state.pid
            );
            return Ok(());
        }

        warn!(
            "Removing stale daemon PID file for non-running PID {}",
            state.pid
        );
        fs::remove_file(&pid_path).await?;
    }

    // Premium gate: acquire x402 session token unless offline
    if !offline {
        println!("Acquiring premium session via x402...");
        match payment::execute_x402_payment(
            "https://api.runtime-sentinel.dev/v1/daemon/start",
            &serde_json::json!({"features": ["egress", "process_anomaly", "file_watch"]}),
        )
        .await
        {
            Ok(resp) => {
                info!("Premium session granted: {:?}", resp);
            }
            Err(e) => {
                warn!(
                    "Premium payment failed ({}). Starting in free-tier mode (file watch only).",
                    e
                );
            }
        }
    }

    let state = DaemonState {
        pid: std::process::id(),
        started_at: chrono::Utc::now().to_rfc3339(),
        premium_until: None,
    };
    fs::create_dir_all(resolve_home("~/.sentinel")).await?;
    fs::write(&pid_path, serde_json::to_string(&state)?).await?;

    println!("✅ Daemon started (PID {})", state.pid);
    println!("Watching: ~/.openclaw/skills, SOUL.md, MEMORY.md");
    println!("Log: {}", DAEMON_LOG_FILE);

    run_watch_loop().await
}

pub async fn stop() -> Result<()> {
    let pid_path = resolve_home(DAEMON_PID_FILE);
    if !pid_path.exists() {
        println!("Daemon is not running.");
        return Ok(());
    }
    let state: DaemonState = serde_json::from_str(&fs::read_to_string(&pid_path).await?)?;
    if !process_running(state.pid) {
        fs::remove_file(&pid_path).await?;
        println!(
            "Daemon PID file existed, but process {} is not running. Cleaned up stale state.",
            state.pid
        );
        return Ok(());
    }

    // Send SIGTERM to the daemon process
    #[cfg(unix)]
    unsafe {
        libc::kill(state.pid as i32, libc::SIGTERM);
    }

    fs::remove_file(&pid_path).await?;
    println!("Daemon stopped (was PID {}).", state.pid);
    Ok(())
}

pub async fn status() -> Result<()> {
    let pid_path = resolve_home(DAEMON_PID_FILE);
    if !pid_path.exists() {
        println!("Daemon: not running");
        return Ok(());
    }
    let state: DaemonState = serde_json::from_str(&fs::read_to_string(&pid_path).await?)?;
    if !process_running(state.pid) {
        fs::remove_file(&pid_path).await?;
        println!(
            "Daemon: not running (cleaned up stale PID file for {})",
            state.pid
        );
        return Ok(());
    }

    println!("Daemon: running (PID {})", state.pid);
    println!("Started: {}", state.started_at);
    match &state.premium_until {
        Some(t) => println!("Premium active until: {}", t),
        None => println!("Mode: free tier (file watch only)"),
    }
    Ok(())
}

pub async fn logs(lines: usize) -> Result<()> {
    let log_path = resolve_home(DAEMON_LOG_FILE);
    if !log_path.exists() {
        println!("No log file found at {}", DAEMON_LOG_FILE);
        return Ok(());
    }
    let content = fs::read_to_string(&log_path).await?;
    let all_lines: Vec<&str> = content.lines().collect();
    let start = all_lines.len().saturating_sub(lines);
    for line in &all_lines[start..] {
        println!("{}", line);
    }
    Ok(())
}

async fn run_watch_loop() -> Result<()> {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

    let skills_dir = resolve_home("~/.openclaw/skills");
    let soul_md = resolve_home("~/.openclaw/SOUL.md");
    let memory_md = resolve_home("~/.openclaw/MEMORY.md");

    if skills_dir.exists() {
        watcher.watch(&skills_dir, RecursiveMode::Recursive)?;
    }
    if soul_md.exists() {
        watcher.watch(&soul_md, RecursiveMode::NonRecursive)?;
    }
    if memory_md.exists() {
        watcher.watch(&memory_md, RecursiveMode::NonRecursive)?;
    }

    info!("File watcher active");

    let egress_interval = std::time::Duration::from_secs(10);
    let mut last_egress_scan = std::time::Instant::now() - egress_interval;

    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Ok(event)) => handle_fs_event(event).await,
            Ok(Err(e)) => error!("Watcher error: {:?}", e),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if last_egress_scan.elapsed() >= egress_interval {
            if let Err(e) = scan_egress().await {
                warn!("Egress scan failed: {}", e);
            }
            last_egress_scan = std::time::Instant::now();
        }
    }

    Ok(())
}

async fn scan_egress() -> Result<()> {
    let skill_pids = collect_skill_processes().await?;
    if skill_pids.is_empty() {
        return Ok(());
    }

    let events = egress::snapshot_connections(&skill_pids).await?;
    for event in events.into_iter().filter(|e| !e.declared) {
        let skill = event
            .skill_name
            .clone()
            .unwrap_or_else(|| event.process_name.clone());
        let severity = egress::undeclared_severity(&event.remote_addr, event.remote_port);
        let msg = format!(
            "[{}] {}: Undeclared outbound connection from pid {} ({}) to {}:{}",
            severity, skill, event.pid, event.process_name, event.remote_addr, event.remote_port
        );

        log_alert(&msg).await;
        if severity >= crate::audit::Severity::High {
            eprintln!("🔴 {}", msg);
        } else {
            eprintln!("🟠 {}", msg);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn collect_skill_processes() -> Result<Vec<(u32, String)>> {
    let mut out = Vec::new();
    let mut dir = fs::read_dir("/proc").await?;

    while let Some(entry) = dir.next_entry().await? {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline_bytes = match fs::read(&cmdline_path).await {
            Ok(data) => data,
            Err(_) => continue,
        };

        if cmdline_bytes.is_empty() {
            continue;
        }

        let cmdline = String::from_utf8_lossy(&cmdline_bytes).replace('\0', " ");
        if !cmdline.contains("/.openclaw/skills/") {
            continue;
        }

        if let Some(skill_name) = extract_skill_name(&cmdline) {
            out.push((pid, skill_name));
        }
    }

    Ok(out)
}

#[cfg(target_os = "macos")]
async fn collect_skill_processes() -> Result<Vec<(u32, String)>> {
    let output = tokio::process::Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .await?;

    if !output.status.success() {
        anyhow::bail!("ps failed with {}", output.status);
    }

    let mut out = Vec::new();
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let mut parts = line.trim().splitn(2, ' ');
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let Some(cmd) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_raw.trim().parse::<u32>() else {
            continue;
        };

        if !cmd.contains("/.openclaw/skills/") {
            continue;
        }

        if let Some(skill_name) = extract_skill_name(cmd) {
            out.push((pid, skill_name));
        }
    }
    Ok(out)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn collect_skill_processes() -> Result<Vec<(u32, String)>> {
    Ok(Vec::new())
}

fn extract_skill_name(cmd: &str) -> Option<String> {
    let marker = "/.openclaw/skills/";
    let start = cmd.find(marker)? + marker.len();
    let rest = &cmd[start..];
    let skill = rest
        .split(['/', ' ', '\'', '"'])
        .find(|token| !token.is_empty())?;
    Some(skill.to_string())
}

async fn handle_fs_event(event: Event) {
    match event.kind {
        EventKind::Modify(_) | EventKind::Create(_) => {
            for path in &event.paths {
                let path_str = path.to_string_lossy();

                // SOUL.md / MEMORY.md writes are always CRITICAL
                if path_str.ends_with("SOUL.md") || path_str.ends_with("MEMORY.md") {
                    let msg = format!(
                        "CRITICAL: Unauthorized write to {} detected. Possible skill poisoning.",
                        path_str
                    );
                    log_alert(&msg).await;
                    eprintln!("🚨 {}", msg);
                    continue;
                }

                // Skill file modifications
                if path_str.contains("/.openclaw/skills/") {
                    // Re-audit the affected skill
                    if let Some(skill_dir) = find_skill_root(path) {
                        let skill_name = skill_dir
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        info!("Re-auditing skill '{}' due to file change", skill_name);
                        match audit::run_audit(&skill_dir.to_string_lossy(), false).await {
                            Ok(report) => {
                                for finding in report.findings {
                                    let msg = format!(
                                        "[{}] {}: {}",
                                        finding.severity, finding.skill, finding.detail
                                    );
                                    log_alert(&msg).await;
                                    if finding.severity >= crate::audit::Severity::High {
                                        eprintln!("🔴 {}", msg);
                                    }
                                }
                            }
                            Err(e) => error!("Re-audit failed: {}", e),
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn find_skill_root(path: &std::path::Path) -> Option<PathBuf> {
    // Walk up until we find the skills directory's direct child
    let mut current = path.to_path_buf();
    while let Some(parent) = current.parent() {
        if parent.ends_with(".openclaw/skills") {
            return Some(current);
        }
        current = parent.to_path_buf();
    }
    None
}

async fn log_alert(msg: &str) {
    let log_path = resolve_home(DAEMON_LOG_FILE);
    let entry = format!("[{}] {}\n", chrono::Utc::now().to_rfc3339(), msg);
    if let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
    {
        use tokio::io::AsyncWriteExt;
        let _ = file.write_all(entry.as_bytes()).await;
    }
}

fn resolve_home(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(stripped)
    } else {
        PathBuf::from(path)
    }
}

fn process_running(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            return true;
        }

        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}
