// egress.rs — Network egress monitoring (premium)
// Attributes outbound connections to the skill subprocesses that initiated them.
// Uses /proc/net/tcp on Linux and lsof on macOS.
//
// Full implementation reads:
//   Linux: /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6 for socket inodes,
//          then cross-references /proc/<pid>/fd/* for open socket fds
//   macOS: spawns `lsof -i -n -P -p <pid>` and parses output
//
// This module is invoked by the daemon when process anomaly detection is active.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct EgressEvent {
    pub pid: u32,
    pub process_name: String,
    pub skill_name: Option<String>,
    pub remote_addr: String,
    pub remote_port: u16,
    pub declared: bool, // true if skill declared this connection in its manifest
}

pub async fn snapshot_connections(skill_pids: &[(u32, String)]) -> Result<Vec<EgressEvent>> {
    info!("Snapshotting network connections for {} skill processes", skill_pids.len());

    #[cfg(target_os = "linux")]
    return linux_connections(skill_pids).await;

    #[cfg(target_os = "macos")]
    return macos_connections(skill_pids).await;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::bail!("Egress monitoring not supported on this platform")
}

#[cfg(target_os = "linux")]
async fn linux_connections(skill_pids: &[(u32, String)]) -> Result<Vec<EgressEvent>> {
    // Parse /proc/net/tcp and /proc/net/tcp6
    // Cross-reference with /proc/<pid>/fd/* for each tracked skill pid
    // Production implementation — stub for now
    let _ = skill_pids;
    Ok(vec![])
}

#[cfg(target_os = "macos")]
async fn macos_connections(skill_pids: &[(u32, String)]) -> Result<Vec<EgressEvent>> {
    // Use `lsof -i -n -P -p <pid1>,<pid2>,...` and parse output
    let pids: Vec<String> = skill_pids.iter().map(|(pid, _)| pid.to_string()).collect();
    let output = tokio::process::Command::new("lsof")
        .args(["-i", "-n", "-P", "-p", &pids.join(",")])
        .output()
        .await?;

    let _ = output; // parse in production implementation
    Ok(vec![])
}
