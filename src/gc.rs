// Reconciliation sweep.
//
// Truth lives in three places:
//   1. cur/ on the spool filesystem — claimed jobs we believe are in flight,
//   2. `limactl list` on the host — VMs that actually exist,
//   3. /orgs/{org}/actions/runners on GitHub — runners GH thinks are registered.
//
// A periodic sweep walks all three and resolves drift:
//
//   * cur/ files older than JOB_MAX_RUNTIME_SECS are moved to error/ (we
//     assume the daemon was restarted mid-job and the VM is now an orphan).
//     Age is measured from claim time (mtime is stamped on rename into cur/);
//   * any Lima VM whose name has our `gha-` prefix but no live cur/ file is
//     stopped and deleted,
//   * any GH runner with our `gha-` prefix that isn't backed by a live cur/
//     file and is offline (or simply not busy) is DELETEd via API.
//
// `live` is built by reading each cur/ file's body and computing the same
// vm_name the supervisor would: signed (repo, workflow_job.id) → SHA-256.
// We never derive a vm_name from envelope/header data; using only signed
// fields means a replay produces the same name we already know about.
//
// SINGLETON DEPLOYMENT REQUIRED PER (org, runner-group).
//
// The runner branch below treats *this* process's cur/ as the single
// source of truth for what `gha-<16hex>` runners should exist in the
// org. Two consumers running against the same org with separate
// SPOOL_DIRs would each see the other's freshly-minted (online, not yet
// busy) runners as orphans and delete them in the window between mint
// and job pickup — a self-inflicted denial of service.
//
// Safe configurations:
//   * one process per (org, runner-group);
//   * multiple processes sharing the same SPOOL_DIR (and so the same
//     cur/), because every consumer sees every claim;
//   * separate consumers in *different* orgs or runner-groups.
//
// Unsafe: separate consumers in the same (org, runner-group) with
// separate SPOOL_DIRs. There's no in-band check for this — the org
// runner list doesn't carry "which consumer minted me" — so the launchd
// plist / deployment harness is the right place to enforce singleton.
// A future option is namespacing runner names per consumer (e.g.
// `gha-<consumer-id>-<jobid>`) and restricting GC to that namespace.

use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::config::Config;
use crate::github::jit::GhClient;
use crate::lima::Lima;
use crate::runner::vm_name;
use crate::spool::{parse_spool_filename, sanitize_for_log};

const VM_NAME_PREFIX: &str = "gha-";

/// True iff `name` matches the exact shape this factory ever mints:
/// `gha-` followed by 16 lowercase hex chars (the `{:016x}` of a u64
/// workflow_job id). The bare `gha-` prefix is too broad — other tooling in
/// the same org/host can plausibly use the same prefix, and GC's runner
/// branch deletes idle online runners, so a loose match risks blasting away
/// unrelated infrastructure.
fn is_managed_vm_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(VM_NAME_PREFIX) else {
        return false;
    };
    suffix.len() == 16
        && suffix
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub async fn sweep(config: &Config, gh: &GhClient, lima: &Lima) {
    if let Err(e) = sweep_inner(config, gh, lima).await {
        warn!(error = %e, "gc sweep error");
    }
}

async fn sweep_inner(config: &Config, gh: &GhClient, lima: &Lima) -> anyhow::Result<()> {
    let cur_dir = config.spool_dir.join("cur");

    expire_stale_cur(
        &cur_dir,
        &config.spool_dir.join("error"),
        config.job_max_runtime_secs,
    )
    .await?;

    let live = live_vm_names_from_cur(&cur_dir).await.unwrap_or_default();

    match lima.list_names().await {
        Ok(names) => {
            for name in names {
                if !is_managed_vm_name(&name) {
                    continue;
                }
                if !live.contains(&name) {
                    info!(vm = %name, "gc: orphan Lima VM, deleting");
                    if let Err(e) = lima.stop(&name).await {
                        warn!(vm = %name, error = %e, "stop");
                    }
                    if let Err(e) = lima.delete(&name).await {
                        warn!(vm = %name, error = %e, "delete");
                    }
                }
            }
        }
        Err(e) => warn!(error = %e, "gc: limactl list failed"),
    }

    match gh.list_runners(VM_NAME_PREFIX).await {
        Ok(runners) => {
            for r in runners {
                // Restrict deletion to the exact shape this factory mints.
                // The org's runner group may host runners from other tooling
                // that happens to share the gha- prefix; we must never delete
                // those.
                if !is_managed_vm_name(&r.name) {
                    continue;
                }
                let backed_by_vm = live.contains(&r.name);
                let dead = r.status == "offline" || !r.busy;
                if !backed_by_vm && dead {
                    info!(
                        runner = %r.name,
                        status = %r.status,
                        busy = r.busy,
                        "gc: removing orphan runner"
                    );
                    if let Err(e) = gh.delete_runner(r.id).await {
                        warn!(runner = %r.name, error = %e, "delete runner");
                    }
                }
            }
        }
        Err(e) => warn!(error = %e, "gc: list runners failed"),
    }
    Ok(())
}

async fn expire_stale_cur(
    cur_dir: &Path,
    error_dir: &Path,
    max_age_secs: u64,
) -> anyhow::Result<()> {
    let mut rd = tokio::fs::read_dir(cur_dir).await?;
    let now = std::time::SystemTime::now();
    while let Some(ent) = rd.next_entry().await? {
        let md = match ent.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = md.modified().unwrap_or(now);
        let age = now.duration_since(modified).unwrap_or_default();
        if age.as_secs() > max_age_secs {
            let name = ent.file_name();
            warn!(file = %sanitize_for_log(&name.to_string_lossy()), age_secs = age.as_secs(), "stale cur/ entry -> error/");
            let from = ent.path();
            let to = error_dir.join(&name);
            let err_path = error_dir.join(format!("{}.err", name.to_string_lossy()));
            let _ = tokio::fs::write(
                &err_path,
                format!(
                    "expired by gc: age {}s > {}s\n",
                    age.as_secs(),
                    max_age_secs
                ),
            )
            .await;
            if let Err(e) = tokio::fs::rename(&from, &to).await {
                warn!(error = %e, "rename stale cur/ -> error/");
            }
        }
    }
    Ok(())
}

/// Derive the expected vm_name for each cur/ file straight from its
/// filename. The filename is `<workflow_job_id>.job`, and vm_name is a
/// deterministic function of that id, so we don't need to read any bodies
/// here. The supervisor validates the filename ↔ envelope id match before
/// it ever lets a file get into cur/, so what's here is trustworthy.
async fn live_vm_names_from_cur(cur_dir: &Path) -> anyhow::Result<HashSet<String>> {
    let mut out = HashSet::new();
    let mut rd = tokio::fs::read_dir(cur_dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let Ok(ft) = ent.file_type().await else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let Some(s) = ent.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(id) = parse_spool_filename(&s) {
            out.insert(vm_name(id));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::vm_name;

    #[test]
    fn is_managed_vm_name_accepts_generated_shape() {
        assert!(is_managed_vm_name(&vm_name(0)));
        assert!(is_managed_vm_name(&vm_name(42)));
        assert!(is_managed_vm_name(&vm_name(u64::MAX)));
        // The generator always pads to 16 hex chars.
        assert!(is_managed_vm_name("gha-0000000000000001"));
        assert!(is_managed_vm_name("gha-deadbeefcafebabe"));
    }

    #[test]
    fn is_managed_vm_name_rejects_other_prefix_users() {
        // Common shapes we must not flatten: hand-named, label-suffixed,
        // uppercase hex, too-short, too-long, non-hex characters.
        assert!(!is_managed_vm_name("gha"));
        assert!(!is_managed_vm_name("gha-"));
        assert!(!is_managed_vm_name("gha-test"));
        assert!(!is_managed_vm_name("gha-runner-1"));
        assert!(!is_managed_vm_name("gha-DEADBEEFCAFEBABE"));
        assert!(!is_managed_vm_name("gha-0000000000000001-suffix"));
        assert!(!is_managed_vm_name("gha-0000000000000")); // 15
        assert!(!is_managed_vm_name("gha-00000000000000000")); // 17
        assert!(!is_managed_vm_name("gha-zzzzzzzzzzzzzzzz"));
        assert!(!is_managed_vm_name("other-0000000000000001"));
    }
}
