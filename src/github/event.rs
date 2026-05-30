// Just enough of the workflow_job webhook payload to dispatch a JIT runner.
//
// We deliberately don't model the whole payload: only the fields we filter
// or echo back. Anything else flows through as opaque JSON in the spool
// file and is available if a future feature needs it.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WorkflowJob {
    pub action: String,
    pub workflow_job: WorkflowJobInfo,
    pub repository: Repository,
}

#[derive(Debug, Deserialize)]
pub struct WorkflowJobInfo {
    pub id: u64,
    pub run_id: u64,
    /// Re-run counter for `run_id`. Present in the webhook payload since 2021;
    /// `#[serde(default)]` keeps us decoding an older or trimmed body. Carried
    /// for log correlation and the reconciler's synthetic spool record.
    #[serde(default)]
    pub run_attempt: u64,
    /// Branch the job runs against. Nullable in the GitHub schema, so
    /// `Option`; `#[serde(default)]` also keeps already-enqueued spool bodies
    /// (written before this field existed) decoding. Used by the cache warmer
    /// to recognise a default-branch build.
    // Consumed by the cache warmer (a later slice); parsed now so spool bodies
    // written before it lands already carry the field.
    #[allow(dead_code)]
    #[serde(default)]
    pub head_branch: Option<String>,
    /// Commit the job runs against. `Option` + `#[serde(default)]` for the same
    /// backward-compatibility reason as `head_branch`. The warmer cross-checks
    /// it against the live default-branch tip before warming.
    #[allow(dead_code)]
    #[serde(default)]
    pub head_sha: Option<String>,
    pub name: String,
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_event_with_head_fields() {
        let json = r#"{
            "action": "queued",
            "workflow_job": {
                "id": 4242,
                "run_id": 99,
                "run_attempt": 2,
                "head_branch": "main",
                "head_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "name": "build",
                "labels": ["self-hosted", "lima-nix"]
            },
            "repository": {"id": 7, "full_name": "o/r"}
        }"#;
        let e: WorkflowJob = serde_json::from_str(json).unwrap();
        assert_eq!(e.workflow_job.run_attempt, 2);
        assert_eq!(e.workflow_job.head_branch.as_deref(), Some("main"));
        assert_eq!(
            e.workflow_job.head_sha.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(e.repository.id, 7);
    }

    #[test]
    fn decodes_body_without_head_fields() {
        // An already-enqueued spool body (written before head_branch/head_sha
        // existed) must still decode; the missing fields default to None.
        let json = r#"{
            "action": "queued",
            "workflow_job": {
                "id": 1,
                "run_id": 2,
                "name": "build",
                "labels": ["self-hosted"]
            },
            "repository": {"id": 7, "full_name": "o/r"}
        }"#;
        let e: WorkflowJob = serde_json::from_str(json).unwrap();
        assert_eq!(e.workflow_job.run_attempt, 0);
        assert_eq!(e.workflow_job.head_branch, None);
        assert_eq!(e.workflow_job.head_sha, None);
    }

    #[test]
    fn decodes_null_head_branch() {
        // head_branch is nullable in the GitHub schema; an explicit null must
        // decode to None rather than erroring.
        let json = r#"{
            "action": "queued",
            "workflow_job": {
                "id": 1,
                "run_id": 2,
                "head_branch": null,
                "head_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "name": "build",
                "labels": ["self-hosted"]
            },
            "repository": {"id": 7, "full_name": "o/r"}
        }"#;
        let e: WorkflowJob = serde_json::from_str(json).unwrap();
        assert_eq!(e.workflow_job.head_branch, None);
        assert_eq!(
            e.workflow_job.head_sha.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
    }
}
