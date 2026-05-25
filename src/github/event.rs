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
    pub name: String,
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
}
