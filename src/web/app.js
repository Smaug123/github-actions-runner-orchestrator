// Control UI client. Talks only to the loopback control server that served
// this page. Two independent pollers:
//   * /status at 2s drives the persistent header (badge + meter + pause/resume),
//   * /jobs at 5s (skipped while the page is hidden) drives the three tabs.
// All cell text is set via textContent (never innerHTML): defence in depth atop
// the server-side sanitize_for_log, so an author-controlled repo/name/label/
// reason can never inject markup.
"use strict";

const STATUS_POLL_MS = 2000;
const JOBS_POLL_MS = 5000;
const TABS = ["queued", "inflight", "completed"];

const el = (id) => document.getElementById(id);
const badge = el("badge");
const buttons = [el("pause"), el("resume")];

// ---- header: /status -------------------------------------------------------

// Render a {paused, in_flight, max_concurrency} status. `live` is false when we
// failed to reach the server, so the UI shows a disconnected state rather than
// silently freezing on the last-known values.
function renderStatus(status, live) {
  if (!live) {
    badge.className = "badge stale";
    el("badge-text").textContent = "unreachable";
    buttons.forEach((b) => (b.disabled = true));
    return;
  }

  const { paused, in_flight, max_concurrency } = status;
  badge.className = "badge " + (paused ? "paused" : "running");
  el("badge-text").textContent = paused ? "Paused" : "Running";

  el("in-flight").textContent = in_flight;
  el("max").textContent = max_concurrency;
  const pct = max_concurrency > 0 ? (in_flight / max_concurrency) * 100 : 0;
  el("meter-fill").style.width = pct + "%";

  // Disable the button matching the current state.
  el("pause").disabled = paused;
  el("resume").disabled = !paused;
}

function stamp(ok) {
  el("error").textContent = ok ? "" : "control server unreachable";
  if (ok) el("updated").textContent = "updated " + new Date().toLocaleTimeString();
}

async function refreshStatus() {
  try {
    const res = await fetch("/status");
    if (!res.ok) throw new Error("status " + res.status);
    renderStatus(await res.json(), true);
    stamp(true);
  } catch (e) {
    renderStatus(null, false);
    stamp(false);
  }
}

// POST /pause or /resume; both return the updated status so we render straight
// from the response instead of waiting for the next poll.
async function send(path) {
  buttons.forEach((b) => (b.disabled = true));
  try {
    const res = await fetch(path, { method: "POST" });
    if (!res.ok) throw new Error("status " + res.status);
    renderStatus(await res.json(), true);
    stamp(true);
  } catch (e) {
    renderStatus(null, false);
    stamp(false);
  }
}

el("pause").addEventListener("click", () => send("/pause"));
el("resume").addEventListener("click", () => send("/resume"));

// ---- tabs: /jobs -----------------------------------------------------------

// epoch ms of the latest VM snapshot (null = none yet); set in renderJobs and
// read by the in-flight row renderer to label VM status.
let vmSnapshotMs = null;

function td(text, cls) {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (cls) cell.className = cls;
  return cell;
}

function fmtAge(secs) {
  if (secs == null) return "—";
  if (secs < 60) return secs + "s";
  if (secs < 3600) return Math.floor(secs / 60) + "m";
  if (secs < 86400) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  return Math.floor(secs / 86400) + "d";
}

function fmtTime(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleString();
}

// Label an in-flight job's VM status for the sub-line. Uses snapshot freshness
// to tell "claimed but not in Lima yet" (booting/torn down) from "no snapshot".
function vmStatusLabel(job) {
  if (job.vm_status) {
    return { text: job.vm_status, cls: /^running$/i.test(job.vm_status) ? "ok" : "warn" };
  }
  if (vmSnapshotMs == null) return null; // no snapshot to speak from
  return { text: "booting?", cls: "warn" }; // claimed but absent from the snapshot
}

// GitHub Actions deep link for a job row, or null when we lack the run_id/repo
// to build one. repo is "owner/name" (GitHub's restricted charset); we encode
// each path segment defensively but keep the separating slash. run_id/id are
// integer strings, harmless, but encoded for the same belt-and-braces reason.
function ghJobUrl(job) {
  if (!job.run_id || !job.repo) return null;
  const repoPath = job.repo.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${repoPath}/actions/runs/${encodeURIComponent(job.run_id)}/job/${encodeURIComponent(job.id)}`;
}

// One renderer for both Queued and In flight — identical columns. In-flight
// rows also carry a `vm` field, shown as a muted second line under the id (with
// its live status from the snapshot) so it can be cross-referenced with
// `limactl list`. The trailing empty actions cell + stable data-id leave room
// for future priority-reorder controls.
function jobRow(job) {
  const tr = document.createElement("tr");
  tr.dataset.id = job.id;

  const idCell = document.createElement("td");
  const idMain = document.createElement("div");
  idMain.className = "mono";
  // Link the id to GitHub's Actions UI when we have the run_id; the id text is
  // still set via textContent (anchor href is a fixed-scheme github.com URL, so
  // it can't carry script — keeps the never-innerHTML guarantee intact).
  const url = ghJobUrl(job);
  if (url) {
    const a = document.createElement("a");
    a.className = "job-link";
    a.href = url;
    a.textContent = job.id;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    idMain.appendChild(a);
  } else {
    idMain.textContent = job.id;
  }
  idCell.appendChild(idMain);
  if (job.vm) {
    const vm = document.createElement("div");
    vm.className = "mono muted sub-line";
    // The VM name is the token operators copy most, so make it an atomic
    // selection unit (CSS .vm-name { user-select: all }): one click grabs the
    // whole `gha-…` id, and a drag can no longer bleed up into the linked
    // Actions id stacked above it in this same cell.
    const name = document.createElement("span");
    name.className = "vm-name";
    name.textContent = job.vm;
    vm.appendChild(name);
    const st = vmStatusLabel(job);
    if (st) {
      const badge = document.createElement("span");
      badge.className = "vm-status " + st.cls;
      badge.textContent = " · " + st.text;
      vm.appendChild(badge);
    }
    idCell.appendChild(vm);
  }
  tr.appendChild(idCell);

  tr.appendChild(td(job.repo || "—"));
  tr.appendChild(td(job.name == null ? "—" : job.name));
  tr.appendChild(td((job.labels && job.labels.length) ? job.labels.join(", ") : "—", "labels"));
  tr.appendChild(td(fmtAge(job.age_secs)));

  // Reserved for future reorder actions.
  tr.appendChild(td("", "actions"));
  return tr;
}

function completedRow(job) {
  const tr = document.createElement("tr");
  tr.dataset.id = job.id;
  tr.appendChild(td(job.id, "mono"));
  tr.appendChild(td(job.repo || "—"));
  tr.appendChild(td(job.name == null ? "—" : job.name));
  tr.appendChild(td(job.outcome, job.outcome === "error" ? "outcome-error" : "outcome-done"));
  tr.appendChild(td(fmtTime(job.finished_ms)));
  const reason = td(job.reason || "", "reason");
  if (job.reason) reason.title = job.reason;
  tr.appendChild(reason);
  return tr;
}

function fillRows(tbodyId, emptyId, items, rowFn) {
  const rows = (items || []).map(rowFn);
  el(tbodyId).replaceChildren(...rows);
  el(emptyId).style.display = rows.length ? "none" : "block";
}

function setNote(id, shown, text) {
  const note = el(id);
  if (shown) {
    note.textContent = text;
    note.hidden = false;
  } else {
    note.hidden = true;
  }
}

function renderJobs(data) {
  // Set before rendering rows: jobRow reads vmSnapshotMs to label VM status.
  vmSnapshotMs = data.vm_snapshot_ms ?? null;

  fillRows("queued-rows", "queued-empty", data.queued, jobRow);
  fillRows("inflight-rows", "inflight-empty", data.in_flight, jobRow);
  fillRows("completed-rows", "completed-empty", data.completed, completedRow);

  // Truncation notes: the server caps each list to bound work, and signals it.
  setNote(
    "queued-note",
    data.queued_truncated,
    `Showing ${(data.queued || []).length} entries; more are queued (list capped).`
  );
  setNote(
    "inflight-note",
    data.in_flight_truncated,
    `Showing ${(data.in_flight || []).length} entries; list capped.`
  );
  setNote(
    "completed-note",
    data.completed_truncated,
    `Showing newest ${(data.completed || []).length} of the last ${data.completed_window_hours}h; older entries omitted.`
  );

  renderVmNote(data);
}

// VM snapshot freshness + orphan VMs, shown on the In flight tab. Always
// visible there: muted for the normal "as of Ns ago", amber when orphans exist.
function renderVmNote(data) {
  const note = el("vm-note");
  const orphans = data.orphan_vms || [];
  let alert = false;
  if (vmSnapshotMs == null) {
    note.textContent = "VM status: initializing…";
  } else {
    const age = Math.max(0, Math.floor((Date.now() - vmSnapshotMs) / 1000));
    let msg = `VM snapshot ${fmtAge(age)} ago`;
    if (orphans.length) {
      msg += ` · ${orphans.length} orphan VM(s) (GC will reap): ${orphans.join(", ")}`;
      alert = true;
    }
    note.textContent = msg;
  }
  note.className = alert ? "note" : "subtle";
  note.hidden = false;
}

async function refreshJobs() {
  // Don't poll a backgrounded tab; we refresh immediately on becoming visible.
  if (document.hidden) return;
  try {
    const res = await fetch("/jobs");
    if (!res.ok) throw new Error("status " + res.status);
    renderJobs(await res.json());
    stamp(true);
  } catch (e) {
    stamp(false);
  }
}

// ---- tab switching (hash-routed, deep-linkable) ----------------------------

function currentTab() {
  const h = location.hash.replace("#", "");
  return TABS.includes(h) ? h : "queued";
}

function showTab(tab) {
  TABS.forEach((t) => {
    el("tab-" + t).classList.toggle("active", t === tab);
  });
  document.querySelectorAll(".tab").forEach((a) => {
    a.classList.toggle("active", a.dataset.tab === tab);
  });
}

window.addEventListener("hashchange", () => showTab(currentTab()));
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshJobs();
});

// ---- boot ------------------------------------------------------------------

showTab(currentTab());
refreshStatus();
refreshJobs();
setInterval(refreshStatus, STATUS_POLL_MS);
setInterval(refreshJobs, JOBS_POLL_MS);
