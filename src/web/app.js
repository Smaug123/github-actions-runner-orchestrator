// Tiny control UI: poll /status, render it, and drive /pause + /resume.
// Talks only to the same loopback control server that served this page.
"use strict";

const POLL_MS = 2000;

const el = (id) => document.getElementById(id);
const badge = el("badge");
const buttons = [el("pause"), el("resume")];

// Render a {paused, in_flight, max_concurrency} status. `live` is false when we
// failed to reach the server, so the UI shows a stale/disconnected state rather
// than silently freezing on the last-known values.
function render(status, live) {
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

  // Disable the button that matches the current state — can't pause when
  // already paused, or resume when already running.
  el("pause").disabled = paused;
  el("resume").disabled = !paused;
}

function stamp(ok) {
  el("error").textContent = ok ? "" : "control server unreachable";
  if (ok) el("updated").textContent = "updated " + new Date().toLocaleTimeString();
}

async function refresh() {
  try {
    const res = await fetch("/status");
    if (!res.ok) throw new Error("status " + res.status);
    render(await res.json(), true);
    stamp(true);
  } catch (e) {
    render(null, false);
    stamp(false);
  }
}

// POST /pause or /resume. Both return the updated status, so we render straight
// from the response instead of waiting for the next poll.
async function send(path) {
  buttons.forEach((b) => (b.disabled = true));
  try {
    const res = await fetch(path, { method: "POST" });
    if (!res.ok) throw new Error("status " + res.status);
    render(await res.json(), true);
    stamp(true);
  } catch (e) {
    render(null, false);
    stamp(false);
  }
}

el("pause").addEventListener("click", () => send("/pause"));
el("resume").addEventListener("click", () => send("/resume"));

refresh();
setInterval(refresh, POLL_MS);
