#!/usr/bin/env bash
# Install a user LaunchAgent that keeps the aarch64-linux remote builder
# (nixpkgs' darwin.linux-builder) running across logins — the persistence layer
# the bare `nix run nixpkgs#darwin.linux-builder` flow lacks.
#
# It installs start-builder.sh (the launcher wrapper, which enforces a stable
# TMPDIR off /tmp and a pinned known-good qemu via a gcroot — see that file for
# why both matter) and renders launchd-agent.plist into ~/Library/LaunchAgents.
#
# This is a per-user agent, not a root daemon: qemu's HVF acceleration needs the
# logged-in GUI session, so the builder runs only while this user is logged in.
#
# Idempotent; safe to re-run (it reloads the agent, picking up wrapper/plist
# edits). Run it as your login user, NOT with sudo.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# All builder runtime state lives here; override with GHA_BUILDER_HOME if you
# keep it elsewhere. The label is the agent's reverse-DNS id; override with
# GHA_BUILDER_LABEL on a host that isn't this one.
BASE="${GHA_BUILDER_HOME:-$HOME/.local/share/gha-linux-builder}"
LABEL="${GHA_BUILDER_LABEL:-uk.co.patrickstevens.gha-linux-builder}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

if [ "$(id -u)" -eq 0 ]; then
  echo "error: run as your login user, not root — HVF needs the GUI session." >&2
  exit 1
fi

mkdir -p "$BASE" "$HOME/Library/LaunchAgents"

# Preflight: the runtime state the agent depends on must already exist. These
# are created by booting the builder once and pinning a known-good run-builder;
# this script does not create them because pinning is a deliberate choice (the
# current nixpkgs qemu may be the HVF-crashing one).
miss=0
for p in "$BASE/run-builder-gcroot" "$BASE/nixos.qcow2" "$BASE/keys/builder_ed25519"; do
  if [ ! -e "$p" ]; then echo "error: missing prerequisite: $p" >&2; miss=1; fi
done
if [ "$miss" -ne 0 ]; then
  cat >&2 <<EOF

Set the builder up once before installing the agent:
  1) Boot it so it creates \$BASE/nixos.qcow2 and \$BASE/keys/ :
       cd "$BASE" && nix run nixpkgs#darwin.linux-builder
     If that qemu aborts on Apple Silicon (hvf_arch_init_vcpu ... Abort trap: 6),
     boot a known-good run-builder instead (an older one already in your store).
  2) Pin the working run-builder so GC and \`nix run\` drift can neither remove
     nor silently replace it:
       nix-store --realise <run-builder-store-path> --indirect \\
         --add-root "$BASE/run-builder-gcroot"
  3) Re-run this script.
EOF
  exit 1
fi

# Install the launcher wrapper.
install -m 0755 "$dir/start-builder.sh" "$BASE/start-builder.sh"

# Render the plist. The only substitutions are absolute paths/label, which a
# launchd plist cannot express portably itself. Escape each replacement for sed:
# a value containing the '#' delimiter, a literal '&' (which else expands to the
# whole match), or a backslash would otherwise corrupt the output (a $HOME with
# such a character is unusual but not impossible). Backslash is escaped first so
# the backslashes we add for '&'/'#' aren't doubled.
sed_repl_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/#/\\#/g'
}
label_esc="$(sed_repl_escape "$LABEL")"
wrapper_esc="$(sed_repl_escape "$BASE/start-builder.sh")"
base_esc="$(sed_repl_escape "$BASE")"
sed -e "s#__LABEL__#$label_esc#g" \
    -e "s#__WRAPPER__#$wrapper_esc#g" \
    -e "s#__BASE__#$base_esc#g" \
    "$dir/launchd-agent.plist" > "$PLIST"
plutil -lint "$PLIST"

# (Re)load it. bootout first so a re-run picks up edits; ignore "not loaded".
# Two instances would both try to bind host port 31022, so never run a manual
# `nix run` builder alongside this agent.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true

echo "Installed LaunchAgent $LABEL."
echo "  state:  launchctl print gui/$(id -u)/$LABEL"
echo "  log:    tail -f $BASE/builder.log"
echo "  restart: launchctl kickstart -k gui/$(id -u)/$LABEL"
echo "  stop:    launchctl bootout gui/$(id -u)/$LABEL"
