#!/usr/bin/env bash
# Build the netmap backend, install it, and sync the omarchy shell plugin.
#
#   ./install.sh                 build + install the binary + sync the plugin
#   ./install.sh --sync-only     just re-copy the QML (what you want while
#                                editing the panel; the shell hot-reloads)
#   ./install.sh --no-enable     do not add the widget to the bar
#   ./install.sh --uninstall     remove the plugin and the binary again
#
# Nothing is written outside ~/.local/bin and the omarchy plugin directory.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ID="omarchy-netmap"
CONFIG_HOME="$HOME/.config"
PLUGIN_DIR="$CONFIG_HOME/omarchy/plugins/$PLUGIN_ID"
BIN_DIR="$HOME/.local/bin"
BIN_PATH="$BIN_DIR/netmap"
BUILD=1
ENABLE=1
RESCAN=1

for arg in "$@"; do
  case "$arg" in
    --sync-only|--no-build) BUILD=0 ;;
    --no-enable) ENABLE=0 ;;
    --no-rescan) RESCAN=0 ;;
    --uninstall)
      echo "==> removing $PLUGIN_DIR"
      rm -rf "$PLUGIN_DIR"
      echo "==> removing $BIN_PATH"
      rm -f "$BIN_PATH"
      if command -v omarchy-shell >/dev/null 2>&1; then
        omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
      fi
      echo "Done. If the bar still shows the widget: omarchy bar move $PLUGIN_ID"
      exit 0
      ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [ "$BUILD" -eq 1 ]; then
  echo "==> building the backend (cargo build --release)"
  cargo build --release --manifest-path "$REPO_DIR/backend/Cargo.toml"
  echo "==> installing $BIN_PATH"
  install -Dm755 "$REPO_DIR/backend/target/release/netmap" "$BIN_PATH"
else
  echo "==> skipping the build"
  if [ ! -x "$BIN_PATH" ]; then
    echo "    note: $BIN_PATH does not exist yet - run without --sync-only first" >&2
  fi
fi

echo "==> syncing the plugin into $PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR"
# Runtime files only: the Rust sources, the tests and the fixtures stay in the
# repo. The plugin directory is what the shell loads, and what it validates.
install -m644 "$REPO_DIR/manifest.json" "$PLUGIN_DIR/manifest.json"
for file in "$REPO_DIR"/*.qml "$REPO_DIR"/*.js; do
  [ -e "$file" ] || continue
  install -m644 "$file" "$PLUGIN_DIR/$(basename "$file")"
done

if command -v omarchy >/dev/null 2>&1; then
  echo "==> validating the manifest"
  omarchy plugin validate "$PLUGIN_DIR"
fi

if command -v omarchy-shell >/dev/null 2>&1 && omarchy-shell shell ping >/dev/null 2>&1; then
  if [ "$RESCAN" -eq 1 ]; then
    echo "==> reloading the shell"
    omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
  fi
  if [ "$ENABLE" -eq 1 ]; then
    # Parse the JSON properly: grepping around an id easily matches a
    # neighbouring plugin's "enabled": true.
    state="$(omarchy plugin list --json 2>/dev/null | python3 -c '
import json, sys
plugin_id = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    print("unknown")
    raise SystemExit(0)
items = data if isinstance(data, list) else data.get("plugins", [])
for item in items:
    if item.get("id") == plugin_id:
        print("yes" if item.get("enabled") else "no")
        raise SystemExit(0)
print("missing")
' "$PLUGIN_ID" 2>/dev/null || echo unknown)"
    case "$state" in
      yes) echo "==> $PLUGIN_ID is already in the bar" ;;
      no)
        echo "==> adding the widget to the bar"
        omarchy plugin enable "$PLUGIN_ID" || true
        ;;
      *)
        echo "==> the shell has not picked the plugin up yet; retry: omarchy-shell shell rescanPlugins"
        ;;
    esac
  fi
else
  echo "==> no running omarchy shell found; skipping the IPC steps"
fi

cat <<'DONE'

netmap is installed.

  CLI     netmap                  scan your subnet, human readable
          netmap --help           every option
          netmap ifaces           interfaces, route and ARP cache
          netmap scan --jsonl     the stream the panel consumes

  Panel   click the bar icon, or bind a key:
          omarchy-shell shell toggle omarchy-netmap '{}'
          e.g. in ~/.config/hypr/bindings.conf:
          bindd = SUPER, N, Network map, exec, omarchy-shell shell toggle omarchy-netmap '{}'

  Keys    j/k move, enter open, s ssh, o browser, w web app, c copy,
          f filter, d details, r rescan, esc close
DONE
