import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// The plugin's service: one headless owner of "what is on my network".
//
// The scan is a short-lived child process that streams newline-delimited JSON,
// so the shell never blocks and the map fills in while the scan runs. Keeping
// this in a service (manifest kind "service") means every bar instance shares
// one scan and one map instead of starting its own process per monitor.
Item {
  id: root

  // ---- settings, pushed by the panel from the shell.json entry ----------
  property var settings: ({})

  // ---- state -------------------------------------------------------------
  property var state: Model.emptyState()
  property bool scanning: false
  property string binaryPath: ""
  property string lastError: ""
  property double startedAt: 0
  property double finishedAt: 0
  property string activity: ""
  property var toast: ({ text: "", kind: "ok" })
  property bool active: false
  /// Media player found on PATH for rtsp streams ("vlc", "mpv", "ffplay").
  /// Empty means xdg-open, which uses whatever handles rtsp:// on this system.
  property string player: ""
  /// Continuous monitoring: one long-lived scanner process that rescans on an
  /// interval and reports what changed since the previous round.
  property bool watching: false
  /// Desktop notification for changes noticed while monitoring.
  property bool notifyOnChange: true
  property int watchedInterval: 0
  property double lastNotifyAt: 0
  /// A child is being stopped on purpose: its exit is not a crash, and the
  /// replacement named by pendingStart waits for that exit instead of racing
  /// the kill (see the note above startWatch).
  property bool childStopping: false
  property string pendingStart: ""
  /// Last error line a media player printed, so a player that exits at once
  /// can explain itself instead of opening nothing.
  property string mediaError: ""
  property bool mediaErrorNeedsAuth: false
  /// Last output of netmap wol, so the panel can report how many packets went out.
  property string wolOutput: ""
  property string wolError: ""
  property string wolTarget: ""

  /// Everything the plugin actually launches is written to the shell journal,
  /// because a toast lives 2.6 seconds and "what did it really do" needs an
  /// answer that survives longer than that.
  function logAction(message) {
    console.log("[netmap] " + message);
  }

  readonly property var hosts: Model.orderedHosts(state)
  readonly property var summary: Model.summarize(state)
  readonly property var services: state.mdns || []

  signal scanStarted()
  signal scanFinished()

  // Directory this plugin was loaded from, so a locally built backend is found
  // without installing anything on PATH.
  readonly property string pluginDir: {
    var url = Qt.resolvedUrl(".").toString();
    if (url.indexOf("file://") === 0) url = url.substring(7);
    try { url = decodeURIComponent(url) } catch (e) { url = url; }
    while (url.length > 1 && url.charAt(url.length - 1) === "/") {
      url = url.substring(0, url.length - 1);
    }
    return url;
  }

  function setting(name, fallback) {
    var value = root.settings ? root.settings[name] : undefined;
    return value === undefined || value === null ? fallback : value;
  }

  function hostByIp(ip) {
    return state.hosts[ip] ? state.hosts[ip] : null;
  }

  // ---- binary discovery ---------------------------------------------------
  //
  // A locally built backend, a system install, or NETMAP_BIN. The plugin never
  // builds anything itself.
  readonly property string probeScript:
    'd="$1"; ' +
    'for c in "$NETMAP_BIN" "$HOME/.local/bin/netmap" "$HOME/.cargo/bin/netmap" ' +
    '"$d/backend/target/release/netmap" "$d/backend/target/debug/netmap"; do ' +
    '[ -n "$c" ] && [ -x "$c" ] && { echo "$c"; exit 0; }; done; command -v netmap'

  Process {
    id: binaryProbe
    command: ["bash", "-lc", root.probeScript, "bash", root.pluginDir]

    stdout: SplitParser {
      onRead: function (line) {
        // A hot reload destroys this instance while its child may still be
        // running, and the handler then fires on a null root.
        if (!root) return;
        var value = String(line || "").trim();
        if (value.length > 0) root.binaryPath = value;
      }
    }

    onExited: function (exitCode) {
      // The instance can be destroyed under a running child during a reload.
      if (!root) return;
      if (exitCode !== 0 || root.binaryPath === "") {
        root.lastError = "netmap backend not found - run install.sh or set NETMAP_BIN";
        return;
      }
      root.lastError = "";
      playerProbe.running = true;
      if (root.setting("autoScan", true) === true) startupScan.restart();
    }
  }

  Timer {
    id: startupScan
    interval: 6000
    onTriggered: root.startWatch()
  }

  // rtsp streams need a media player, not a browser. Probed once at startup.
  Process {
    id: playerProbe
    command: ["bash", "-lc", 'for p in vlc mpv ffplay; do command -v "$p" >/dev/null 2>&1 && { echo "$p"; exit 0; }; done']
    stdout: SplitParser {
      onRead: function (line) {
        if (!root) return;
        var value = String(line || "").trim();
        if (value.length > 0) root.player = value;
      }
    }
  }

  // ---- scan lifecycle -----------------------------------------------------

  /// Interval used both for continuous monitoring and for the refresh while
  /// the panel is open.
  function interval() {
    return Math.max(15, Number(root.setting("intervalSec", 60)));
  }

  function scanCommand(watch) {
    var argv = [
      root.binaryPath,
      "scan",
      "--jsonl",
      "--ports", String(root.setting("ports", "top")),
      "--timeout", String(root.setting("timeoutMs", 400)),
      "--concurrency", String(root.setting("concurrency", 1024)),
      "--mdns", String(root.setting("mdns", "auto")),
      "--mdns-ms", String(root.setting("mdnsMs", 2500))
    ];
    if (root.setting("deepProbe", true) !== true) argv.push("--no-probe");
    if (root.setting("netbios", true) !== true) argv.push("--no-netbios");
    var hosts = String(root.setting("hosts", "")).trim();
    if (hosts.length > 0) argv.push("--hosts", hosts);
    var subnets = String(root.setting("subnets", "")).trim();
    if (subnets.length > 0) {
      var parts = subnets.split(/[,\s]+/).filter(function (part) { return part.length > 0; });
      for (var i = 0; i < parts.length; i++) argv.push("--subnet", parts[i]);
    }
    if (watch === true) {
      // One long-lived process, one round per interval, and a diff event per
      // round so a consumer is told what changed instead of diffing itself.
      argv.push("--watch", String(root.interval()));
    }
    return argv;
  }

  // ---- continuous monitoring ---------------------------------------------
  //
  // Watching is a long-lived process rather than a timer that spawns scans, so
  // the backend keeps the previous round snapshot and emits a diff. The map
  // never goes blank between rounds.
  /// Stop the current scan child. Its exit is observed in onExited, which is
  /// the only place a new child may be started: starting one here, in the same
  /// breath as the kill, is what let the old child's exit signal tear down its
  /// own replacement - and then "helpfully" restart it, forever.
  function stopChild() {
    if (!scanProcess.running) return false;
    root.childStopping = true;
    scanProcess.running = false;
    return true;
  }

  function startWatch() {
    if (root.watching) return true;
    // Clear the notice from the previous child: monitoring is back, and a
    // stale error leaves the bar icon urgent for no reason.
    if (root.lastError.indexOf("monitoring stopped") === 0) root.lastError = "";
    if (root.binaryPath === "") {
      root.notify(root.lastError !== "" ? root.lastError : "netmap backend not found", "error");
      return false;
    }
    // A child is still on its way out (or a scan is running): queue the watch
    // for onExited instead of racing the kill.
    if (root.childStopping || scanProcess.running) {
      root.childStopping = true;
      root.pendingStart = "watch";
      scanProcess.running = false;
      return true;
    }
    return root.launchWatch();
  }

  function launchWatch() {
    root.watchedInterval = root.interval();
    scanProcess.command = root.scanCommand(true);
    root.watching = true;
    root.scanning = true;
    root.startedAt = Date.now();
    root.childStopping = false;
    root.pendingStart = "";
    watchGuard.restart();
    scanProcess.running = true;
    root.scanStarted();
    return true;
  }

  function stopWatch(quiet) {
    // An explicit stop also cancels a start that was queued behind the child
    // being killed.
    root.pendingStart = "";
    var wasRunning = root.stopChild();
    watchGuard.stop();
    root.watching = false;
    root.scanning = false;
    root.watchedInterval = 0;
    if (quiet !== true) root.notify("Continuous monitoring off", "warn");
    if (wasRunning) root.scanFinished();
    return true;
  }

  function toggleWatch() {
    if (root.watching) return root.stopWatch(false);
    return root.startWatch();
  }

  /// Called by the panel after it pushed new settings: changing the interval
  /// has to restart the running watch process to take effect.
  function onSettingsApplied() {
    root.notifyOnChange = root.setting("notify", "On") !== "Off";
    if (root.watching && root.watchedInterval !== root.interval()) {
      root.stopWatch(true);
      root.startWatch();
    }
  }

  function startScan(force) {
    if (root.scanning) return false;
    if (root.binaryPath === "") {
      root.notify(root.lastError !== "" ? root.lastError : "netmap backend not found", "error");
      return false;
    }
    if (force !== true && root.startedAt > 0 && Date.now() - root.startedAt < 5000) return false;
    if (root.childStopping || scanProcess.running) {
      root.childStopping = true;
      root.pendingStart = "scan";
      scanProcess.running = false;
      return true;
    }
    return root.launchScan();
  }

  function launchScan() {
    scanProcess.command = root.scanCommand(false);
    root.scanning = true;
    root.startedAt = Date.now();
    root.activity = "";
    root.toast = { text: "", kind: "ok" };
    root.childStopping = false;
    root.pendingStart = "";
    scanGuard.restart();
    scanProcess.running = true;
    root.scanStarted();
    return true;
  }

  function cancelScan() {
    if (!root.scanning) return;
    root.stopChild();
    scanGuard.stop();
    root.scanning = false;
    root.notify("Scan stopped", "warn");
  }

  Process {
    id: scanProcess
    running: false

    stdout: SplitParser {
      onRead: function (line) { if (root) root.ingest(line); }
    }

    // In --jsonl mode the stream carries everything, so anything on stderr is a
    // real warning rather than progress.
    stderr: SplitParser {
      onRead: function (line) {
        if (!root) return;
        var text = String(line || "").trim();
        if (text.length > 0) root.activity = text;
      }
    }

    onExited: function (exitCode) {
      // The instance can be destroyed under a running child during a reload.
      if (!root) return;
      scanGuard.stop();
      watchGuard.stop();
      var wasWatching = root.watching;
      // A stop we asked for is not a crash, and its replacement only starts
      // now: the old child is really gone, so nothing can tear the new one down.
      var stopped = root.childStopping;
      var pending = root.pendingStart;
      root.childStopping = false;
      root.pendingStart = "";
      root.watching = false;
      root.watchedInterval = 0;
      root.scanning = false;
      if (pending === "watch") { root.launchWatch(); return; }
      if (pending === "scan") { root.launchScan(); return; }
      if (stopped) {
        root.finishedAt = Date.now();
        root.scanFinished();
        return;
      }
      if (exitCode !== 0 && root.state.meta === null) {
        root.lastError = "scan failed (exit " + exitCode + ")";
      } else if (wasWatching && exitCode !== 0) {
        // A child that was killed (a plugin reload, a shell restart, a crash)
        // is not a decision the user made: put monitoring back if it is
        // configured on, so the map keeps itself fresh.
        root.lastError = "monitoring stopped (exit " + exitCode + ")"
          + (root.setting("autoScan", true) === true ? ", restarting" : "");
        if (root.setting("autoScan", true) === true) resumeWatch.restart();
      }
      root.finishedAt = Date.now();
      root.scanFinished();
    }
  }

  // A backend that hangs would otherwise leave the panel showing "scanning".
  Timer {
    id: scanGuard
    interval: 150000
    onTriggered: {
      root.notify("Scan timed out after 150s", "error");
      root.cancelScan();
    }
  }

  // In watch mode the process is meant to live for hours, so this is an
  // inactivity watchdog instead: every event restarts it, and it only fires
  // once the stream has gone quiet for several intervals.
  Timer {
    id: watchGuard
    interval: 180000
    onTriggered: {
      root.notify("Monitoring stopped: the scanner went quiet", "error");
      root.stopWatch(true);
    }
  }

  function ingest(line) {
    var text = String(line || "").trim();
    if (text.length === 0) return;
    var event = null;
    try {
      event = JSON.parse(text);
    } catch (error) {
      return;
    }
    if (!event || typeof event !== "object") return;
    state = Model.applyEvent(state, event);
    watchGuard.restart();
    if (event.type === "status" && event.message) root.activity = event.message;
    if (event.type === "diff") {
      var change = Model.diffSummary(event);
      if (change) {
        // The journal becomes the audit trail for "when did that machine come
        // up?" - which is the only answer to whether a wake actually worked.
        root.logAction("change: " + change + " - " + Model.diffHeadline(event));
        root.activity = change;
        root.notify(change, "ok");
        if (root.notifyOnChange) root.notifyChange(Model.diffHeadline(event), change);
      }
    }
    if (event.type === "host" && event.ports && event.ports.length > 0) {
      root.activity = "found " + event.ip;
    }
    if (event.type === "error" && event.message) root.lastError = String(event.message);
  }

  // ---- refresh policy -----------------------------------------------------
  //
  // While the panel is open the map refreshes itself; when it is closed the
  // scan only runs on request (or once at startup), so the plugin is never a
  // background port scanner.
  function setActive(on) {
    root.active = on === true;
    if (!root.active) {
      // Monitoring is deliberate: closing the panel keeps it running so the
      // change alerts keep coming. Only the plain refresh loop is tied to the
      // panel being open.
      refreshTimer.stop();
      return;
    }
    if (root.watching) {
      // The watch process is the only scan source while monitoring: letting the
      // refresh timer run as well would fire a one-shot scan on top of the
      // monitor at every interval boundary.
      refreshTimer.stop();
      return;
    }
    refreshTimer.interval = root.interval() * 1000;
    refreshTimer.restart();
    if (root.startedAt === 0 || Date.now() - root.startedAt > refreshTimer.interval) {
      root.startWatch();
    }
  }

  Timer {
    id: refreshTimer
    repeat: true
    running: false
    onTriggered: root.startScan(true)
  }

  // ---- actions ------------------------------------------------------------

  // The single launch point. Model.argvFor validates the scheme for the kind
  // and refuses anything that must not be launched, so a non-URL can never
  // reach a launcher - which is how an ssh command once opened a browser.
  // Media players run as a managed child: a camera refusing with 401, a stream
  // that is not there, a missing codec - all of it exits immediately, and
  // "nothing happened" is the worst possible answer. The player's own error
  // line comes back as a toast. (The trade-off: the player is a child of the
  // shell, so restarting the shell closes it.)
  function playUrl(action) {
    // The probe already knows when a camera refused with 401, so say so
    // immediately instead of launching a player that can only fail.
    if (action.needsAuth === true && root.setting("rtspUser", "") === "") {
      var hint = "The camera answered 401 Unauthorized: set the stream credentials, e.g. "
        + "omarchy bar set omarchy-netmap rtspUser admin, then rtspPassword (or export "
        + "NETMAP_RTSP_PASSWORD), then rtspPath (Dahua: /cam/realmonitor?channel=1&subtype=0)";
      root.notify(hint, "error");
      root.notifyDesktop(action.title ? ("Stream " + action.title) : "Stream", hint);
      return false;
    }
    var argv = Model.argvFor(action, { player: root.player });
    if (!argv || argv.length === 0) {
      root.notify("No media player available for " + (action.url || ""), "warn");
      return false;
    }
    root.mediaError = "";
    root.mediaErrorNeedsAuth = action.needsAuth === true;
    root.logAction("play " + (action.url || "")
      + (root.player !== "" ? " via " + root.player : " via the system handler"));
    mediaProcess.command = argv;
    mediaProcess.running = true;
    root.notify("Playing " + (action.url || ""), "ok");
    return true;
  }

  Process {
    id: mediaProcess
    running: false

    stdout: SplitParser {
      onRead: function (line) { if (root) root.notePlayerLine(line); }
    }
    stderr: SplitParser {
      onRead: function (line) { if (root) root.notePlayerLine(line); }
    }

    onExited: function (exitCode) {
      // The instance can be destroyed under a running child during a reload.
      if (!root) return;
      if (exitCode === 0) return;
      var detail = root.mediaError !== ""
        ? root.mediaError
        : "the player exited with code " + exitCode;
      if (root.mediaErrorNeedsAuth) {
        detail += " - the camera asked for credentials: set rtspUser and rtspPassword";
        if (root.setting("rtspPath", "") === "") {
          detail += " (and rtspPath, e.g. /cam/realmonitor?channel=1&subtype=0 for Dahua)";
        }
      }
      // A desktop notification, not just the panel toast: the panel closes
      // itself when it launches a player, so a toast inside it would never be
      // seen - which is how "nothing happens" stays unexplained.
      root.logAction("stream failed: " + detail);
      root.notify(detail, "error");
      root.notifyDesktop("Stream failed", detail);
      root.mediaError = "";
    }
  }

  /// Keep the first thing that looks like a real error; players are chatty.
  function notePlayerLine(line) {
    var text = String(line || "").trim();
    if (text.length === 0) return;
    text = text.replace(/^\[[^\]]*\]\s*/, "");
    var lower = text.toLowerCase();
    var looksLikeError = lower.indexOf("fail") !== -1 || lower.indexOf("error") !== -1
      || lower.indexOf("401") !== -1 || lower.indexOf("unauthor") !== -1
      || lower.indexOf("cannot") !== -1 || lower.indexOf("refus") !== -1
      || lower.indexOf("not found") !== -1 || lower.indexOf("invalid") !== -1;
    // First error wins: players print the root cause first and a generic
    // "Exiting... (Errors when loading file)" last.
    if (looksLikeError && root.mediaError === "") root.mediaError = text;
  }

  // ---- wake-on-lan --------------------------------------------------------
  //
  // The magic packet lives in the backend (netmap wol), which knows the local
  // interface broadcasts. A machine needs a few seconds to boot, so a follow-up
  // round is scheduled instead of waiting for the next hourly scan.
  function wakeHost(action) {
    var argv = Model.argvFor(action, { netmapBin: root.binaryPath });
    if (!argv) {
      var missing = "Cannot wake " + ((action && action.title) ? action.title : "that device")
        + ": no MAC address known (rescan with r, or pin a host that has been seen)";
      root.notify(missing, "warn");
      root.notifyDesktop("Wake-on-LAN", missing);
      return false;
    }
    root.wolOutput = "";
    root.wolError = "";
    root.wolTarget = (action.title && action.title !== "") ? action.title : action.mac;
    root.logAction("wol -> " + action.mac + (action.ip ? " (" + action.ip + ")" : ""));
    root.notify("Waking " + root.wolTarget + "\u2026", "ok");
    wolProcess.command = argv;
    wolProcess.running = true;
    return true;
  }

  Process {
    id: wolProcess
    running: false

    stdout: SplitParser {
      onRead: function (line) {
        if (!root) return;
        var text = String(line || "").trim();
        if (text.length > 0) root.wolOutput = text;
      }
    }
    stderr: SplitParser {
      onRead: function (line) {
        if (!root) return;
        var text = String(line || "").trim();
        if (text.length > 0) root.wolError = text;
      }
    }

    onExited: function (exitCode) {
      // The instance can be destroyed under a running child during a reload.
      if (!root) return;
      if (exitCode !== 0) {
        var reason = root.wolError !== ""
          ? root.wolError
          : "netmap wol exited with code " + exitCode;
        root.logAction("wol failed for " + root.wolTarget + ": " + reason);
        root.notify(reason, "error");
        root.notifyDesktop("Wake-on-LAN failed", reason);
        return;
      }
      var sent = 0;
      try { sent = JSON.parse(root.wolOutput).sent; } catch (error) { sent = 0; }
      root.logAction("wol sent " + sent + " magic packet(s) for " + root.wolTarget
        + "; a fresh round runs in " + Math.round(wakeFollowUp.interval / 1000) + "s");
      root.notify("Sent " + sent + " magic packet(s)", "ok");
      wakeFollowUp.restart();
    }
  }

  // One retry per exit, so a backend that cannot start at all cannot loop.
  Timer {
    id: resumeWatch
    interval: 4000
    onTriggered: {
      if (!root.watching && root.binaryPath !== "" && root.setting("autoScan", true) === true) {
        root.logAction("monitoring restarted after the child was killed");
        root.startWatch();
      }
    }
  }

  Timer {
    id: wakeFollowUp
    interval: 25000
    onTriggered: {
      if (root.watching) {
        root.stopWatch(true);
        root.startWatch();
      } else {
        root.startScan(true);
      }
    }
  }

  function runAction(action) {
    if (!action) return false;
    if (action.kind === "wol") return root.wakeHost(action);
    if (action.kind === "media") return root.playUrl(action);
    var argv = Model.argvFor(action, { player: root.player });
    if (!argv || argv.length === 0) {
      var reason = "Cannot open " + (action.kind ? action.kind : "that")
        + ((action.ip || action.url) ? " for " + (action.ip || action.url) : "");
      root.logAction("refused: " + reason);
      root.notify(reason, "warn");
      root.notifyDesktop("netmap", reason);
      return false;
    }
    if (action.kind === "ssh") {
      // The journal records the exact destination ssh was given, which is the
      // only way to tell afterwards whether ~/.ssh/config or the plugin's
      // sshUser setting decided the user.
      root.logAction("ssh -> " + argv.slice(1).join(" ")
        + (action.user ? " (explicit user)" : " (user from ~/.ssh/config)"));
    }
    Quickshell.execDetached(argv);
    root.notify(action.label ? action.label : argv[0], "ok");
    return true;
  }

  function notifyDesktop(title, body) {
    Quickshell.execDetached([
      "omarchy-notification-send", "--app-name", "netmap",
      "-g", Model.GLYPH.warn, "-u", "normal", "-t", "9000",
      String(title), String(body)
    ]);
  }

  function notifyChange(headline, summary) {
    if (Date.now() - root.lastNotifyAt < 15000) return;
    root.lastNotifyAt = Date.now();
    Quickshell.execDetached([
      "omarchy-notification-send", "--app-name", "netmap",
      "-g", Model.GLYPH.loop, "-u", "normal", "-t", "8000",
      "Network change", headline + " (" + summary + ")"
    ]);
  }

  function notify(text, kind) {
    root.toast = { text: String(text || ""), kind: kind ? kind : "ok" };
    toastTimer.restart();
  }

  Timer {
    id: toastTimer
    interval: 2600
    onTriggered: root.toast = { text: "", kind: "ok" }
  }

  Component.onCompleted: binaryProbe.running = true

  onPluginDirChanged: if (root.binaryPath === "") binaryProbe.running = true
}
