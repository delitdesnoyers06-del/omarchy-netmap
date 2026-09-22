// Pure state and presentation logic for the Network Map plugin.
//
// No Quickshell or Qt imports on purpose: everything here is unit-testable with
// node (tests/model.test.js), and the panel stays a thin rendering layer.

// ---------------------------------------------------------------- glyphs
//
// Material Design Icons from the Nerd Font the omarchy shell renders with.
// Every codepoint below was verified present in JetBrainsMono Nerd Font.
function nf(codepoint) {
  return String.fromCodePoint(codepoint);
}

// Every codepoint below was read out of the font itself (its cmap table plus
// the post-table glyph names) and is pinned by a test: a codepoint that is off
// by even one row renders a completely different icon, which is how a hard
// disk once ended up where "open in browser" should have been.
var GLYPH = {
  // device classes (the backend sends its own glyph; this is the fallback)
  router: nf(0xf1087), // md-router_network
  ap: nf(0xf0003), // md-access_point
  laptop: nf(0xf0322), // md-laptop
  desktop: nf(0xf01c5), // md-desktop_tower
  phone: nf(0xf011c), // md-cellphone
  tablet: nf(0xf04f6), // md-tablet
  printer: nf(0xf042a), // md-printer
  camera: nf(0xf07ae), // md-cctv
  tv: nf(0xf0502), // md-television
  speaker: nf(0xf04c3), // md-speaker
  nas: nf(0xf08f3), // md-nas
  server: nf(0xf048b), // md-server
  iot: nf(0xf061a), // md-chip
  apple: nf(0xf0035), // md-apple
  windows: nf(0xf05b3), // md-microsoft_windows
  linux: nf(0xf033d), // md-linux
  pi: nf(0xf043f), // md-raspberry_pi
  cast: nf(0xf0118), // md-cast
  web: nf(0xf01e7), // md-earth
  ip: nf(0xf0a5f), // md-ip
  unknown: nf(0xf02fc), // md-information
  // chrome
  lan: nf(0xf0317), // md-lan
  refresh: nf(0xf0450), // md-refresh
  loop: nf(0xf006a), // md-autorenew - the discreet watch toggle
  ssh: nf(0xf018d), // md-console
  open: nf(0xf01e7), // md-earth - a planet, not a hard disk
  webapp: nf(0xf03cc), // md-open_in_new
  media: nf(0xf040c), // md-play_circle
  copy: nf(0xf018f), // md-content_copy
  filter: nf(0xf0232), // md-filter
  warn: nf(0xf0026), // md-alert
  magnify: nf(0xf0349), // md-magnify
  check: nf(0xf012c), // md-check
  pause: nf(0xf03e4), // md-pause
  stop: nf(0xf04db), // md-stop
  pin: nf(0xf0403), // md-pin
  wake: nf(0xf0425), // md-power
  offline: nf(0xf0902) // md-power_off
};

// ---------------------------------------------------------------- state

function emptyState() {
  return {
    meta: null,
    hosts: {},
    mdns: [],
    progress: null,
    status: "",
    error: "",
    done: null,
    scanId: 0,
    lastDiff: null,
    lastDiffAt: 0
  };
}

// A round of a continuous watch keeps the map it already has: the backend tells
// us what vanished through a diff instead of making every node disappear and
// come back on each round.
function isNewScan(state, meta) {
  var round = meta && typeof meta.round === "number" ? meta.round : 0;
  return round === 0 || !state.meta;
}

// Apply a diff to the host map: host removals delete records, port removals
// delete the port from the record.
function applyDiff(state, event) {
  var hosts = Object.assign({}, state.hosts);
  var changed = false;
  (event.removed_hosts || []).forEach(function (host) {
    if (hosts[host.ip]) {
      delete hosts[host.ip];
      changed = true;
    }
  });
  (event.removed_ports || []).forEach(function (gone) {
    var record = hosts[gone.ip];
    if (!record || !record.ports) return;
    var kept = record.ports.filter(function (port) { return port.port !== gone.port; });
    if (kept.length !== record.ports.length) {
      var next = Object.assign({}, record);
      next.ports = kept;
      next.open_ports = kept.length;
      hosts[gone.ip] = next;
      changed = true;
    }
  });
  if (!changed) return state;
  var next = Object.assign({}, state);
  next.hosts = hosts;
  return next;
}

// One line describing what a diff changed, for the toast and the notification.
function diffSummary(event) {
  if (!event) return "";
  var parts = [];
  function count(list, singular, plural) {
    if (!list || list.length === 0) return;
    parts.push(list.length + " " + (list.length === 1 ? singular : plural));
  }
  count(event.added_hosts, "new device", "new devices");
  count(event.added_ports, "new port", "new ports");
  count(event.removed_hosts, "device gone", "devices gone");
  count(event.removed_ports, "port closed", "ports closed");
  return parts.join(", ");
}

// What a diff is worth telling the user about in a notification.
function diffHeadline(event) {
  if (!event) return "";
  if (event.added_hosts && event.added_hosts.length > 0) {
    var host = event.added_hosts[0];
    return host.name && host.name !== host.ip
      ? host.name + " (" + host.ip + ")"
      : host.ip;
  }
  if (event.added_ports && event.added_ports.length > 0) {
    var port = event.added_ports[0];
    return port.ip + ":" + port.port + " " + (port.proto || port.service || "");
  }
  return diffSummary(event);
}

function mdnsKey(record) {
  return [record.service_type || "", record.name || "", record.ip || ""].join("|");
}

// Fold one JSON Lines event from the scanner into the panel state. A "meta"
// event starts a new scan, so the previous map is cleared instead of merging
// two scans' worth of stale ports.
function applyEvent(state, event) {
  var next = Object.assign({}, state);
  if (!event || typeof event !== "object") return next;
  switch (event.type) {
    case "meta":
      next.meta = event;
      if (isNewScan(state, event)) {
        next.hosts = {};
        next.mdns = [];
      }
      next.progress = null;
      next.done = null;
      next.error = "";
      next.status = "";
      next.scanId = (state.scanId || 0) + 1;
      break;
    case "host":
      if (!event.ip) break;
      next.hosts = Object.assign({}, state.hosts);
      next.hosts[event.ip] = event;
      break;
    case "mdns": {
      var key = mdnsKey(event);
      var known = false;
      for (var i = 0; i < state.mdns.length; i++) {
        if (mdnsKey(state.mdns[i]) === key) { known = true; break; }
      }
      if (!known) next.mdns = state.mdns.concat([event]);
      break;
    }
    case "progress":
      next.progress = event;
      break;
    case "status":
      next.status = String(event.message || "");
      break;
    case "error":
      next.error = String(event.message || "");
      break;
    case "diff": {
      var folded = applyDiff(state, event);
      Object.keys(folded).forEach(function (key) { next[key] = folded[key]; });
      next.lastDiff = event;
      break;
    }
    case "done":
      next.done = event;
      next.progress = null;
      break;
    default:
      break;
  }
  return next;
}

function ipValue(ip) {
  var parts = String(ip || "").split(".");
  var value = 0;
  for (var i = 0; i < 4; i++) {
    value = value * 256 + (parseInt(parts[i], 10) || 0);
  }
  return value;
}

// Gateway first (it is the hub of the map), then by address.
function orderedHosts(state) {
  var list = [];
  for (var ip in state.hosts) {
    if (Object.prototype.hasOwnProperty.call(state.hosts, ip)) list.push(state.hosts[ip]);
  }
  list.sort(function (a, b) {
    var ga = a.is_gateway ? 0 : 1;
    var gb = b.is_gateway ? 0 : 1;
    if (ga !== gb) return ga - gb;
    return ipValue(a.ip) - ipValue(b.ip);
  });
  return list;
}

var FILTERS = ["all", "pinned", "open"];

function filterLabel(filter) {
  if (filter === "open") return "WITH PORTS";
  if (filter === "pinned") return "PINNED";
  return "ALL";
}

function nextFilter(filter) {
  var index = FILTERS.indexOf(filter);
  return FILTERS[(index + 1) % FILTERS.length];
}

function filterHosts(hosts, filter) {
  var list = asArray(hosts);
  if (filter === "open") return list.filter(function (host) { return host.open_ports > 0; });
  if (filter === "pinned") return list.filter(function (host) { return host.pinned === true; });
  return list;
}

// Gateway first, then pinned machines, then by address: the devices you care
// about stay at the top of the list.
function sortHosts(hosts) {
  return asArray(hosts).slice().sort(function (a, b) {
    var gatewayA = a.is_gateway ? 0 : 1;
    var gatewayB = b.is_gateway ? 0 : 1;
    if (gatewayA !== gatewayB) return gatewayA - gatewayB;
    var pinnedA = a.pinned ? 0 : 1;
    var pinnedB = b.pinned ? 0 : 1;
    if (pinnedA !== pinnedB) return pinnedA - pinnedB;
    return ipValue(a.ip) - ipValue(b.ip);
  });
}

// ------------------------------------------------------- pinned machines
//
// A pin is kept as {mac, ip, name} in the widget's shell.json entry. The MAC is
// what wake-on-LAN needs and what survives a DHCP change; the ip and name let
// the panel keep showing a machine that is switched off - which is exactly the
// moment you want to wake it.

// A list that crossed the QML/JSON boundary - a value read back from
// shell.json, or one handed over by the bar facade - is not a JS Array, but it
// still has a length and indexed members. Treating those as empty is how a
// saved pin list would silently disappear after a shell restart.
function asArray(value) {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  if (typeof value === "object" && typeof value.length === "number") {
    var out = [];
    for (var i = 0; i < value.length; i++) out.push(value[i]);
    return out;
  }
  return [];
}

function asPinList(value) {
  if (typeof value === "string") {
    if (value.trim().length === 0) return [];
    try {
      var parsed = JSON.parse(value);
      return looksLikePin(parsed) ? [parsed] : asArray(parsed);
    } catch (error) {
      return [];
    }
  }
  // A single pin written by hand (or by a command line that flattened a
  // one-element list) is still a pin.
  if (looksLikePin(value)) return [value];
  return asArray(value);
}

function looksLikePin(value) {
  return !!value && typeof value === "object" && !Array.isArray(value)
    && (typeof value.mac === "string" || typeof value.ip === "string");
}

function pinKey(host) {
  if (!host) return "";
  if (host.mac) return String(host.mac).toLowerCase();
  return "ip:" + String(host.ip || "");
}

// A MAC is the identity when both sides have one: matching on the address alone
// would follow a lease that moved to another machine.
function entryMatchesHost(entry, host) {
  if (!entry || !host) return false;
  var mac = host.mac ? String(host.mac).toLowerCase() : "";
  if (mac && entry.mac && String(entry.mac).toLowerCase() === mac) return true;
  if (!mac && entry.ip && entry.ip === host.ip) return true;
  return false;
}

function isPinned(host, pinned) {
  if (!host) return false;
  if (host.pinned === true) return true;
  return asPinList(pinned).some(function (entry) { return entryMatchesHost(entry, host); });
}

function pinEntry(host) {
  return {
    mac: host && host.mac ? String(host.mac).toLowerCase() : "",
    ip: host ? host.ip : "",
    name: hostName(host)
  };
}

function togglePin(host, pinned) {
  var list = asPinList(pinned);
  if (isPinned(host, list)) {
    var key = pinKey(host);
    return list.filter(function (entry) {
      return pinKey({ mac: entry.mac, ip: entry.ip }) !== key;
    });
  }
  return list.concat([pinEntry(host)]);
}

// Add the pinned machines the scan did not see, as offline entries, so a
// switched-off desktop is still on screen with its wake action one keystroke
// away.
function mergePinned(hosts, pinned) {
  var list = asPinList(pinned);
  var hostList = asArray(hosts);
  if (list.length === 0) return hostList;

  // A pinned machine that IS on the network must be flagged too: the flag is
  // what the PINNED filter and the pin glyph in a row look at, and only adding
  // ghosts left every online pinned machine unflagged - so the filter reported
  // "no host matches" while the pins were right there. The scan's objects are
  // not mutated: a copy carries the flag, so nothing downstream is surprised.
  var seen = hostList.map(function (host) {
    var matched = list.some(function (entry) { return entryMatchesHost(entry, host); });
    if (!matched || host.pinned === true) return host;
    var copy = Object.assign({}, host);
    copy.pinned = true;
    return copy;
  });

  list.forEach(function (entry) {
    var found = seen.some(function (host) { return entryMatchesHost(entry, host); });
    if (found) return;
    seen.push({
      ip: entry.ip || "",
      mac: entry.mac ? String(entry.mac).toLowerCase() : "",
      names: entry.name ? [entry.name] : [],
      alive: false,
      open_ports: 0,
      ports: [],
      services: [],
      sources: ["pin"],
      pinned: true,
      offline: true,
      class: {
        key: "pinned",
        label: "Offline",
        glyph: GLYPH.offline,
        confidence: 1,
        evidence: ["pinned"]
      }
    });
  });
  return seen;
}

// Wake-on-LAN needs the MAC, so a pin made from an address alone cannot be
// woken until the machine has been seen once.
function wakeAction(host, options) {
  if (!host || !host.mac) return null;
  return {
    key: "wake",
    glyph: GLYPH.wake,
    label: "Wake " + hostName(host),
    tooltip: "Wake-on-LAN to " + host.mac,
    kind: "wol",
    mac: String(host.mac).toLowerCase(),
    ip: host.ip,
    title: hostName(host),
    // Only pinned machines carry the chip: an online host does not need waking,
    // and every other row should stay quiet.
    chip: isPinned(host, options ? options.pinned : [])
  };
}

// ---------------------------------------------------------------- display

function shorten(text, width) {
  var value = String(text === undefined || text === null ? "" : text);
  if (value.length <= width) return value;
  return value.slice(0, Math.max(0, width - 1)) + "\u2026";
}

function hostName(host) {
  var names = host && host.names ? host.names : [];
  if (names.length > 0) return names[0];
  if (host && host.vendor) return host.vendor;
  return host ? host.ip : "";
}

function hostGlyph(host) {
  if (host && host.class && host.class.glyph) return host.class.glyph;
  return GLYPH.ip;
}

function hostClassLabel(host) {
  if (host && host.class && host.class.label) return host.class.label;
  return host && host.alive ? "Host" : "Unresponsive";
}

// One muted line under the name: address, MAC, class, vendor.
function hostMeta(host) {
  var parts = [host.ip];
  if (host.mac) parts.push(host.mac);
  parts.push(hostClassLabel(host));
  if (host.vendor && host.class && host.class.label !== host.vendor) parts.push(host.vendor);
  if (host.rtt_ms !== undefined && host.rtt_ms !== null) parts.push(host.rtt_ms + "ms");
  return parts.join(" \u00b7 ");
}

function portLabel(port) {
  var proto = port.proto || port.service || "tcp";
  return port.port + " " + proto;
}

// Ports shown as chips on a row, capped so a busy host cannot push the actions
// off the panel.
function portChips(host, limit) {
  var ports = host && host.ports ? host.ports : [];
  var max = limit || 4;
  var chips = ports.slice(0, max).map(portLabel);
  if (ports.length > max) chips.push("+" + (ports.length - max));
  return chips;
}

function describePort(port) {
  var parts = [];
  if (port.product) {
    parts.push(port.version ? port.product + "/" + port.version : port.product);
  } else if (port.banner) {
    parts.push(shorten(port.banner, 52));
  }
  if (port.title) parts.push("\u201c" + shorten(port.title, 40) + "\u201d");
  if (port.note) parts.push(port.note);
  if (port.rtt_ms !== undefined && port.rtt_ms !== null) parts.push(port.rtt_ms + "ms");
  return parts.join(" \u00b7 ");
}

function mdnsRows(state, limit) {
  var max = limit || 6;
  return (state.mdns || []).slice(0, max);
}

// ---------------------------------------------------------------- actions

function sshTarget(host, options) {
  var user = options && options.sshUser ? String(options.sshUser).trim() : "";
  return user ? user + "@" + host.ip : host.ip;
}

// Only ever hand a real web URL to a browser. This is the guard that keeps a
// non-URL (an argv array, a bare port, an adb endpoint) from being turned into
// a file:// URL by the browser launcher.
function isHttpUrl(url) {
  var value = String(url || "").trim().toLowerCase();
  return value.indexOf("http://") === 0 || value.indexOf("https://") === 0;
}

function isMediaUrl(url) {
  var value = String(url || "").trim().toLowerCase();
  return value.indexOf("rtsp://") === 0
    || value.indexOf("rtsps://") === 0
    || value.indexOf("rtmp://") === 0
    || value.indexOf("mms://") === 0;
}

// A copyable string, restricted to what an address can contain so the text can
// never be mistaken for a command line flag.
function isCopyable(text) {
  return /^[A-Za-z0-9._:\-]+$/.test(String(text || ""));
}

// argv for a media player. The player is probed once by the service; the
// fallback hands the URL to xdg-open, which uses whatever is registered.
// A player that fails must be *seen* to fail: force-window makes the window
// appear even when the stream cannot be opened, so the error is on screen
// instead of being a silent exit. Errors go to the player's stderr and to the
// shell journal either way.
function mediaArgv(url, player, title) {
  var label = title ? "netmap: " + title : "netmap";
  if (player === "vlc") return ["vlc", "--meta-title", label, url];
  if (player === "mpv") {
    return ["mpv", "--no-config", "--force-window=yes", "--keep-open=no",
      "--title=" + label, url];
  }
  if (player === "ffplay") {
    return ["ffplay", "-hide_banner", "-loglevel", "warning", "-window_title", label, url];
  }
  // No player found: hand the URL to the system handler for rtsp://.
  return ["gio", "open", url];
}

// The name ssh should be given instead of the address, when we have one that
// actually resolves. Only dotted names qualify: a bare NetBIOS name
// (DESKTOP-ABC) is not resolvable by the resolver, so the address is safer.
function sshNameFor(host) {
  var names = (host && host.names) || [];
  for (var i = 0; i < names.length; i++) {
    if (String(names[i]).indexOf(".") !== -1) return String(names[i]);
  }
  return null;
}

// argv for a terminal that runs ssh. Built here (pure, tested) and handed
// straight to execDetached - there is no shell and no string building.
//
// The user is deliberately left to ssh itself: an explicit user (the plugin's
// sshUser setting, or a per-port override) is prefixed as user@target, and
// otherwise the target is passed bare so ssh applies ~/.ssh/config - a Host
// block, a Host * default, whatever the user configured.
function sshArgvFor(ip, port, user, options) {
  var target = ip;
  if (options && options.sshTarget === "name" && options.sshName) target = options.sshName;
  if (user) target = user + "@" + target;
  var argv = ["omarchy-launch-terminal", "ssh"];
  if (port && port !== 22) argv.push("-p", String(port));
  argv.push(target);
  return argv;
}

// The single place that turns an action into a process. Returns null when the
// action must not be launched as given.
function argvFor(action, options) {
  if (!action) return null;
  var player = options && options.player ? options.player : "";
  if (action.kind === "browser") {
    return isHttpUrl(action.url) ? ["omarchy-launch-browser", action.url] : null;
  }
  if (action.kind === "webapp") {
    return isHttpUrl(action.url) ? ["omarchy-launch-webapp", action.url] : null;
  }
  if (action.kind === "media") {
    if (!isMediaUrl(action.url)) return null;
    return mediaArgv(action.url, player, action.title);
  }
  if (action.kind === "ssh") {
    var user = action.user ? String(action.user).trim() : "";
    return sshArgvFor(action.ip, action.port, user, {
      sshTarget: action.sshTarget,
      sshName: action.sshName
    });
  }
  if (action.kind === "copy") {
    return isCopyable(action.text) ? ["wl-copy", action.text] : null;
  }
  if (action.kind === "wol") {
    if (!isMac(action.mac)) return null;
    var binary = options && options.netmapBin ? String(options.netmapBin) : "netmap";
    var argv = [binary, "wol", String(action.mac).toLowerCase(), "--json"];
    if (action.ip) argv.push("--ip", String(action.ip));
    return argv;
  }
  return null;
}

/// MAC in the shapes the backend accepts (and nothing else).
function isMac(value) {
  var text = String(value || "").toLowerCase();
  return /^(([0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{12})$/.test(text);
}

// argv for launching a terminal that runs ssh. No shell, no string building:
// the panel hands this straight to execDetached.
function sshArgv(host, options) {
  var user = options && options.sshUser ? String(options.sshUser).trim() : "";
  return sshArgvFor(host.ip, host.ssh_port, user, {
    sshTarget: options ? options.sshTarget : "ip",
    sshName: sshNameFor(host)
  });
}

// What ssh will actually be asked to do, for a tooltip or a debug dump:
// "ssh admin@truenas.local" / "ssh -p 2222 192.168.1.42".
function sshCommandPreview(host, options) {
  if (!host || !host.ssh_port) return "";
  return sshArgv(host, options).slice(1).join(" ");
}

// The action the play chip and the media key run for a host.
function mediaAction(host, options) {
  return actionFor(host, options, ["play"]);
}

// The host's main web UI, and only a real http(s) one: an rtsp stream is not
// something to hand to a browser.
function primaryUrl(host) {
  var url = host && host.web_url ? String(host.web_url) : "";
  return isHttpUrl(url) ? url : null;
}

// The port to stream from, when the host serves one.
function mediaPort(host) {
  var ports = (host && host.ports) || [];
  for (var i = 0; i < ports.length; i++) {
    if (ports[i].url && isMediaUrl(ports[i].url)) return ports[i];
  }
  for (var j = 0; j < ports.length; j++) {
    var port = ports[j];
    if (port.proto === "rtsp" || port.service === "rtsp" || port.service === "rtsp-alt") {
      return port;
    }
  }
  return null;
}

// user[:password]@ part of a stream URL, from the plugin settings.
function streamAuthority(ip, options) {
  var user = options && options.rtspUser ? String(options.rtspUser).trim() : "";
  var password = options && options.rtspPassword ? String(options.rtspPassword) : "";
  if (!user) return ip;
  return password ? user + ":" + password + "@" + ip : user + "@" + ip;
}

// Cameras almost always want credentials (a bare OPTIONS answers 401) and a
// vendor-specific path, so the URL is rebuilt from the settings rather than
// handed over exactly as the probe saw it: a URL the camera refused is not a
// URL worth opening.
function mediaUrl(host, options) {
  var port = mediaPort(host);
  if (!port) return null;
  var base = "rtsp://" + streamAuthority(host.ip, options) + ":" + port.port;
  var reported = port.url && isMediaUrl(port.url)
    ? String(port.url).replace(/^rtsps?:\/\/[^/]*/, "")
    : "";
  if (reported && reported.length > 1 && reported !== "/") return base + reported;
  var configured = options && options.rtspPath ? String(options.rtspPath).trim() : "";
  if (configured.length === 0) return base + "/";
  return base + (configured.charAt(0) === "/" ? configured : "/" + configured);
}

// True when the camera already told us it wants credentials. Used to explain
// the failure before the user wonders why the player opened nothing.
function mediaNeedsAuth(host) {
  var port = mediaPort(host);
  if (!port) return false;
  var text = ((port.banner || "") + " " + (port.note || "") + " " + (port.title || "")).toLowerCase();
  return text.indexOf("401") !== -1 || text.indexOf("unauthorized") !== -1
    || text.indexOf("authentication") !== -1;
}

// Chips are rendered in this order and the first one is the primary action,
// so the browser comes before ssh: a device with a web UI is opened, not
// logged into.
// Actions carry plain scalars only - never an array. An array handed to a
// QML consumer arrives as an opaque sequence, and treating it as a string is
// exactly how an ssh command once reached the browser launcher. The service
// rebuilds the argv from these fields (see argvFor).
function actionsFor(host, options) {
  var actions = [];
  var user = options && options.sshUser ? String(options.sshUser).trim() : "";
  var url = primaryUrl(host);
  var sshPort = host && host.ssh_port ? host.ssh_port : 0;
  if (url) {
    actions.push({
      key: "open",
      glyph: GLYPH.open,
      label: "Open " + url,
      tooltip: "Open the web UI",
      kind: "browser",
      url: url,
      chip: true
    });
    actions.push({
      key: "webapp",
      glyph: GLYPH.webapp,
      label: "Open " + url + " as a web app",
      tooltip: "Open as a web app",
      kind: "webapp",
      url: url,
      chip: false
    });
  }
  var stream = mediaUrl(host, options);
  if (stream) {
    var needsAuth = mediaNeedsAuth(host);
    actions.push({
      key: "play",
      glyph: GLYPH.media,
      label: "Play " + stream,
      tooltip: needsAuth
        ? "Play the stream (the camera asked for credentials: set rtspUser and rtspPassword)"
        : "Play the stream in a media player",
      kind: "media",
      url: stream,
      title: host.ip,
      needsAuth: needsAuth,
      chip: true
    });
  }
  if (sshPort) {
    actions.push({
      key: "ssh",
      glyph: GLYPH.ssh,
      label: "SSH to " + sshTarget(host, options),
      tooltip: sshPort === 22 ? "SSH in a terminal" : "SSH on port " + sshPort,
      kind: "ssh",
      ip: host.ip,
      port: sshPort,
      user: user,
      sshTarget: options ? options.sshTarget : "ip",
      sshName: sshNameFor(host),
      chip: true
    });
  }
  var wake = wakeAction(host, options);
  if (wake) actions.push(wake);
  actions.push({
    key: "copy",
    glyph: GLYPH.copy,
    label: "Copy " + host.ip,
    tooltip: "Copy the address",
    kind: "copy",
    text: host.ip,
    chip: false
  });
  return actions;
}

// The action a single identified port supports: its reported URL, or ssh when
// that is what is listening there (possibly on a non-standard port).
function portAction(host, port, options) {
  if (!host || !port) return null;
  if (port.url && isMediaUrl(port.url)) {
    return {
      key: "play",
      glyph: GLYPH.media,
      label: "Play " + port.url,
      tooltip: "Open the stream in a media player",
      kind: "media",
      url: port.url,
      chip: false
    };
  }
  if (port.url && isHttpUrl(port.url)) {
    return {
      key: "open",
      glyph: GLYPH.open,
      label: "Open " + port.url,
      tooltip: "Open the web UI",
      kind: "browser",
      url: port.url,
      chip: false
    };
  }
  var isSsh = port.proto === "ssh" || port.service === "ssh"
    || port.service === "ssh-alt" || port.port === 22;
  if (isSsh) {
    var user = options && options.sshUser ? String(options.sshUser).trim() : "";
    var target = user ? user + "@" + host.ip : host.ip;
    return {
      key: "ssh",
      glyph: GLYPH.ssh,
      label: "SSH to " + target + " port " + port.port,
      tooltip: "SSH on port " + port.port,
      kind: "ssh",
      ip: host.ip,
      port: port.port,
      user: user,
      sshTarget: options ? options.sshTarget : "ip",
      sshName: sshNameFor(host),
      chip: false
    };
  }
  // A camera advertising RTSP without answering still deserves a player.
  if (port.proto === "rtsp" || port.service === "rtsp" || port.service === "rtsp-alt") {
    var stream = "rtsp://" + host.ip + ":" + port.port + "/";
    return {
      key: "play",
      glyph: GLYPH.media,
      label: "Play " + stream,
      tooltip: "Open the stream in a media player",
      kind: "media",
      url: stream,
      chip: false
    };
  }
  return null;
}

// Keys are a preference list: actionFor(host, options, ["webapp", "open"])
// returns the web app action when the host supports it, and only falls back to
// the plain browser otherwise.
function actionFor(host, options, keys) {
  var actions = actionsFor(host, options);
  for (var index = 0; index < keys.length; index++) {
    for (var i = 0; i < actions.length; i++) {
      if (actions[i].key === keys[index]) return actions[i];
    }
  }
  return null;
}

// What Enter and a plain click do: open the browser when the host serves a web
// UI, otherwise ssh in when it accepts ssh, otherwise copy the address.
// Waking is the primary action for a pinned machine that is off, because it is
// the only thing that can be done with it.
function primaryAction(host, options) {
  if (!host) return null;
  return actionFor(host, options, ["open", "play", "ssh", "wake", "copy"]);
}

function chipActions(host, options) {
  return actionsFor(host, options).filter(function (action) { return action.chip; });
}

// ---------------------------------------------------------------- progress

function progressInfo(progress) {
  if (!progress) return null;
  var total = progress.total || 0;
  var done = progress.done || 0;
  var percent = total > 0 ? Math.min(100, (done / total) * 100) : 0;
  return {
    percent: percent,
    done: done,
    total: total,
    alive: progress.alive || 0,
    openPorts: progress.open_ports || 0,
    text: Math.round(percent) + "% of " + total + " probes \u00b7 " + (progress.alive || 0) + " hosts \u00b7 " + (progress.open_ports || 0) + " open"
  };
}

function formatAge(milliseconds) {
  var seconds = Math.max(0, Math.round(milliseconds / 1000));
  if (seconds < 3) return "just now";
  if (seconds < 60) return seconds + "s ago";
  var minutes = Math.round(seconds / 60);
  if (minutes < 60) return minutes + "m ago";
  return Math.round(minutes / 60) + "h ago";
}

function summarize(state) {
  var hosts = orderedHosts(state);
  var alive = 0;
  var openPorts = 0;
  for (var i = 0; i < hosts.length; i++) {
    if (hosts[i].alive) alive++;
    openPorts += hosts[i].open_ports || 0;
  }
  return {
    hosts: hosts.length,
    alive: alive,
    openPorts: openPorts,
    services: (state.mdns || []).length
  };
}

// The hero subtitle, and the "what is happening right now" line.
function statusLine(state, nowMs, scanning) {
  var counts = summarize(state);
  if (state.error) return state.error;
  if (scanning) {
    var progress = progressInfo(state.progress);
    if (progress) return progress.text;
    return state.status || "scanning\u2026";
  }
  var parts = [];
  parts.push(counts.hosts + " host" + (counts.hosts === 1 ? "" : "s"));
  if (counts.openPorts > 0) parts.push(counts.openPorts + " ports");
  if (counts.services > 0) parts.push(counts.services + " mdns");
  if (state.meta && state.meta.interfaces && state.meta.interfaces.length > 0) {
    var iface = state.meta.interfaces[0];
    parts.push(iface.name + " " + iface.network);
  }
  if (state.finishedAt && nowMs) parts.push("updated " + formatAge(nowMs - state.finishedAt));
  return parts.join(" \u00b7 ");
}

// ---------------------------------------------------------------- map layout

// Gateway in the middle, everything else on one ring, or two when it is busy.
// Coordinates are in the given box so QML only has to place items.
function layoutMap(hosts, width, height) {
  var gateway = null;
  var others = [];
  for (var i = 0; i < hosts.length; i++) {
    var host = hosts[i];
    if (host.is_gateway && !gateway) gateway = host;
    else if (!host.is_self) others.push(host);
  }
  var cx = width / 2;
  var cy = height / 2;
  var nodes = [];
  var ringCount = others.length > 9 ? 2 : 1;
  var perRing = Math.ceil(others.length / ringCount);
  if (perRing < 1) perRing = 1;
  for (var index = 0; index < others.length; index++) {
    var host = others[index];
    var ring = Math.floor(index / perRing);
    var inRing = index % perRing;
    var inThisRing = Math.min(perRing, others.length - ring * perRing);
    var angle = -Math.PI / 2 + ((inRing + 0.5) * (2 * Math.PI)) / Math.max(1, inThisRing);
    if (ring === 1) angle += Math.PI / Math.max(1, inThisRing);
    var scale = ring === 0 ? 1 : 0.6;
    var radiusX = width * 0.40 * scale;
    var radiusY = height * 0.40 * scale;
    var openPorts = host.open_ports || 0;
    nodes.push({
      host: host,
      ip: host.ip,
      x: cx + Math.cos(angle) * radiusX,
      y: cy + Math.sin(angle) * radiusY,
      r: 9 + Math.min(5, openPorts) * 1.6
    });
  }
  return {
    gateway: gateway
      ? { host: gateway, ip: gateway.ip, x: cx, y: cy, r: 15 }
      : null,
    nodes: nodes,
    centerX: cx,
    centerY: cy
  };
}

// Keep the keyboard cursor on the same device while hosts come and go.
function indexOfIp(hosts, ip) {
  for (var i = 0; i < hosts.length; i++) {
    if (hosts[i].ip === ip) return i;
  }
  return -1;
}

function mdnsLabel(record) {
  var type = String(record.service_type || "").replace(/^_/, "").replace(/\.local\.$/, "").replace(/\._/g, " / ");
  return record.name ? record.name + " \u00b7 " + type : type;
}

// Only the web service types get a browser URL, and only the rtsp type gets a
// stream. Everything else (adb, sftp, kdeconnect, matter) is not clickable:
// those ports are not web servers and opening a browser at them is noise.
function mdnsUrl(record) {
  if (!record.ip || !record.port) return null;
  var type = String(record.service_type || "");
  if (type.indexOf("_https._tcp") !== -1) return "https://" + record.ip + ":" + record.port + "/";
  if (type.indexOf("_http._tcp") !== -1) return "http://" + record.ip + ":" + record.port + "/";
  return null;
}

// The action an advertised service supports, or null when it supports none.
function mdnsAction(record) {
  var url = mdnsUrl(record);
  if (url) return { kind: "browser", url: url, glyph: GLYPH.open, tooltip: "Open " + url };
  if (!record.ip || !record.port) return null;
  if (String(record.service_type || "").indexOf("_rtsp._tcp") !== -1) {
    var stream = "rtsp://" + record.ip + ":" + record.port + "/";
    return { kind: "media", url: stream, glyph: GLYPH.media, tooltip: "Play " + stream };
  }
  return null;
}

if (typeof module !== "undefined") {
  module.exports = {
    GLYPH: GLYPH,
    FILTERS: FILTERS,
    emptyState: emptyState,
    applyEvent: applyEvent,
    orderedHosts: orderedHosts,
    filterHosts: filterHosts,
    sortHosts: sortHosts,
    asArray: asArray,
    asPinList: asPinList,
    pinKey: pinKey,
    isPinned: isPinned,
    pinEntry: pinEntry,
    togglePin: togglePin,
    mergePinned: mergePinned,
    wakeAction: wakeAction,
    entryMatchesHost: entryMatchesHost,
    isMac: isMac,
    nextFilter: nextFilter,
    filterLabel: filterLabel,
    ipValue: ipValue,
    shorten: shorten,
    hostName: hostName,
    hostGlyph: hostGlyph,
    hostClassLabel: hostClassLabel,
    hostMeta: hostMeta,
    portLabel: portLabel,
    portChips: portChips,
    describePort: describePort,
    mdnsRows: mdnsRows,
    sshTarget: sshTarget,
    sshArgv: sshArgv,
    sshNameFor: sshNameFor,
    sshCommandPreview: sshCommandPreview,
    primaryUrl: primaryUrl,
    mediaUrl: mediaUrl,
    mediaPort: mediaPort,
    mediaAction: mediaAction,
    mediaNeedsAuth: mediaNeedsAuth,
    streamAuthority: streamAuthority,
    isHttpUrl: isHttpUrl,
    isMediaUrl: isMediaUrl,
    isCopyable: isCopyable,
    mediaArgv: mediaArgv,
    argvFor: argvFor,
    isNewScan: isNewScan,
    applyDiff: applyDiff,
    diffSummary: diffSummary,
    diffHeadline: diffHeadline,
    actionsFor: actionsFor,
    actionFor: actionFor,
    primaryAction: primaryAction,
    portAction: portAction,
    sshArgvFor: sshArgvFor,
    chipActions: chipActions,
    progressInfo: progressInfo,
    formatAge: formatAge,
    summarize: summarize,
    statusLine: statusLine,
    layoutMap: layoutMap,
    indexOfIp: indexOfIp,
    mdnsLabel: mdnsLabel,
    mdnsUrl: mdnsUrl,
    mdnsAction: mdnsAction
  };
}
