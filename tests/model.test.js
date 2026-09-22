// Run with: node tests/model.test.js
//
// Plain node asserts, no framework - the same convention the omarchy shell
// plugins use. Everything here is pure logic from Model.js.
var assert = require("assert");
var M = require("../Model.js");

// ---------------------------------------------------------------- glyphs
//
// Nerd Font glyphs live above the BMP, and a codepoint that is off by one row
// renders a completely different icon (a hard disk where "open in browser"
// should be). These pin the codepoints verified against the font itself.
var expected = {
  lan: 0xf0317, router: 0xf1087, laptop: 0xf0322, desktop: 0xf01c5, phone: 0xf011c,
  printer: 0xf042a, camera: 0xf07ae, tv: 0xf0502, speaker: 0xf04c3, nas: 0xf08f3,
  server: 0xf048b, iot: 0xf061a, apple: 0xf0035, windows: 0xf05b3, linux: 0xf033d,
  pi: 0xf043f, cast: 0xf0118, web: 0xf01e7, ip: 0xf0a5f, unknown: 0xf02fc,
  refresh: 0xf0450, loop: 0xf006a, ssh: 0xf018d, open: 0xf01e7, webapp: 0xf03cc,
  media: 0xf040c, copy: 0xf018f, filter: 0xf0232, warn: 0xf0026, magnify: 0xf0349,
  check: 0xf012c, pause: 0xf03e4, stop: 0xf04db
};
Object.keys(expected).forEach(function (name) {
  var glyph = M.GLYPH[name];
  assert.ok(glyph, name + " is defined");
  assert.strictEqual(glyph.length, 2, name + " must be one non-BMP glyph (surrogate pair)");
  assert.strictEqual(glyph.codePointAt(0), expected[name],
    name + " must be U+" + expected[name].toString(16).toUpperCase());
  assert.strictEqual(glyph, String.fromCodePoint(expected[name]));
});
// The browser chip is a planet, the ssh chip is a terminal console.
assert.strictEqual(M.GLYPH.open, M.GLYPH.web, "the web action is the globe/planet glyph");
assert.notStrictEqual(M.GLYPH.open, String.fromCodePoint(0xf02ca), "0xF02CA is a hard disk");

// ---------------------------------------------------------------- state

var state = M.emptyState();
assert.deepStrictEqual(state.hosts, {});
assert.deepStrictEqual(state.mdns, []);

state = M.applyEvent(state, { type: "meta", targets: 253, ports: 158, round: 0 });
assert.strictEqual(state.meta.targets, 253);
assert.strictEqual(state.scanId, 1);

state = M.applyEvent(state, { type: "host", ip: "192.168.1.20", alive: true, open_ports: 2, ports: [{ port: 80, proto: "http" }] });
assert.strictEqual(state.hosts["192.168.1.20"].open_ports, 2);

state = M.applyEvent(state, { type: "host", ip: "192.168.1.20", alive: true, open_ports: 3, ports: [] });
assert.strictEqual(Object.keys(state.hosts).length, 1, "upsert replaces, it does not duplicate");
assert.strictEqual(state.hosts["192.168.1.20"].open_ports, 3);

state = M.applyEvent(state, { type: "progress", done: 50, total: 100 });
assert.strictEqual(state.progress.done, 50);
state = M.applyEvent(state, { type: "done", hosts: 3, elapsed_ms: 4200 });
assert.strictEqual(state.done.hosts, 3);
assert.strictEqual(state.progress, null, "done clears the progress line");

state = M.applyEvent(state, { type: "mdns", service_type: "_http._tcp.local.", name: "Web", ip: "192.168.1.20", port: 80 });
state = M.applyEvent(state, { type: "mdns", service_type: "_http._tcp.local.", name: "Web", ip: "192.168.1.20", port: 80 });
state = M.applyEvent(state, { type: "mdns", service_type: "_http._tcp.local.", name: "Web", ip: "192.168.1.21", port: 80 });
assert.strictEqual(state.mdns.length, 2, "mdns records are deduplicated");

[null, undefined, 42, "nonsense", [], {}].forEach(function (bad) {
  var before = JSON.stringify(state);
  assert.strictEqual(JSON.stringify(M.applyEvent(state, bad)), before, "ignored: " + JSON.stringify(bad));
});

// ------------------------------------------------- continuous watch rounds

// Round 0 starts a fresh map.
var watch = M.applyEvent(M.emptyState(), { type: "meta", round: 0, targets: 4, ports: 2 });
watch = M.applyEvent(watch, { type: "host", ip: "10.0.0.1", alive: true, open_ports: 1, ports: [{ port: 22, proto: "ssh" }] });
watch = M.applyEvent(watch, { type: "host", ip: "10.0.0.2", alive: true, open_ports: 1, ports: [{ port: 80, proto: "http" }] });
assert.strictEqual(Object.keys(watch.hosts).length, 2);

// Round 1 must NOT wipe the map: nodes stay put and vanish only when the diff
// says so. This is what keeps the panel from flashing every 60 seconds.
var round1 = M.applyEvent(watch, { type: "meta", round: 1, targets: 4, ports: 2 });
assert.strictEqual(Object.keys(round1.hosts).length, 2, "a new round keeps the existing map");
assert.strictEqual(M.isNewScan(watch, { round: 1 }), false);
assert.strictEqual(M.isNewScan(watch, { round: 0 }), true);

var withDiff = M.applyEvent(round1, {
  type: "diff",
  removed_hosts: [{ ip: "10.0.0.2", name: "lamp", class: "IoT device", open_ports: 1 }],
  added_hosts: [{ ip: "10.0.0.9", name: "phone", class: "Android device", open_ports: 2 }],
  removed_ports: [{ ip: "10.0.0.1", port: 22, proto: "ssh", service: "ssh" }]
});
assert.strictEqual(withDiff.hosts["10.0.0.2"], undefined, "a removed host leaves the map");
assert.strictEqual(withDiff.hosts["10.0.0.1"].ports.length, 0, "a closed port leaves the record");
assert.strictEqual(withDiff.hosts["10.0.0.1"].open_ports, 0);
assert.ok(withDiff.lastDiff, "the last diff is kept for the toast");
// A diff that changes nothing returns the same state object.
assert.strictEqual(M.applyDiff(round1, { removed_hosts: [], removed_ports: [] }), round1);

assert.strictEqual(M.diffSummary({ added_hosts: [{}], added_ports: [{}, {}] }), "1 new device, 2 new ports");
assert.strictEqual(M.diffSummary({}), "");
assert.strictEqual(M.diffHeadline({ added_hosts: [{ ip: "10.0.0.9", name: "phone" }] }), "phone (10.0.0.9)");
assert.strictEqual(M.diffHeadline({ added_hosts: [{ ip: "10.0.0.9", name: "10.0.0.9" }] }), "10.0.0.9");
assert.strictEqual(M.diffHeadline({ added_ports: [{ ip: "10.0.0.1", port: 445, proto: "smb" }] }), "10.0.0.1:445 smb");

// ---------------------------------------------------------------- ordering

var hosts = [
  { ip: "192.168.1.10", is_gateway: false, alive: true, open_ports: 0 },
  { ip: "192.168.1.2", is_gateway: false, alive: true, open_ports: 2 },
  { ip: "192.168.1.1", is_gateway: true, alive: true, open_ports: 1 },
  { ip: "192.168.1.9", is_gateway: false, alive: false, open_ports: 0 }
];
var ordered = M.orderedHosts({ hosts: { "192.168.1.10": hosts[0], "192.168.1.2": hosts[1], "192.168.1.1": hosts[2], "192.168.1.9": hosts[3] } });
assert.deepStrictEqual(ordered.map(function (h) { return h.ip; }),
  ["192.168.1.1", "192.168.1.2", "192.168.1.9", "192.168.1.10"],
  "gateway first, then numerically ordered - not string ordered");
assert.ok(M.ipValue("192.168.1.10") > M.ipValue("192.168.1.9"));

// ---------------------------------------------------------------- filters

assert.strictEqual(M.filterHosts(hosts, "all").length, 4);
assert.strictEqual(M.filterHosts(hosts, "open").length, 2);
assert.strictEqual(M.nextFilter("all"), "pinned");
assert.strictEqual(M.nextFilter("pinned"), "open");
assert.strictEqual(M.nextFilter("open"), "all", "the filter cycle stays closed");
assert.strictEqual(M.filterLabel("open"), "WITH PORTS");

// ---------------------------------------------------------------- actions

var web = { ip: "192.168.1.50", web_url: "http://192.168.1.50/", ssh_port: 22, ports: [], names: ["router.local"] };
var primary = M.primaryAction(web, {});
assert.strictEqual(primary.kind, "browser", "a web UI wins over ssh");
assert.strictEqual(primary.url, "http://192.168.1.50/");
assert.deepStrictEqual(M.argvFor(primary, {}), ["omarchy-launch-browser", "http://192.168.1.50/"]);
// Actions carry scalars only: an array crossing into QML arrives opaque, and
// stringifying it is what once sent "ssh,..." to the browser launcher.
Object.keys(primary).forEach(function (key) {
  assert.ok(typeof primary[key] !== "object" || primary[key] === null, "action field " + key + " must be a scalar");
});

var sshOnly = { ip: "192.168.1.60", ssh_port: 2222, ports: [] };
var sshAction = M.primaryAction(sshOnly, { sshUser: "pi" });
assert.strictEqual(sshAction.kind, "ssh");
assert.strictEqual(sshAction.ip, "192.168.1.60");
assert.strictEqual(sshAction.port, 2222);
assert.strictEqual(sshAction.user, "pi");
assert.deepStrictEqual(M.argvFor(sshAction, {}), ["omarchy-launch-terminal", "ssh", "-p", "2222", "pi@192.168.1.60"]);

var plain = { ip: "192.168.1.61", ports: [] };
assert.strictEqual(M.primaryAction(plain, {}).kind, "copy", "falls back to copying the address");
assert.deepStrictEqual(M.argvFor(M.primaryAction(plain, {}), {}), ["wl-copy", "192.168.1.61"]);

assert.deepStrictEqual(M.sshArgv({ ip: "192.168.1.5" }, {}), ["omarchy-launch-terminal", "ssh", "192.168.1.5"]);
assert.deepStrictEqual(M.sshArgv({ ip: "192.168.1.5", ssh_port: 22 }, { sshUser: "root" }),
  ["omarchy-launch-terminal", "ssh", "root@192.168.1.5"]);
assert.deepStrictEqual(M.sshArgv({ ip: "192.168.1.5", ssh_port: 2200 }, {}),
  ["omarchy-launch-terminal", "ssh", "-p", "2200", "192.168.1.5"]);

// ------------------------------------------------- browsers only get URLs

assert.strictEqual(M.isHttpUrl("http://a/"), true);
assert.strictEqual(M.isHttpUrl("https://a/"), true);
assert.strictEqual(M.isHttpUrl("rtsp://a/"), false);
assert.strictEqual(M.isHttpUrl("omarchy-launch-terminal,ssh,192.168.1.42"), false);
assert.strictEqual(M.isHttpUrl(""), false);
// The bug that started this: a non-URL must never reach the browser launcher.
assert.strictEqual(M.argvFor({ kind: "browser", url: "omarchy-launch-terminal,ssh,192.168.1.42" }, {}), null);
assert.strictEqual(M.argvFor({ kind: "webapp", url: "file:///etc/passwd" }, {}), null);
assert.strictEqual(M.argvFor({ kind: "copy", text: "-rf /" }, {}), null, "flags are not copyable");
assert.strictEqual(M.argvFor(null, {}), null);
assert.strictEqual(M.argvFor({ kind: "unknown", arg: "x" }, {}), null);

// ------------------------------------------------- media players

assert.strictEqual(M.isMediaUrl("rtsp://10.0.0.9:554/"), true);
assert.strictEqual(M.isMediaUrl("http://10.0.0.9/"), false);
var stream = { ip: "10.0.0.9", ports: [{ port: 554, proto: "rtsp", service: "rtsp", state: "open" }] };
assert.strictEqual(M.mediaUrl(stream), "rtsp://10.0.0.9:554/");
assert.strictEqual(M.primaryAction(stream, {}).kind, "media", "a camera plays, it does not browse");
assert.deepStrictEqual(M.argvFor(M.primaryAction(stream, {}), { player: "vlc" }),
  ["vlc", "--meta-title", "netmap: 10.0.0.9", "rtsp://10.0.0.9:554/"]);
assert.deepStrictEqual(M.argvFor({ kind: "media", url: "rtsp://10.0.0.9:554/" }, { player: "mpv" }),
  ["mpv", "--no-config", "--force-window=yes", "--keep-open=no", "--title=netmap",
   "rtsp://10.0.0.9:554/"]);
assert.deepStrictEqual(M.argvFor({ kind: "media", url: "rtsp://10.0.0.9:554/" }, { player: "" }),
  ["gio", "open", "rtsp://10.0.0.9:554/"], "no player found falls back to the scheme handler");
assert.strictEqual(M.argvFor({ kind: "media", url: "http://10.0.0.9/" }, {}), null);
// A probe URL that is a stream must not be treated as a web UI.
var camera = { ip: "10.0.0.9", web_url: "rtsp://10.0.0.9:554/", ports: [{ port: 554, proto: "rtsp", url: "rtsp://10.0.0.9:554/" }] };
assert.strictEqual(M.primaryUrl(camera), null);
assert.strictEqual(M.primaryAction(camera, {}).kind, "media");

var sshPort = { port: 2222, proto: "ssh", service: "ssh-alt" };
assert.deepStrictEqual(M.argvFor(M.portAction({ ip: "10.0.0.4" }, sshPort, {}), {}),
  ["omarchy-launch-terminal", "ssh", "-p", "2222", "10.0.0.4"]);
var httpPort = { port: 8080, proto: "http", service: "http", url: "http://10.0.0.4:8080/" };
assert.strictEqual(M.portAction({ ip: "10.0.0.4" }, httpPort, {}).kind, "browser");
// adb, sftp, kdeconnect: no action at all, so nothing can be launched by mistake.
assert.strictEqual(M.portAction({ ip: "10.0.0.4" }, { port: 445, proto: "microsoft-ds" }, {}), null);
assert.strictEqual(M.portAction({ ip: "10.0.0.4" }, { port: 38471, proto: "adb-tls-connect" }, {}), null);
assert.strictEqual(M.portAction({ ip: "10.0.0.4" }, { port: 53601, proto: "FC9F5ED42C8A" }, {}), null);

var chips = M.chipActions({ ip: "10.0.0.4", ssh_port: 22, web_url: "http://10.0.0.4/", ports: [] }, {});
assert.deepStrictEqual(chips.map(function (action) { return action.key; }), ["open", "ssh"]);
assert.strictEqual(M.actionFor(web, {}, ["webapp", "open"]).key, "webapp");
assert.strictEqual(M.actionFor(web, {}, ["ssh", "open"]).key, "ssh");

// ---------------------------------------------------------------- mDNS rows

assert.strictEqual(M.mdnsUrl({ ip: "10.0.0.5", port: 80, service_type: "_http._tcp.local." }), "http://10.0.0.5:80/");
assert.strictEqual(M.mdnsUrl({ ip: "10.0.0.5", port: 443, service_type: "_https._tcp.local." }), "https://10.0.0.5:443/");
assert.strictEqual(M.mdnsUrl({ ip: "10.0.0.5", port: 1716, service_type: "_kdeconnect._udp.local." }), null);
assert.strictEqual(M.mdnsUrl({ ip: "10.0.0.5", port: 38471, service_type: "_adb-tls-connect._tcp.local." }), null,
  "adb is not a web service");
assert.strictEqual(M.mdnsAction({ ip: "10.0.0.5", port: 38471, service_type: "_adb-tls-connect._tcp.local." }), null);
assert.strictEqual(M.mdnsAction({ ip: "10.0.0.5", port: 554, service_type: "_rtsp._tcp.local." }).kind, "media");
assert.strictEqual(M.mdnsAction({ ip: "10.0.0.5", port: 80, service_type: "_http._tcp.local." }).kind, "browser");
assert.ok(M.mdnsLabel({ name: "Valetudo", service_type: "_http._tcp.local." }).indexOf("Valetudo") === 0);

// ---------------------------------------------------------------- display

assert.strictEqual(M.hostName({ ip: "10.0.0.1", names: ["nas.local", "NAS"] }), "nas.local");
assert.strictEqual(M.hostName({ ip: "10.0.0.1", names: [], vendor: "Apple" }), "Apple");
assert.strictEqual(M.hostName({ ip: "10.0.0.1" }), "10.0.0.1");
assert.ok(M.hostMeta({ ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff", class: { label: "NAS" }, rtt_ms: 1.5 })
  .indexOf("aa:bb:cc:dd:ee:ff") !== -1);
assert.strictEqual(M.hostGlyph({ ip: "x", class: { glyph: "Q" } }), "Q");
assert.strictEqual(M.hostGlyph({ ip: "x" }), M.GLYPH.ip);
assert.strictEqual(M.portLabel({ port: 80, proto: "http" }), "80 http");
assert.deepStrictEqual(M.portChips({ ip: "x", ports: [{ port: 22, proto: "ssh" }, { port: 80, proto: "http" }, { port: 443, proto: "https" }] }, 2),
  ["22 ssh", "80 http", "+1"]);
assert.ok(M.describePort({ port: 80, service: "http", product: "nginx", version: "1.24.0", title: "Router admin" })
  .indexOf("nginx/1.24.0") !== -1);
assert.strictEqual(M.shorten("abcdefgh", 5), "abcd\u2026");
assert.strictEqual(M.shorten("abc", 5), "abc");

// ---------------------------------------------------------------- progress

assert.strictEqual(M.progressInfo(null), null);
var progress = M.progressInfo({ done: 25, total: 100, alive: 4, open_ports: 3 });
assert.strictEqual(progress.percent, 25);
assert.ok(progress.text.indexOf("25%") === 0);
assert.strictEqual(M.progressInfo({ done: 100, total: 0 }).percent, 0, "no divide by zero");

assert.strictEqual(M.formatAge(500), "just now");
assert.strictEqual(M.formatAge(30000), "30s ago");
assert.strictEqual(M.formatAge(600000), "10m ago");
assert.strictEqual(M.formatAge(7200000), "2h ago");

// ---------------------------------------------------------------- summary

var summary = M.summarize({
  hosts: {
    "10.0.0.1": { ip: "10.0.0.1", alive: true, open_ports: 2, is_gateway: true },
    "10.0.0.2": { ip: "10.0.0.2", alive: false, open_ports: 0 }
  },
  mdns: [{}]
});
assert.deepStrictEqual(summary, { hosts: 2, alive: 1, openPorts: 2, services: 1 });
assert.ok(M.statusLine({ hosts: {}, mdns: [], meta: null }, Date.now(), false).indexOf("0 hosts") === 0);
assert.ok(M.statusLine({ hosts: {}, mdns: [], error: "boom" }, Date.now(), false) === "boom");

// ---------------------------------------------------------------- layout

var layoutHosts = [];
layoutHosts.push({ ip: "10.0.0.1", is_gateway: true, open_ports: 1, alive: true });
for (var i = 2; i <= 12; i++) {
  layoutHosts.push({ ip: "10.0.0." + i, is_gateway: false, open_ports: i % 3, alive: true });
}
var layout = M.layoutMap(layoutHosts, 400, 200);
assert.strictEqual(layout.gateway.x, 200);
assert.strictEqual(layout.gateway.y, 100);
assert.strictEqual(layout.nodes.length, 11);
layout.nodes.forEach(function (node) {
  assert.ok(node.x >= 0 && node.x <= 400, "node x inside the box: " + node.x);
  assert.ok(node.y >= 0 && node.y <= 200, "node y inside the box: " + node.y);
  assert.ok(node.r >= 9, "node radius floor");
});
var radii = layout.nodes.map(function (node) { return Math.round(Math.hypot(node.x - 200, node.y - 100)); });
assert.ok(Math.max.apply(null, radii) - Math.min.apply(null, radii) > 10, "two rings");
assert.deepStrictEqual(M.layoutMap(layoutHosts, 400, 200), layout, "deterministic");
assert.strictEqual(M.indexOfIp(hosts, "192.168.1.10"), 0);
assert.strictEqual(M.indexOfIp(hosts, "10.9.9.9"), -1);


// ------------------------------------------- media: credentials and players

var camera = {
  ip: "192.168.1.154",
  ports: [{ port: 554, proto: "rtsp", service: "rtsp", url: "rtsp://192.168.1.154:554/",
            banner: "RTSP/1.0 401 Unauthorized", note: "answered in 991ms" }]
};
assert.strictEqual(M.mediaUrl(camera, {}), "rtsp://192.168.1.154:554/");
assert.strictEqual(M.mediaUrl(camera, { rtspUser: "admin" }), "rtsp://admin@192.168.1.154:554/");
assert.strictEqual(M.mediaUrl(camera, { rtspUser: "admin", rtspPassword: "pw" }),
  "rtsp://admin:pw@192.168.1.154:554/");
assert.strictEqual(M.mediaUrl(camera, { rtspPath: "cam/realmonitor?channel=1&subtype=0" }),
  "rtsp://192.168.1.154:554/cam/realmonitor?channel=1&subtype=0", "a path without a leading slash still works");
assert.strictEqual(M.mediaUrl(camera, { rtspUser: "u", rtspPassword: "p", rtspPath: "/cam/realmonitor?channel=1&subtype=1" }),
  "rtsp://u:p@192.168.1.154:554/cam/realmonitor?channel=1&subtype=1");

// A camera that already refused without credentials must say so, and the chip
// must carry the hint that explains it.
assert.strictEqual(M.mediaNeedsAuth(camera), true);
assert.strictEqual(M.mediaNeedsAuth({ ip: "x", ports: [{ port: 554, proto: "rtsp" }] }), false);
assert.strictEqual(M.chipActions(camera, {}).filter(function (a) { return a.key === "play"; })[0].needsAuth, true);
assert.ok(M.mediaAction(camera, {}).tooltip.indexOf("rtspUser") !== -1);

// A path the camera reported wins over the configured one.
var withPath = { ip: "10.0.0.9", ports: [{ port: 8554, proto: "rtsp", url: "rtsp://10.0.0.9:8554/live" }] };
assert.strictEqual(M.mediaUrl(withPath, { rtspPath: "/ignored" }), "rtsp://10.0.0.9:8554/live");
assert.strictEqual(M.mediaUrl({ ip: "10.0.0.9", ports: [{ port: 80, proto: "http" }] }, {}), null);
assert.strictEqual(M.mediaAction({ ip: "10.0.0.9", ports: [] }, {}), null);

// Player argv. A stream that cannot be opened must still show a window:
// quiet mode plus no window is what made a 401 look like nothing happening.
var play = M.mediaAction(camera, {});
assert.deepStrictEqual(M.argvFor(play, { player: "mpv" }),
  ["mpv", "--no-config", "--force-window=yes", "--keep-open=no", "--title=netmap: 192.168.1.154",
   "rtsp://192.168.1.154:554/"]);
assert.ok(M.argvFor(play, { player: "mpv" }).indexOf("--really-quiet") === -1,
  "quiet mode is what turned a failed stream into silence");
assert.strictEqual(M.argvFor(play, { player: "vlc" })[0], "vlc");
assert.strictEqual(M.argvFor(play, { player: "ffplay" })[0], "ffplay");
assert.deepStrictEqual(M.argvFor(play, { player: "" }), ["gio", "open", "rtsp://192.168.1.154:554/"],
  "with no player installed the system handler for rtsp:// is asked");

// --------------------------------------------- pinned machines and wake-on-LAN

var desktop = { ip: "192.168.1.42", mac: "AA:BB:CC:DD:EE:FF", names: ["bureau.local"],
                alive: false, ports: [], open_ports: 0 };
var pins = M.togglePin(desktop, []);
assert.deepStrictEqual(pins, [{ mac: "aa:bb:cc:dd:ee:ff", ip: "192.168.1.42", name: "bureau.local" }]);
assert.strictEqual(M.isPinned(desktop, pins), true);
assert.strictEqual(M.isPinned({ ip: "192.168.1.42", mac: "aa:bb:cc:dd:ee:ff" }, pins), true, "matched by MAC");
assert.strictEqual(M.isPinned({ ip: "192.168.1.42", mac: "11:22:33:44:55:66" }, pins), false,
  "a different MAC at the same address is a different machine");
assert.deepStrictEqual(M.togglePin(desktop, pins), [], "toggling again unpins");
assert.deepStrictEqual(M.asPinList(JSON.stringify(pins)), pins, "pins survive a round trip through shell.json");
assert.deepStrictEqual(M.asPinList("not json"), []);
assert.deepStrictEqual(M.asPinList(""), []);
assert.deepStrictEqual(M.asPinList(null), []);

// A pinned machine that is switched off stays on screen, otherwise there is no
// way to reach its wake action.
var scanned = [
  { ip: "192.168.1.1", is_gateway: true, alive: true, ports: [], open_ports: 0, names: [] },
  { ip: "192.168.1.42", mac: "aa:bb:cc:dd:ee:ff", alive: true, open_ports: 1,
    web_url: "http://192.168.1.42/", names: ["bureau.local"], ports: [{ port: 80, proto: "http" }] }
];
// A pinned machine that is present on the network carries the flag as well,
// otherwise the PINNED filter finds nothing at all.
var marked = M.mergePinned(scanned, pins);
assert.strictEqual(marked[1].pinned, true, "an online pinned host is flagged");
assert.strictEqual(marked[0].pinned, undefined, "an unpinned host is not");
assert.strictEqual(scanned[1].pinned, undefined, "the scan's own object is not mutated");
assert.strictEqual(M.filterHosts(marked, "pinned").length, 1);
assert.strictEqual(M.sortHosts(marked)[1].ip, "192.168.1.42", "and it sorts above the rest");

var offline = M.mergePinned([scanned[0]], pins)[1];
assert.strictEqual(M.mergePinned(scanned, pins).length, 2, "a pin that was seen is not duplicated");
assert.strictEqual(M.mergePinned(scanned, []).length, 2, "no pins, no ghosts");
assert.strictEqual(offline.offline, true);
assert.strictEqual(offline.pinned, true);
assert.strictEqual(offline.alive, false);
assert.strictEqual(M.hostName(offline), "bureau.local");
assert.strictEqual(M.hostClassLabel(offline), "Offline");
assert.strictEqual(M.hostGlyph(offline), M.GLYPH.offline);

// Order: gateway, then pinned, then the rest by address.
assert.deepStrictEqual(M.sortHosts([
  { ip: "10.0.0.5", ports: [], open_ports: 0 },
  { ip: "10.0.0.9", pinned: true, ports: [], open_ports: 0 },
  { ip: "10.0.0.1", is_gateway: true, ports: [], open_ports: 0 }
]).map(function (h) { return h.ip; }), ["10.0.0.1", "10.0.0.9", "10.0.0.5"]);
assert.deepStrictEqual(M.FILTERS, ["all", "pinned", "open"]);
assert.strictEqual(M.filterHosts(M.mergePinned([scanned[0]], pins), "pinned").length, 1);
assert.strictEqual(M.filterLabel("pinned"), "PINNED");

// Wake needs the MAC, is the primary action of an offline pin, and only pinned
// machines carry the chip: an online host has nothing to wake.
assert.strictEqual(M.wakeAction({ ip: "10.0.0.9", ports: [] }, { pinned: [] }), null);
var wake = M.wakeAction(offline, { pinned: pins });
assert.strictEqual(wake.kind, "wol");
assert.strictEqual(wake.chip, true);
assert.strictEqual(M.chipActions(offline, { pinned: pins }).map(function (a) { return a.key; }).join(), "wake");
assert.strictEqual(M.wakeAction(scanned[1], { pinned: [] }).chip, false, "unpinned: no wake chip");
assert.strictEqual(M.primaryAction(offline, { pinned: pins }).kind, "wol");
assert.strictEqual(M.primaryAction(scanned[1], { pinned: pins }).key, "open",
  "an online pin still opens its web UI, waking is not forced on it");
assert.deepStrictEqual(M.argvFor(wake, { netmapBin: "/usr/local/bin/netmap" }),
  ["/usr/local/bin/netmap", "wol", "aa:bb:cc:dd:ee:ff", "--json", "--ip", "192.168.1.42"]);
assert.strictEqual(M.argvFor({ kind: "wol", mac: "zz:zz" }, {}), null, "a bad MAC never reaches the backend");
assert.strictEqual(M.argvFor({ kind: "wol" }, {}), null);
assert.strictEqual(M.isMac("aa:bb:cc:dd:ee:ff"), true);
assert.strictEqual(M.isMac("aabbccddeeff"), true);
assert.strictEqual(M.isMac("aa:bb:cc:dd:ee"), false);

console.log("Model.js: all assertions passed");
