import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

// Network Map: a bar widget that opens a panel showing the LAN as a map plus a
// keyboard-driven host list, where the primary action on a host is "open its
// web UI" when it has one and "ssh in" when it has ssh.
Panel {
  id: root

  moduleName: "omarchy-netmap"
  ipcTarget: "omarchy-netmap"
  // manageIpc is off because this panel owns the one IpcHandler the target
  // allows, so rescan() and setFilter() can be called from a keybinding.
  manageIpc: false

  IpcHandler {
    target: "omarchy-netmap"

    function open() { root.open() }
    function close() { root.close() }
    function show() { root.open() }
    function hide() { root.close() }
    function toggle() { root.toggle() }
    function rescan() { root.refresh() }
    function filter(value: string) { root.setFilter(value) }
    function watch() { root.toggleWatch() }
    // Automation: pin the host behind an address, and wake it.
    function pin(ip: string) {
      if (!root.svc) return
      var host = root.hostForIp(ip)
      if (!host) return
      root.focusedIp = ip
      root.togglePin(host)
    }
    function wake(ip: string) {
      if (!root.svc) return
      var host = root.hostForIp(ip)
      if (!host) return
      var action = Model.actionFor(host, root.options, ["wake"])
      if (action) root.launch(action)
    }
    // Automation and testing: run a host's primary action, or its stream.
    function play(ip: string) {
      if (!root.svc) return
      var host = root.hostForIp(ip)
      if (!host) return
      var action = Model.actionFor(host, root.options, ["play"])
      if (action) root.launch(action)
    }

    // Automation and debugging: what the panel is currently showing, as JSON.
    function state(): string {
      return JSON.stringify({
        scanning: root.scanning,
        watching: root.watching,
        player: root.player,
        pinned: root.pinned,
        // Geometry, so the layout can be checked from outside: the list must
        // shrink until the whole column fits inside the card.
        layout: {
          card: panel.contentHeight,
          cardAvailable: panel.availableCardHeight,
          list: hostList.height,
          listContent: hostList.contentHeight
        },
        filter: root.filter,
        selected: root.selectedHost ? root.selectedHost.ip : "",
        summary: root.summary,
        error: root.svc ? root.svc.lastError : "",
        activity: root.svc ? root.svc.activity : "",
        toast: root.svc ? root.svc.toast : null,
        filter: root.filter,
        visibleHosts: root.visibleHosts.length,
        // The display list, not the raw scan: ghosts and pin flags included, so
        // what this reports is what the panel actually shows.
        hosts: root.allHosts.map(function (host) {
          return {
            ip: host.ip,
            name: Model.hostName(host),
            class: Model.hostClassLabel(host),
            ports: (host.ports || []).map(function (port) { return port.port + "/" + (port.proto || ""); }),
            web_url: host.web_url || "",
            ssh_port: host.ssh_port || 0,
            ssh_command: Model.sshCommandPreview(host, root.options),
            pinned: host.pinned === true,
            offline: host.offline === true,
            actions: Model.chipActions(host, root.options).map(function (action) { return action.key; })
          };
        })
      });
    }
  }

  // One scan for the whole shell: the shell mounts the service once and hands
  // the same instance to every bar widget.
  readonly property var svc: bar && bar.shell && typeof bar.shell.serviceFor === "function"
    ? bar.shell.serviceFor(root.moduleName)
    : null

  readonly property color fg: Color.foreground
  readonly property color barFg: bar ? bar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property color muted: Qt.darker(fg, 1.4)
  readonly property color faint: Qt.darker(fg, 1.8)
  readonly property string ff: bar ? bar.fontFamily : Style.font.family

  // Pinned machines live in this widget's shell.json entry: the MAC is what
  // wake-on-LAN needs and what survives a DHCP change.
  readonly property var pinned: Model.asPinList(root.setting("pinned", []))

  readonly property var options: ({
    pinned: root.pinned,
    netmapBin: root.svc ? root.svc.binaryPath : "netmap",
    // "ip" or "name": whether ssh is given the address or the resolvable name.
    // The name is what a Host block in ~/.ssh/config usually matches, but it
    // needs mDNS resolution to work; the address always resolves.
    sshTarget: root.setting("sshTarget", "ip"),
    sshUser: root.setting("sshUser", ""),
    rtspUser: root.setting("rtspUser", ""),
    // A camera password does not have to be written into shell.json, which is
    // world-readable: NETMAP_RTSP_PASSWORD in the session environment wins.
    rtspPassword: Quickshell.env("NETMAP_RTSP_PASSWORD") !== ""
      ? Quickshell.env("NETMAP_RTSP_PASSWORD")
      : root.setting("rtspPassword", ""),
    rtspPath: root.setting("rtspPath", "")
  })

  /// Look a host up in what the panel actually shows, not just in the scan's
  /// map: a pinned machine that is switched off is an offline entry here, and
  /// it is precisely the one an IPC wake has to reach.
  function hostForIp(ip) {
    var list = root.allHosts;
    for (var i = 0; i < list.length; i++) {
      if (list[i].ip === ip) return list[i];
    }
    return root.svc ? root.svc.hostByIp(ip) : null;
  }

  // One place launches things. The panel closes first, because a window that
  // opens underneath the panel overlay looks exactly like nothing happening.
  function launch(action) {
    if (!action || !root.svc) return;
    if (action.kind !== "copy") root.close();
    root.svc.runAction(action);
  }

  // ---- settings ------------------------------------------------------------
  //
  // Settings live on the bar entry; the service cannot see them, so every bar
  // pushes the same values (idempotent).
  function syncSettings() {
    if (!root.svc) return;
    root.svc.settings = root.settings ? root.settings : ({});
    // Let the service react to settings that only matter to it (the monitoring
    // interval restarts the watcher; the notify switch is read there).
    if (typeof root.svc.onSettingsApplied === "function") root.svc.onSettingsApplied();
  }
  onSvcChanged: root.syncSettings()
  onSettingsChanged: root.syncSettings()
  Component.onCompleted: root.syncSettings()

  // ---- state ---------------------------------------------------------------
  readonly property var svcState: root.svc ? root.svc.state : Model.emptyState()
  // Pinned machines the scan did not see are added back as offline entries, so
  // a switched-off desktop is still on screen with wake one keystroke away.
  readonly property var allHosts: Model.sortHosts(
    Model.mergePinned(root.svc ? root.svc.hosts : [], root.pinned))
  readonly property var visibleHosts: Model.filterHosts(root.allHosts, root.filter)
  readonly property var summary: root.svc ? root.svc.summary : ({ hosts: 0, alive: 0, openPorts: 0, services: 0 })
  readonly property bool scanning: root.svc ? root.svc.scanning === true : false
  readonly property bool watching: root.svc ? root.svc.watching === true : false
  readonly property string player: root.svc ? root.svc.player : ""
  readonly property var progress: Model.progressInfo(root.svcState.progress)

  property string filter: root.setting("filter", "all")
  property bool detailsOpen: root.setting("detailsOpen", true) === true
  property string focusedIp: ""
  property bool cursorActive: false
  property int actionIndex: -1
  property double nowMs: Date.now()

  readonly property int selectedIndex: {
    var index = Model.indexOfIp(root.visibleHosts, root.focusedIp);
    return index < 0 ? 0 : index;
  }
  readonly property var selectedHost: root.visibleHosts.length > 0
    ? root.visibleHosts[root.selectedIndex]
    : null

  onVisibleHostsChanged: {
    if (root.visibleHosts.length === 0) {
      root.focusedIp = "";
      root.actionIndex = -1;
      return;
    }
    if (Model.indexOfIp(root.visibleHosts, root.focusedIp) < 0) {
      root.focusedIp = root.visibleHosts[0].ip;
    }
  }

  Timer {
    interval: 5000
    running: root.opened
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  readonly property string statusText: {
    root.nowMs; // re-evaluate the "updated 30s ago" part on every tick
    var text = Model.statusLine(root.svcState, root.nowMs, root.scanning);
    if (root.scanning && root.svc && root.svc.activity) {
      var activity = String(root.svc.activity);
      // The stream's status lines are the live activity feed.
      if (activity.indexOf("scanning ") === 0 || activity.indexOf("found ") === 0
          || activity.indexOf("open ") === 0 || activity.indexOf("mDNS") === 0
          || activity.indexOf("verifying") === 0 || activity.indexOf("asking") === 0) {
        text = text + " \u00b7 " + activity;
      }
    }
    return root.watching ? ("monitoring \u00b7 " + text) : text;
  }

  // ---- cursor --------------------------------------------------------------
  function moveCursor(delta) {
    if (root.visibleHosts.length === 0) return;
    var index = root.selectedIndex + delta;
    if (index < 0) index = 0;
    if (index > root.visibleHosts.length - 1) index = root.visibleHosts.length - 1;
    root.focusedIp = root.visibleHosts[index].ip;
    root.actionIndex = -1;
  }

  function chipCount() {
    return Model.chipActions(root.selectedHost, root.options).length;
  }

  function moveAction(delta) {
    var count = root.chipCount();
    if (count === 0) return;
    if (root.actionIndex < 0) {
      root.actionIndex = delta > 0 ? 0 : count - 1;
      return;
    }
    var next = root.actionIndex + delta;
    if (next < 0) { root.actionIndex = -1; return; }
    if (next > count - 1) { root.actionIndex = count - 1; return; }
    root.actionIndex = next;
  }

  function activateCursor() {
    if (!root.cursorActive) { root.cursorActive = true; return; }
    var host = root.selectedHost;
    if (!host || !root.svc) return;
    var chips = Model.chipActions(host, root.options);
    if (root.actionIndex >= 0 && root.actionIndex < chips.length) {
      root.launch(chips[root.actionIndex]);
      return;
    }
    var primary = Model.primaryAction(host, root.options);
    if (primary) root.launch(primary);
    else root.svc.notify("Nothing to open on " + host.ip, "warn");
  }

  function runKeys(keys) {
    var host = root.selectedHost;
    if (!host || !root.svc) return;
    var action = Model.actionFor(host, root.options, keys);
    if (action) root.launch(action);
    else root.svc.notify("Not available for " + Model.hostName(host), "warn");
  }

  function persistPinned(list) {
    var next = {};
    for (var key in root.settings) next[key] = root.settings[key];
    next.pinned = list;
    root.settings = next;
    if (root.bar && root.bar.shell && typeof root.bar.shell.updateEntryInline === "function") {
      root.bar.shell.updateEntryInline(root.moduleName, next);
    }
  }

  function togglePin(target) {
    // Called from the keyboard with no argument (the cursor's host) and from
    // IPC with an explicit one: relying on the cursor would pin whatever the
    // list happens to have selected when a filter hides the requested host.
    var host = target ? target : root.selectedHost;
    if (!host || !root.svc) return;
    var wasPinned = Model.isPinned(host, root.pinned);
    root.persistPinned(Model.togglePin(host, root.pinned));
    root.svc.notify(
      (wasPinned ? "Unpinned " : "Pinned ") + Model.hostName(host)
        + (wasPinned ? "" : (host.mac ? " - enter or the power chip wakes it" : " (no MAC: cannot wake it)")),
      wasPinned ? "warn" : "ok"
    );
  }

  function setFilter(value) {
    if (Model.FILTERS.indexOf(value) === -1) return;
    root.filter = value;
    root.actionIndex = -1;
  }

  // A one-shot rescan: monitoring is stopped first, so the two scan sources
  // can never run at once.
  function refresh() {
    if (!root.svc) return;
    if (root.watching) root.svc.stopWatch(true);
    if (root.scanning) root.svc.cancelScan();
    else root.svc.startScan(true);
  }

  function toggleWatch() {
    if (root.svc) root.svc.toggleWatch();
  }

  function handleKey(text) {
    var key = String(text || "").toLowerCase();
    if (key === "r") { root.refresh(); return; }
    if (key === "f") { root.setFilter(Model.nextFilter(root.filter)); return; }
    if (key === "d") { root.detailsOpen = !root.detailsOpen; return; }
    if (key === "s") { root.runKeys(["ssh"]); return; }
    if (key === "o") { root.runKeys(["open"]); return; }
    if (key === "p") { root.runKeys(["play", "open"]); return; }
    if (key === "w") { root.runKeys(["webapp", "open"]); return; }
    if (key === "c") { root.runKeys(["copy"]); return; }
    if (key === "t") { root.toggleWatch(); return; }
    if (key === "b") { root.togglePin(); return; }
    if (key === "g") { root.runKeys(["wake"]); return; }
    if (key === "i" && root.selectedHost && root.svc) {
      root.svc.notify(Model.hostMeta(root.selectedHost), "ok");
    }
  }

  function activateNode(ip) {
    if (!root.svc) return;
    if (root.focusedIp === ip && root.cursorActive) {
      var host = root.svc.hostByIp(ip);
      var primary = Model.primaryAction(host, root.options);
      if (primary) root.launch(primary);
      return;
    }
    root.focusedIp = ip;
    root.cursorActive = true;
    root.actionIndex = -1;
  }

  onOpenedChanged: {
    if (opened) {
      root.nowMs = Date.now();
      root.syncSettings();
      if (root.svc) root.svc.setActive(true);
      root.cursorActive = false;
      root.actionIndex = -1;
    } else if (root.svc) {
      root.svc.setActive(false);
    }
  }

  // ---- bar button ----------------------------------------------------------
  readonly property bool showCount: root.setting("showCount", "On") !== "Off"
  // The bar icon is the discreet state light: the loop glyph while continuous
  // monitoring is on, the magnifier while a scan is actually running.
  readonly property string icon: root.watching
    ? Model.GLYPH.loop
    : (root.scanning ? Model.GLYPH.magnify : Model.GLYPH.lan)
  readonly property string buttonLabel: root.showCount && root.summary.hosts > 0
    ? root.icon + " " + root.summary.hosts
    : root.icon

  visible: true
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.buttonLabel
    fontFamily: root.ff
    foreground: root.barFg
    active: !!(root.svc && root.svc.lastError !== "")
    tooltipText: {
      if (!root.svc) return "Network map";
      if (root.svc.lastError) return root.svc.lastError;
      if (root.scanning) return "Scanning the network\u2026";
      return root.summary.hosts + " hosts \u00b7 " + root.summary.openPorts + " open ports \u00b7 click to open, right-click to rescan";
    }
    onPressed: function (mouseButton) {
      if (mouseButton === Qt.RightButton) root.refresh();
      else root.toggle();
    }
  }

  // ---- panel ---------------------------------------------------------------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(780))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent

      onMoveRequested: function (dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return; }
        if (dy !== 0) root.moveCursor(dy);
        else if (dx !== 0) root.moveAction(dx);
      }
      onActivateRequested: root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function (direction) { root.switchPanel(direction) }
      onDeleteRequested: root.toggleWatch()
      onTextKey: function (text) { root.handleKey(text) }

      Column {
        id: column
        anchors.fill: parent
        spacing: Style.space(10)

        // ---------- hero ----------
        Item {
          id: heroBlock
          width: parent.width
          implicitHeight: Math.max(heroGlyph.implicitHeight, heroLabels.implicitHeight, heroButton.implicitHeight)

          Text {
            id: heroGlyph
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: root.icon
            color: root.accent
            font.family: root.ff
            font.pixelSize: Style.font.display
          }

          // Discrete continuous-monitoring toggle: a small loop arrow that
          // only lights up while watching.
          PanelActionButton {
            id: watchButton
            anchors.right: heroButton.left
            anchors.rightMargin: Style.space(6)
            anchors.verticalCenter: parent.verticalCenter
            size: Math.max(Style.space(24), Style.font.title + Style.spacing.md)
            iconText: Model.GLYPH.loop
            tooltipText: root.watching
              ? "Monitoring every " + Math.max(15, Number(root.setting("intervalSec", 60))) + "s - click to stop"
              : "Watch the network continuously"
            foreground: root.fg
            hoverColor: root.accent
            fontFamily: root.ff
            bordered: root.watching
            hasCursor: root.watching
            onClicked: root.toggleWatch()
          }

          PanelActionButton {
            id: heroButton
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            size: Math.max(Style.space(24), Style.font.title + Style.spacing.md)
            iconText: root.scanning && !root.watching ? Model.GLYPH.magnify : Model.GLYPH.refresh
            tooltipText: root.scanning && !root.watching ? "Stop the scan" : "Rescan once"
            foreground: root.fg
            hoverColor: root.accent
            fontFamily: root.ff
            onClicked: root.refresh()
          }

          Column {
            id: heroLabels
            anchors.left: heroGlyph.right
            anchors.leftMargin: Style.space(12)
            anchors.right: watchButton.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(1)

            Text {
              textFormat: Text.PlainText
              text: "Network Map"
              color: root.fg
              font.family: root.ff
              font.pixelSize: Style.font.title
              font.bold: true
              width: parent.width
              elide: Text.ElideRight
            }

            Text {
              id: heroStatus
              textFormat: Text.PlainText
              text: root.statusText
              color: root.muted
              font.family: root.ff
              font.pixelSize: Style.font.caption
              width: parent.width
              elide: Text.ElideRight
            }
          }
        }

        // ---------- map ----------
        Map {
          id: mapBlock
          width: parent.width
          height: Style.space(150)
          hosts: root.allHosts
          selectedIp: root.focusedIp
          scanning: root.scanning
          foreground: root.fg
          accent: root.accent
          onNodeClicked: function (ip) { root.activateNode(ip) }
          onNodeHovered: function (ip) {
            // Hovering a node moves the shared cursor, so the list follows the
            // map and there is only ever one highlight on screen.
            if (root.focusedIp !== ip) {
              root.focusedIp = ip;
              root.actionIndex = -1;
            }
          }
        }

        // ---------- scan progress ----------
        Item {
          id: progressBlock
          width: parent.width
          height: Style.space(6)
          visible: root.scanning

          Rectangle {
            id: progressTrack
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - progressText.width - Style.space(8)
            height: Style.space(3)
            radius: height / 2
            color: Style.normalFillFor(root.fg, root.accent)

            Rectangle {
              width: Math.round(parent.width * ((root.progress ? root.progress.percent : 0) / 100))
              height: parent.height
              radius: height / 2
              color: root.accent

              Behavior on width {
                NumberAnimation { duration: 200; easing.type: Easing.OutQuad }
              }
            }
          }

          Text {
            id: progressText
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: root.progress ? Math.round(root.progress.percent) + "%" : "\u2026"
            color: root.muted
            font.family: root.ff
            font.pixelSize: Style.font.caption
          }
        }

        // ---------- filter + counts ----------
        Item {
          id: filterBlock
          width: parent.width
          height: chipRow.implicitHeight

          Row {
            id: chipRow
            spacing: Style.space(6)

            Repeater {
              model: Model.FILTERS

              delegate: FilterChip {
                required property var modelData
                text: Model.filterLabel(modelData)
                count: modelData === "all"
                  ? root.allHosts.length
                  : Model.filterHosts(root.allHosts, modelData).length
                selected: root.filter === modelData
                onClicked: root.setFilter(modelData)
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: (root.selectedHost
              ? Model.hostClassLabel(root.selectedHost)
              : "no hosts") + " \u00b7 " + root.visibleHosts.length + " shown"
            color: root.faint
            font.family: root.ff
            font.pixelSize: Style.font.caption
          }
        }

        PanelSeparator { foreground: root.fg }

        // ---------- hosts ----------
        ListView {
          id: hostList
          width: parent.width
          // The list gets exactly what is left of the panel after the rest of
          // the column, so the footer can never be pushed outside the card -
          // which is what a fixed height used to do on a short screen.
          height: {
            var others = heroBlock.implicitHeight + mapBlock.height + progressBlock.height
              + filterBlock.implicitHeight + footerBlock.implicitHeight + Style.space(10) * 6;
            var available = panel.availableCardHeight - panel.verticalContentInset - others;
            var wanted = Math.min(contentHeight, Style.space(Number(root.setting("listHeight", 300))));
            return Math.max(Style.space(88), Math.min(wanted, available));
          }
          clip: true
          spacing: Style.space(4)
          boundsBehavior: Flickable.StopAtBounds
          interactive: contentHeight > height
          model: root.visibleHosts
          currentIndex: root.selectedIndex
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
          onCurrentIndexChanged: if (currentIndex >= 0) Qt.callLater(keepCurrentVisible)
          function keepCurrentVisible() {
            if (currentIndex >= 0) positionViewAtIndex(currentIndex, ListView.Contain);
          }

          delegate: HostRow {
            required property var modelData
            width: hostList.width
            host: modelData
            rowIndex: root.visibleHosts.indexOf(modelData)
          }

          Text {
            textFormat: Text.PlainText
            visible: root.visibleHosts.length === 0
            anchors.centerIn: parent
            width: parent.width - Style.space(20)
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: root.svc && root.svc.lastError
              ? root.svc.lastError
              : (root.allHosts.length > 0
                ? "No host matches this filter"
                : "Press r to scan the network")
            color: root.muted
            font.family: root.ff
            font.pixelSize: Style.font.bodySmall
          }
        }

        // Advertised services are shown on the host they belong to, inside
        // its details. An advertised port is not a service you can click: adb,
        // sftp and kdeconnect ports are not web servers, and offering a browser
        // for them was simply wrong.

        // ---------- footer ----------
        Item {
          id: footerBlock
          width: parent.width
          height: footer.implicitHeight

          Text {
            id: footer
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.right: hint.left
            anchors.rightMargin: Style.space(8)
            text: {
              if (root.svc && root.svc.toast && root.svc.toast.text) return root.svc.toast.text;
              if (root.selectedHost) {
                return Model.hostName(root.selectedHost) + " \u00b7 " + Model.hostMeta(root.selectedHost);
              }
              return root.watching
                ? "monitoring the network"
                : "Click a node to select it, click again to open it";
            }
            // A toast the user triggered is the one line worth colouring: a
            // failed one is urgent, a plain refresh notice stays quiet.
            color: {
              if (!root.svc || !root.svc.toast || !root.svc.toast.text) return root.muted;
              return root.svc.toast.kind !== "ok" ? Color.urgent : root.accent;
            }
            font.family: root.ff
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
          }

          Text {
            id: hint
            textFormat: Text.PlainText
            anchors.right: parent.right
            width: Math.min(implicitWidth, column.width * 0.5)
            horizontalAlignment: Text.AlignRight
            text: root.watching
              ? "t stop \u00b7 enter open \u00b7 b pin \u00b7 g wake \u00b7 s ssh"
              : "t watch \u00b7 enter open \u00b7 b pin \u00b7 f filter \u00b7 r rescan"
            color: root.faint
            font.family: root.ff
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
          }
        }
      }
    }
  }

  // ---- components ----------------------------------------------------------

  component FilterChip: BorderSurface {
    id: chip

    property string text: ""
    property int count: 0
    property bool selected: false
    signal clicked()

    implicitWidth: chipLabel.implicitWidth + Style.space(12)
    implicitHeight: chipLabel.implicitHeight + Style.space(6)
    radius: Style.cornerRadius
    color: chip.selected
      ? Style.selectedFillFor(root.fg, root.accent)
      : (chipMouse.containsMouse ? Style.hoverFillFor(root.fg, root.accent) : "transparent")
    borderSpec: chip.selected
      ? Border.controlSpec("selected", root.accent, root.accent)
      : Border.controlSpec("normal", root.fg, root.accent)

    Text {
      id: chipLabel
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: chip.text + (chip.count > 0 ? " " + chip.count : "")
      color: chip.selected ? root.accent : root.fg
      font.family: root.ff
      font.pixelSize: Style.font.caption
      font.bold: chip.selected
      font.letterSpacing: 0.8
    }

    MouseArea {
      id: chipMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: chip.clicked()
    }
  }

  // One host: name, address/vendor/class, port chips, action chips, and - for
  // the selected row - the identified services underneath.
  component HostRow: CursorSurface {
    id: row

    required property var host
    required property int rowIndex

    readonly property bool isSelected: root.cursorActive
      && root.selectedIndex === row.rowIndex
      && root.focusedIp === row.host.ip
    readonly property var actions: Model.actionsFor(row.host, root.options)
    readonly property var chips: Model.chipActions(row.host, root.options)
    // One name width shared by every row, so the addresses line up in a column
    // instead of trailing each name at a different x. Clamped so a wide address
    // can never be pushed off the row on a narrow panel.
    readonly property real nameColumn: Math.max(Style.space(72),
      Math.min(Math.round(rowLabels.width * 0.42),
        rowLabels.width - ipLabel.implicitWidth - Style.space(30)))

    hasCursor: row.isSelected && root.actionIndex < 0
    current: row.host.is_gateway === true
    foreground: root.fg
    accent: root.accent
    implicitHeight: content.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      id: rowMouse
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      cursorShape: Qt.PointingHandCursor

      onContainsMouseChanged: if (containsMouse) {
        root.cursorActive = true;
        root.focusedIp = row.host.ip;
        root.actionIndex = -1;
      }

      onClicked: function (mouse) {
        var primary = Model.primaryAction(row.host, root.options);
        if (mouse.button === Qt.RightButton) {
          var copy = Model.actionFor(row.host, root.options, ["copy"]);
          if (copy) root.launch(copy);
          return;
        }
        if (!root.svc || !primary) return;
        root.launch(primary);
      }
    }

    // Accent rail on the row under the cursor: the selection reads at a glance
    // even when the row has no open ports to colour it.
    Rectangle {
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(3)
      height: Math.max(Style.space(12), parent.height - Style.space(12))
      radius: width / 2
      color: root.accent
      visible: row.isSelected
    }

    Item {
      id: content
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      implicitHeight: mainRow.implicitHeight + (details.visible ? details.implicitHeight + Style.space(6) : 0)

      Item {
        id: mainRow
        width: parent.width
        implicitHeight: Math.max(rowGlyph.implicitHeight, rowLabels.implicitHeight, actionRow.implicitHeight)

        Text {
          id: rowGlyph
          textFormat: Text.PlainText
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          text: Model.hostGlyph(row.host)
          color: row.host.alive !== false ? root.accent : root.faint
          font.family: root.ff
          font.pixelSize: Style.font.heading
        }

        Row {
          id: actionRow
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(4)

          Repeater {
            model: row.chips

            delegate: PanelActionButton {
              required property var modelData
              required property int index
              iconText: modelData.glyph
              tooltipText: modelData.tooltip
              foreground: root.fg
              hoverColor: root.accent
              fontFamily: root.ff
              hasCursor: row.isSelected && root.actionIndex === index
              onHovered: function (isHovered) {
                if (!isHovered) {
                  if (rowMouse.containsMouse) root.actionIndex = -1;
                  return;
                }
                root.cursorActive = true;
                root.focusedIp = row.host.ip;
                root.actionIndex = index;
              }
              onClicked: if (root.svc) root.svc.runAction(modelData)
            }
          }
        }

        Column {
          id: rowLabels
          anchors.left: rowGlyph.right
          anchors.leftMargin: Style.space(10)
          anchors.right: actionRow.left
          anchors.rightMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(1)

          Row {
            width: parent.width
            spacing: Style.space(6)

            // Always occupies its slot (an empty string when there is no pin);
            // a positioner skips an invisible item, which would shift every
            // unpinned row left of the pinned ones.
            Text {
              id: pinGlyph
              textFormat: Text.PlainText
              text: row.host.pinned === true ? Model.GLYPH.pin : ""
              color: root.accent
              font.family: root.ff
              font.pixelSize: Style.font.caption
              width: Style.space(12)
            }

            // The name elides into one shared column (see nameColumn), so the
            // address always starts at the same x down the list.
            Text {
              id: hostLabel
              textFormat: Text.PlainText
              text: Model.shorten(Model.hostName(row.host), 30)
              color: root.fg
              font.family: root.ff
              font.pixelSize: Style.font.body
              width: row.nameColumn
              elide: Text.ElideRight
            }

            Text {
              id: ipLabel
              textFormat: Text.PlainText
              text: row.host.ip
              color: root.muted
              font.family: root.ff
              font.pixelSize: Style.font.caption
            }
          }

          // One line of ports, or the class label when nothing is open. The
          // MAC, vendor and round trip live in the details and in the i toast:
          // a row is not the place for four facts at once.
          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: row.host.open_ports > 0
              ? Model.portChips(row.host, 4).join("  \u00b7  ")
                + ((row.host.services || []).length > 0 ? "  \u00b7  mdns " + row.host.services.length : "")
              : Model.hostClassLabel(row.host)
            color: row.host.open_ports > 0 ? root.accent : root.muted
            font.family: root.ff
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
          }
        }
      }

      // Identified services for the selected host: every port with what the
      // scanner learned about it, and a chip to act on it directly.
      Column {
        id: details
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: mainRow.bottom
        anchors.topMargin: Style.space(6)
        anchors.leftMargin: Style.space(26)
        spacing: Style.space(2)
        visible: row.isSelected && root.detailsOpen

        Repeater {
          model: (row.host.ports || []).slice(0, 4)

          delegate: PortRow {
            required property var modelData
            width: details.width
            host: row.host
            port: modelData
          }
        }

        Repeater {
          model: (row.host.services || []).slice(0, 3)

          delegate: Text {
            required property var modelData
            textFormat: Text.PlainText
            width: details.width
            text: "\u25cb " + Model.mdnsLabel(modelData)
            color: root.muted
            font.family: root.ff
            font.pixelSize: Style.font.caption
            elide: Text.ElideRight
          }
        }

        Text {
          textFormat: Text.PlainText
          visible: (row.host.ports || []).length > 4
          width: details.width
          text: "+" + ((row.host.ports || []).length - 4) + " more ports"
          color: root.faint
          font.family: root.ff
          font.pixelSize: Style.font.caption
        }
      }
    }
  }

  // One identified port inside the expanded host: what it is, and the action it
  // supports (ssh, or open the URL it reported).
  component PortRow: Item {
    id: portRow

    required property var host
    required property var port

    readonly property var action: Model.portAction(portRow.host, portRow.port, root.options)

    implicitHeight: Math.max(portLabelText.implicitHeight, portAction.implicitHeight)

    Text {
      id: portLabelText
      textFormat: Text.PlainText
      anchors.left: parent.left
      anchors.right: portAction.visible ? portAction.left : parent.right
      anchors.rightMargin: Style.space(6)
      anchors.verticalCenter: parent.verticalCenter
      text: portRow.port.port + "/tcp  " + (portRow.port.proto || portRow.port.service)
        + (Model.describePort(portRow.port) ? "  \u00b7  " + Model.describePort(portRow.port) : "")
      color: root.muted
      font.family: root.ff
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
    }

    PanelActionButton {
      id: portAction
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      visible: portRow.action !== null
      iconText: portRow.action ? portRow.action.glyph : ""
      tooltipText: portRow.action ? portRow.action.tooltip : ""
      foreground: root.fg
      hoverColor: root.accent
      fontFamily: root.ff
      onClicked: if (portRow.action) root.launch(portRow.action)
    }
  }


}
