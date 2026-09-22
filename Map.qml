import QtQuick
import qs.Ui
import qs.Commons
import "Model.js" as Model

// The topology view: the gateway sits in the middle, every other host on one or
// two rings around it, connected by a spoke. Node size grows with the number of
// open ports, colour comes from the active theme, and nodes glide when the
// layout changes so a rescan does not flash.
Item {
  id: root

  property var hosts: []
  property string selectedIp: ""
  property bool scanning: false
  property color foreground: Color.foreground
  property color accent: Color.accent

  signal nodeClicked(string ip)
  signal nodeHovered(string ip)

  readonly property var layout: Model.layoutMap(root.hosts, root.width, root.height)
  readonly property var gateway: root.layout.gateway
  readonly property color spokeColor: Util.alpha(root.foreground, 0.22)
  readonly property color ringColor: Util.alpha(root.foreground, 0.10)

  // Subnet ring, so the graph reads as a network rather than a starburst.
  Rectangle {
    visible: root.layout.nodes.length > 2
    anchors.centerIn: parent
    width: Math.min(root.width, root.height) - Style.space(34)
    height: width
    radius: width / 2
    color: "transparent"
    border.width: 1
    border.color: root.ringColor
    opacity: 0.8
  }

  // ---- spokes ------------------------------------------------------------
  Repeater {
    model: root.layout.nodes

    delegate: Item {
      required property var modelData
      visible: root.gateway !== null
      x: root.gateway ? root.gateway.x : 0
      y: root.gateway ? root.gateway.y : 0
      width: 1
      height: 1

      Rectangle {
        width: Math.max(1, Math.sqrt(
          Math.pow(modelData.x - (root.gateway ? root.gateway.x : 0), 2) +
          Math.pow(modelData.y - (root.gateway ? root.gateway.y : 0), 2)))
        height: 1
        color: root.spokeColor
        transformOrigin: Item.TopLeft
        rotation: Math.atan2(
          modelData.y - (root.gateway ? root.gateway.y : 0),
          modelData.x - (root.gateway ? root.gateway.x : 0)) * 180 / Math.PI
      }
    }
  }

  // ---- nodes -------------------------------------------------------------
  Repeater {
    model: root.layout.nodes

    delegate: Item {
      id: node
      required property var modelData

      readonly property var host: node.modelData.host
      readonly property bool selected: root.selectedIp === node.modelData.ip
      readonly property int openPorts: node.host.open_ports || 0
      readonly property bool lively: node.host.alive !== false

      width: node.modelData.r * 2
      height: node.modelData.r * 2
      x: node.modelData.x - node.modelData.r
      y: node.modelData.y - node.modelData.r
      z: node.selected ? 3 : 1

      Behavior on x { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }
      Behavior on y { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }

      // Pulse on the selected node while a scan is running.
      Rectangle {
        anchors.centerIn: parent
        width: parent.width + Style.space(10)
        height: width
        radius: width / 2
        color: "transparent"
        border.width: 1
        border.color: root.accent
        opacity: 0
        visible: node.selected && root.scanning

        SequentialAnimation on opacity {
          running: node.selected && root.scanning
          loops: Animation.Infinite
          NumberAnimation { to: 0.55; duration: 500; easing.type: Easing.OutQuad }
          NumberAnimation { to: 0.0; duration: 700; easing.type: Easing.InQuad }
        }
      }

      BorderSurface {
        anchors.fill: parent
        radius: width / 2
        color: node.selected
          ? Style.selectedFillFor(root.foreground, root.accent)
          : (mouse.containsMouse || node.openPorts > 0
            ? Style.hoverFillFor(root.foreground, root.accent)
            : "transparent")
        borderSpec: node.selected
          ? Border.controlSpec("selected", root.accent, root.accent)
          : (node.openPorts > 0
            ? Border.controlSpec("hover-cursor", root.accent, root.accent)
            : Border.controlSpec("normal", root.foreground, root.accent))
        opacity: node.lively ? 1 : 0.55
      }

      Text {
        textFormat: Text.PlainText
        anchors.centerIn: parent
        text: Model.hostGlyph(node.host)
        color: node.selected || node.openPorts > 0 ? root.accent : root.foreground
        font.family: Style.font.family
        font.pixelSize: Math.max(Style.font.bodySmall, node.modelData.r)
        opacity: node.lively ? 1 : 0.7
      }

      Text {
        textFormat: Text.PlainText
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.bottom
        anchors.topMargin: Style.space(1)
        text: node.modelData.ip.split(".").slice(2).join(".")
        color: node.selected ? root.accent : Util.alpha(root.foreground, 0.6)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      Text {
        textFormat: Text.PlainText
        visible: node.selected
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.bottom
        anchors.topMargin: Style.space(1) + Style.font.caption + 1
        text: Model.shorten(Model.hostName(node.host), 22)
        color: root.foreground
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onEntered: root.nodeHovered(node.modelData.ip)
        onClicked: root.nodeClicked(node.modelData.ip)
      }
    }
  }

  // ---- gateway -----------------------------------------------------------
  Item {
    id: hub
    visible: root.gateway !== null
    width: (root.gateway ? root.gateway.r * 2 : 0)
    height: width
    x: (root.gateway ? root.gateway.x : 0) - width / 2
    y: (root.gateway ? root.gateway.y : 0) - height / 2
    z: 2

    readonly property bool selected: root.gateway !== null && root.selectedIp === root.gateway.ip

    BorderSurface {
      anchors.fill: parent
      radius: width / 2
      color: hub.selected
        ? Style.selectedFillFor(root.foreground, root.accent)
        : Style.hoverFillFor(root.foreground, root.accent)
      borderSpec: hub.selected
        ? Border.controlSpec("selected", root.accent, root.accent)
        : Border.controlSpec("hover-cursor", root.accent, root.accent)
    }

    Text {
      textFormat: Text.PlainText
      anchors.centerIn: parent
      text: Model.GLYPH.router
      color: root.accent
      font.family: Style.font.family
      font.pixelSize: Style.font.heading
    }

    Text {
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.top: parent.bottom
      anchors.topMargin: Style.space(2)
      text: root.gateway ? Model.shorten(Model.hostName(root.gateway.host), 18) : ""
      color: root.foreground
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    MouseArea {
      id: hubMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: if (root.gateway) root.nodeHovered(root.gateway.ip)
      onClicked: if (root.gateway) root.nodeClicked(root.gateway.ip)
    }
  }

  // Empty state, so the map is not just a blank rectangle while scanning.
  Text {
    textFormat: Text.PlainText
    visible: root.hosts.length === 0
    anchors.centerIn: parent
    width: parent.width - Style.space(20)
    horizontalAlignment: Text.AlignHCenter
    wrapMode: Text.WordWrap
    text: root.scanning
      ? "Mapping the network\u2026"
      : "No hosts yet \u2014 press r to scan"
    color: Util.alpha(root.foreground, 0.7)
    font.family: Style.font.family
    font.pixelSize: Style.font.bodySmall
  }
}
