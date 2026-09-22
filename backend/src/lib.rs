//! netmap: local network mapping for humans and for the Omarchy shell.
//!
//! The library is split so each piece is testable on its own:
//!   * interfaces - what this machine is connected to, and its ARP cache
//!   * mdns       - service discovery over DNS-SD (native + avahi)
//!   * ports      - the curated port table and how to probe each port
//!   * probe      - protocol identification for an open port
//!   * netbios    - NetBIOS name queries, the cheapest name source on a LAN
//!   * classify   - port/mDNS/vendor evidence to a device class and icon
//!   * scan       - the parallel driver that ties all of it together
//!   * emit       - JSON Lines / JSON / table rendering

pub mod classify;
pub mod cli;
pub mod diff;
pub mod emit;
pub mod interfaces;
pub mod mdns;
pub mod model;
pub mod netbios;
pub mod oui;
pub mod ports;
pub mod probe;
pub mod scan;
pub mod util;
pub mod wol;
