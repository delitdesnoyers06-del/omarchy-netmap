//! MAC OUI to vendor hint.
//!
//! The full IEEE OUI registry is about 35k prefixes and changes weekly. This is
//! a deliberately curated table of prefixes for hardware that actually shows up
//! on a home or office LAN. It is a hint shown next to the classification that
//! comes from port and mDNS evidence; an unknown prefix returns None rather
//! than guessing wrong.

use crate::util::oui_key;

/// (OUI prefix, vendor). Prefixes are the first three octets of the MAC.
static VENDORS: &[(&str, &str)] = &[
    ("000C29", "VMware"),
    ("005056", "VMware"),
    ("00155D", "Microsoft (Hyper-V)"),
    ("080027", "Oracle VirtualBox"),
    ("525400", "QEMU/KVM"),
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("2CCF67", "Raspberry Pi Trading"),
    ("288088", "Intel"),
    ("001B21", "Intel"),
    ("8086F2", "Intel"),
    ("3C22FB", "Apple"),
    ("0017F2", "Apple"),
    ("0017AB", "Apple"),
    ("001E52", "Apple"),
    ("002332", "Apple"),
    ("00264A", "Apple"),
    ("0026B0", "Apple"),
    ("3451C9", "Apple"),
    ("3C0754", "Apple"),
    ("4C3275", "Apple"),
    ("5C969D", "Apple"),
    ("60FACD", "Apple"),
    ("6C709F", "Apple"),
    ("78CA39", "Apple"),
    ("7CD1C3", "Apple"),
    ("8863DF", "Apple"),
    ("8C8590", "Apple"),
    ("9801A7", "Apple"),
    ("A4C361", "Apple"),
    ("A8667F", "Apple"),
    ("B8C75D", "Apple"),
    ("D0E140", "Apple"),
    ("F0DBE2", "Apple"),
    ("F4F15A", "Apple"),
    ("F81EDF", "Apple"),
    ("24A2E1", "Apple"),
    ("2C1F23", "Apple"),
    ("5CF938", "Apple"),
    ("9C207B", "Apple"),
    ("F0B0E7", "Apple"),
    ("F0D1A9", "Apple"),
    ("BC926B", "Apple"),
    ("D49A20", "Apple"),
    ("24F094", "Apple"),
    ("38C986", "Apple"),
    ("F8FF0B", "Apple"),
    ("BC52B7", "Apple"),
    ("40831D", "Apple"),
    ("F0EE7A", "Apple"),
    ("7CC537", "Apple"),
    ("B0BE76", "Apple"),
    ("28CFE9", "Apple"),
    ("18FE34", "Espressif (IoT)"),
    ("600194", "Espressif (IoT)"),
    ("240AC4", "Espressif (IoT)"),
    ("30AEA4", "Espressif (IoT)"),
    ("3C71BF", "Espressif (IoT)"),
    ("84CCA8", "Espressif (IoT)"),
    ("A4CF12", "Espressif (IoT)"),
    ("CC50E3", "Espressif (IoT)"),
    ("DC4F22", "Espressif (IoT)"),
    ("ECFABC", "Espressif (IoT)"),
    ("7CDFA1", "Espressif (IoT)"),
    ("483FDA", "Espressif (IoT)"),
    ("C44F33", "Espressif (IoT)"),
    ("B4E62D", "Espressif (IoT)"),
    ("08B61F", "Espressif (IoT)"),
    ("F4CFA2", "Espressif (IoT)"),
    ("AC67B2", "Espressif (IoT)"),
    ("94B97E", "Espressif (IoT)"),
    ("44650D", "Espressif (IoT)"),
    ("3CE90E", "Shelly (Allterco)"),
    ("C45BBE", "Shelly (Allterco)"),
    ("441793", "Shelly (Allterco)"),
    ("84F3EB", "Shelly (Allterco)"),
    ("D8F15B", "Tuya / smart device"),
    ("68572D", "Tuya / smart device"),
    ("105A17", "Tuya / smart device"),
    ("3425B4", "Tuya / smart device"),
    ("001788", "Philips Hue"),
    ("ECB5FA", "Philips Hue"),
    ("000E58", "Sonos"),
    ("5CAAFD", "Sonos"),
    ("949F3E", "Sonos"),
    ("B8E937", "Sonos"),
    ("F0272D", "Amazon"),
    ("384F49", "Amazon"),
    ("6854FD", "Amazon"),
    ("74C246", "Amazon"),
    ("84D6D0", "Amazon"),
    ("AC63BE", "Amazon"),
    ("FCA183", "Amazon"),
    ("4CEFC0", "Amazon"),
    ("3C5AB4", "Google"),
    ("F4F5D8", "Google"),
    ("6CADF8", "Google"),
    ("48D6D5", "Google"),
    ("A47733", "Google"),
    ("F88FCA", "Google"),
    ("6466B3", "Google"),
    ("DAA119", "Google"),
    ("B0A737", "Roku"),
    ("CC6DA0", "Roku"),
    ("D83134", "Roku"),
    ("AC3A7A", "Roku"),
    ("0012FB", "Samsung"),
    ("002454", "Samsung"),
    ("5001BB", "Samsung"),
    ("8425DB", "Samsung"),
    ("8C71F8", "Samsung"),
    ("E8508B", "Samsung"),
    ("F8042E", "Samsung"),
    ("1C5A3E", "Samsung"),
    ("00241D", "LG Electronics"),
    ("10F1F2", "LG Electronics"),
    ("A816B2", "LG Electronics"),
    ("C4366C", "LG Electronics"),
    ("001A8C", "Sony"),
    ("30F9ED", "Sony"),
    ("AC9B0A", "Sony"),
    ("28E31F", "Xiaomi"),
    ("34CE00", "Xiaomi"),
    ("50EC50", "Xiaomi"),
    ("64B473", "Xiaomi"),
    ("F0B429", "Xiaomi"),
    ("00259E", "Huawei"),
    ("00E0FC", "Huawei"),
    ("10474B", "Huawei"),
    ("24099A", "Huawei"),
    ("9C28F7", "Huawei"),
    ("001D7E", "Cisco-Linksys"),
    ("1CDF0F", "Cisco"),
    ("C067AF", "Cisco"),
    ("00206B", "Cisco Aironet"),
    ("24A43C", "Ubiquiti"),
    ("44D9E7", "Ubiquiti"),
    ("68D79A", "Ubiquiti"),
    ("74ACB9", "Ubiquiti"),
    ("788A20", "Ubiquiti"),
    ("B4FBE4", "Ubiquiti"),
    ("E063DA", "Ubiquiti"),
    ("F80277", "Ubiquiti"),
    ("0418D6", "Ubiquiti"),
    ("687251", "Ubiquiti"),
    ("DC9FDB", "Ubiquiti"),
    ("18E829", "Ubiquiti"),
    ("245A4C", "Ubiquiti"),
    ("744D28", "MikroTik"),
    ("488F5A", "MikroTik"),
    ("6C3B6B", "MikroTik"),
    ("E48D8C", "MikroTik"),
    ("2CC81B", "MikroTik"),
    ("DC2C6E", "MikroTik"),
    ("0022B0", "D-Link"),
    ("14D64D", "D-Link"),
    ("1CBDB9", "D-Link"),
    ("CCB255", "D-Link"),
    ("001F33", "Netgear"),
    ("20E52A", "Netgear"),
    ("2C3033", "Netgear"),
    ("A040A0", "Netgear"),
    ("B03956", "Netgear"),
    ("C40415", "Netgear"),
    ("9C3DCF", "Netgear"),
    ("2C3AE8", "TP-Link"),
    ("50C7BF", "TP-Link"),
    ("60E327", "TP-Link"),
    ("AC84C6", "TP-Link"),
    ("F4EC38", "TP-Link"),
    ("1CFA68", "TP-Link"),
    ("B0958E", "TP-Link"),
    ("1027F5", "TP-Link"),
    ("001132", "Synology"),
    ("0011D8", "ASUS"),
    ("2C56DC", "ASUS"),
    ("AC9E17", "ASUS"),
    ("F832E4", "ASUS"),
    ("50465D", "ASUS"),
    ("9C5C8E", "ASUS"),
    ("245EBE", "QNAP"),
    ("00089B", "QNAP"),
    ("0090A9", "Western Digital"),
    ("0014FD", "Western Digital"),
    ("0004AC", "HP"),
    ("3CD92B", "HP"),
    ("001BA9", "Brother"),
    ("30055C", "Brother"),
    ("008077", "Brother"),
    ("000048", "Seiko Epson"),
    ("44D244", "Seiko Epson"),
    ("001E8F", "Canon"),
    ("F48139", "Canon"),
    ("0017C8", "Kyocera"),
    ("001F3B", "Crestron"),
    ("000B82", "Grandstream"),
    ("9C4E20", "Cisco Meraki"),
];

/// Number of curated OUI prefixes, for the version report.
pub fn table_size() -> usize {
    VENDORS.len()
}

/// Vendor hint for a MAC address, if its OUI is in the curated table.
pub fn lookup(mac: &str) -> Option<&'static str> {
    let key = oui_key(mac)?;
    VENDORS
        .iter()
        .find(|(prefix, _)| prefix.eq_ignore_ascii_case(&key))
        .map(|(_, vendor)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_well_formed() {
        for (prefix, vendor) in VENDORS {
            assert_eq!(prefix.len(), 6, "bad OUI prefix {prefix}");
            assert!(
                prefix.chars().all(|c| c.is_ascii_hexdigit()),
                "non-hex OUI prefix {prefix}"
            );
            assert!(
                prefix.chars().all(|c| !c.is_ascii_lowercase()),
                "OUI prefixes are uppercase: {prefix}"
            );
            assert!(!vendor.is_empty());
        }
    }

    #[test]
    fn no_duplicate_prefixes() {
        let mut sorted: Vec<&str> = VENDORS.iter().map(|(p, _)| *p).collect();
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate OUI prefix {}", pair[0]);
        }
    }

    #[test]
    fn finds_known_vendors() {
        assert_eq!(lookup("b8:27:eb:11:22:33"), Some("Raspberry Pi Foundation"));
        assert_eq!(lookup("3c:22:fb:aa:bb:cc"), Some("Apple"));
        assert_eq!(lookup("24:0a:c4:00:11:22"), Some("Espressif (IoT)"));
    }

    #[test]
    fn unknown_oui_is_none() {
        assert_eq!(lookup("de:ad:be:ef:00:01"), None);
        assert_eq!(lookup("garbage"), None);
    }
}
