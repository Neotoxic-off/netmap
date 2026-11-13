//! The device model and the heuristics that guess what each device is.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::lookup::Netbios;
use crate::net::{MacAddr, Ping, Subnet};
use crate::scan::{Probe, Service, Upnp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Gateway,
    This,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Gateway,
    ThisDevice,
    Printer,
    Camera,
    Media,
    Phone,
    Server,
    Computer,
    Iot,
    Unknown,
}

impl fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Gateway => "Router",
            Self::ThisDevice => "This device",
            Self::Printer => "Printer",
            Self::Camera => "Camera",
            Self::Media => "Media",
            Self::Phone => "Phone",
            Self::Server => "Server",
            Self::Computer => "Computer",
            Self::Iot => "IoT device",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: Ipv4Addr,
    /// The network the device was found on.
    pub subnet: Subnet,
    pub role: Role,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub upnp: Option<Upnp>,
    pub ping: Option<Ping>,
    /// Its Windows-style name and workgroup, when it answers NetBIOS.
    #[serde(default)]
    pub netbios: Option<Netbios>,
    /// The service types it advertises over mDNS (Bonjour), like `_airplay._tcp`.
    #[serde(default)]
    pub mdns: Vec<String>,
    pub probes: Vec<Probe>,
    /// The name the user gave it; it wins over every discovered name.
    #[serde(default)]
    pub label: Option<String>,
    /// Unix time of the first scan that ever saw the device.
    #[serde(default)]
    pub first_seen: u64,
    /// Unix time of the last scan that saw the device.
    pub last_seen: u64,
    /// Unix time of its last full port scan, if it ever had one.
    pub ports_scanned: Option<u64>,
    /// What the latest scan says about it. Never saved: a device loaded from disk is unconfirmed.
    #[serde(skip)]
    pub presence: Presence,
}

/// Whether a device is there, as far as the latest scan knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Presence {
    /// Not confirmed yet, or confirmed and still waiting for its full port scan.
    #[default]
    Checking,
    Online,
    Offline,
}

/// What a ping reply's TTL says about the system that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    UnixLike,
    Windows,
    NetworkGear,
}

impl OsFamily {
    /// Systems start their TTL at 64 (Linux, macOS, Android, iOS), 128 (Windows)
    /// or 255 (routers, switches, printers), and a LAN reply loses none on the way.
    pub const fn from_ttl(ttl: u8) -> Self {
        match ttl {
            0..=64 => Self::UnixLike,
            65..=128 => Self::Windows,
            129..=255 => Self::NetworkGear,
        }
    }
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::UnixLike => "Unix",
            Self::Windows => "Windows",
            Self::NetworkGear => "Network equipment",
        })
    }
}

impl Device {
    pub fn is_online(&self) -> bool {
        self.presence == Presence::Online
    }

    /// Whether two sightings are the same machine: by MAC when both have one (addresses
    /// change with DHCP), by address otherwise.
    pub fn same_device(&self, other: &Self) -> bool {
        self.subnet == other.subnet
            && match (self.mac, other.mac) {
                (Some(mine), Some(theirs)) => mine == theirs,
                _ => self.ip == other.ip,
            }
    }

    /// A guess, only for devices that answer ping.
    pub fn os_family(&self) -> Option<OsFamily> {
        self.ping.map(|ping| OsFamily::from_ttl(ping.ttl))
    }

    /// Best human name available, from most to least specific.
    pub fn name(&self) -> &str {
        let advertised = self
            .upnp
            .as_ref()
            .and_then(|upnp| upnp.friendly_name.as_deref());
        self.label
            .as_deref()
            .or(advertised)
            .or(self.hostname.as_deref())
            .or(self
                .netbios
                .as_ref()
                .and_then(|netbios| netbios.name.as_deref()))
            .or(self.vendor.as_deref())
            .unwrap_or("Unknown device")
    }

    pub fn kind(&self) -> DeviceKind {
        let upnp_server = self.upnp.as_ref().and_then(|upnp| upnp.server.as_deref());
        let advertised = (!self.mdns.is_empty()).then(|| self.mdns.join(" "));
        let windows = (self.os_family() == Some(OsFamily::Windows)).then_some("windows");
        let hints = [
            Some(self.name()),
            self.hostname.as_deref(),
            self.vendor.as_deref(),
            upnp_server,
            advertised.as_deref(),
            windows,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
        let randomized_mac = self.mac.is_some_and(MacAddr::is_randomized);
        let services: Vec<Service> = self.probes.iter().filter_map(Probe::service).collect();
        classify(self.role, &services, &hints, randomized_mac)
    }
}

/// First matching rule wins, so rules go from most to least telling.
fn classify(role: Role, services: &[Service], hints: &str, randomized_mac: bool) -> DeviceKind {
    let serves = |wanted: &[Service]| wanted.iter().any(|service| services.contains(service));
    let hinted = |words: &[&str]| words.iter().any(|word| hints.contains(word));

    match role {
        Role::Gateway => DeviceKind::Gateway,
        Role::This => DeviceKind::ThisDevice,
        Role::Peer
            if serves(&[Service::JetDirect, Service::Ipp])
                || hinted(&["print", "_ipp", "_pdl-datastream"]) =>
        {
            DeviceKind::Printer
        }
        Role::Peer if serves(&[Service::Rtsp]) || hinted(&["camera", "hikvision", "dahua"]) => {
            DeviceKind::Camera
        }
        Role::Peer
            if serves(&[Service::Cast])
                || hinted(&[
                    "tv",
                    "chromecast",
                    "roku",
                    "sonos",
                    "dlna",
                    "_googlecast",
                    "_airplay",
                    "_raop",
                ]) =>
        {
            DeviceKind::Media
        }
        Role::Peer
            if serves(&[Service::AppleSync])
                || randomized_mac
                || hinted(&["iphone", "ipad", "android", "galaxy", "pixel"]) =>
        {
            DeviceKind::Phone
        }
        Role::Peer if serves(&[Service::Rdp]) => DeviceKind::Computer,
        Role::Peer if serves(&[Service::Ssh, Service::Plex, Service::Ftp, Service::Dns]) => {
            DeviceKind::Server
        }
        Role::Peer if serves(&[Service::Smb, Service::Vnc]) || hinted(&["windows"]) => {
            DeviceKind::Computer
        }
        Role::Peer
            if serves(&[
                Service::Mqtt,
                Service::Http,
                Service::Https,
                Service::Telnet,
            ]) || hinted(&["espressif", "tuya", "shelly", "_hap", "_matter"]) =>
        {
            DeviceKind::Iot
        }
        Role::Peer => DeviceKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(role: Role) -> Device {
        Device {
            ip: Ipv4Addr::new(192, 168, 1, 9),
            role,
            subnet: Subnet::new(Ipv4Addr::new(192, 168, 1, 9), 24),
            ping: None,
            netbios: None,
            mdns: Vec::new(),
            label: None,
            first_seen: 0,
            last_seen: 0,
            ports_scanned: None,
            presence: Presence::Online,
            mac: None,
            hostname: None,
            vendor: None,
            upnp: None,
            probes: Vec::new(),
        }
    }

    #[test]
    fn names_fall_back_from_most_to_least_specific() {
        let mut device = bare(Role::Peer);
        assert_eq!(device.name(), "Unknown device");
        device.vendor = Some("Espressif Inc.".to_owned());
        assert_eq!(device.name(), "Espressif Inc.");
        device.hostname = Some("plug.lan".to_owned());
        assert_eq!(device.name(), "plug.lan");
        device.upnp = Some(Upnp {
            friendly_name: Some("Desk plug".to_owned()),
            ..Upnp::default()
        });
        assert_eq!(device.name(), "Desk plug");
        device.label = Some("Office lamp".to_owned());
        assert_eq!(device.name(), "Office lamp", "the user's own name wins");
    }

    #[test]
    fn kind_uses_every_clue_a_device_gives() {
        let mut device = bare(Role::Peer);
        assert_eq!(device.kind(), DeviceKind::Unknown);
        device.vendor = Some("Espressif Inc.".to_owned());
        assert_eq!(device.kind(), DeviceKind::Iot);
        device.probes = vec![
            Probe {
                port: 3389,
                banner: None,
            },
            Probe {
                port: 4444,
                banner: None,
            },
        ];
        assert_eq!(device.kind(), DeviceKind::Computer);
        device.upnp = Some(Upnp {
            server: Some("Roku/9.4 UPnP/1.0".to_owned()),
            ..Upnp::default()
        });
        assert_eq!(device.kind(), DeviceKind::Media);
        device.mac = "02:00:00:00:00:01".parse().ok();
        device.upnp = None;
        device.probes.clear();
        device.vendor = None;
        assert_eq!(device.kind(), DeviceKind::Phone);
        assert_eq!(bare(Role::This).kind(), DeviceKind::ThisDevice);
    }

    #[test]
    fn recognises_a_device_across_scans() {
        let mut before = bare(Role::Peer);
        let mut after = bare(Role::Peer);
        assert!(before.same_device(&after), "same address, no MAC known");
        after.ip = Ipv4Addr::new(192, 168, 1, 77);
        assert!(!before.same_device(&after));
        before.mac = "00:00:0c:12:34:56".parse().ok();
        after.mac = before.mac;
        assert!(
            before.same_device(&after),
            "DHCP moved it, the MAC did not change"
        );
        after.mac = "00:00:0c:65:43:21".parse().ok();
        after.ip = before.ip;
        assert!(
            !before.same_device(&after),
            "another machine took the address"
        );
        after.mac = before.mac;
        after.subnet = Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 24);
        assert!(
            !before.same_device(&after),
            "networks are mapped separately"
        );
    }

    #[test]
    fn name_services_name_and_classify_devices() {
        let mut device = bare(Role::Peer);
        device.netbios = Some(Netbios {
            name: Some("OFFICE-PC".to_owned()),
            workgroup: None,
        });
        device.vendor = Some("Acme".to_owned());
        assert_eq!(
            device.name(),
            "OFFICE-PC",
            "a NetBIOS name beats the vendor"
        );
        device.hostname = Some("office.lan".to_owned());
        assert_eq!(device.name(), "office.lan", "but not a DNS name");

        let advertising = |services: &[&str]| {
            let mut device = bare(Role::Peer);
            device.mdns = services
                .iter()
                .map(|service| (*service).to_owned())
                .collect();
            device.kind()
        };
        assert_eq!(
            advertising(&["_ipp._tcp", "_http._tcp"]),
            DeviceKind::Printer
        );
        assert_eq!(advertising(&["_googlecast._tcp"]), DeviceKind::Media);
        assert_eq!(advertising(&["_hap._tcp"]), DeviceKind::Iot);
        assert_eq!(advertising(&["_workstation._tcp"]), DeviceKind::Unknown);
    }

    #[test]
    fn only_a_confirmed_device_is_online() {
        let mut device = bare(Role::Peer);
        assert!(device.is_online());
        for presence in [Presence::Offline, Presence::Checking, Presence::default()] {
            device.presence = presence;
            assert!(!device.is_online());
        }
    }

    #[test]
    fn ping_ttl_reveals_the_os_family() {
        let families = [
            (64, OsFamily::UnixLike),
            (128, OsFamily::Windows),
            (255, OsFamily::NetworkGear),
        ];
        for (ttl, family) in families {
            assert_eq!(OsFamily::from_ttl(ttl), family);
        }
        assert_eq!(
            OsFamily::from_ttl(57),
            OsFamily::UnixLike,
            "a few hops away still counts"
        );
        let labels = families.map(|(_, family)| family.to_string());
        assert_eq!(labels, ["Unix", "Windows", "Network equipment"]);

        let mut device = bare(Role::Peer);
        assert_eq!(device.os_family(), None);
        device.ping = Some(Ping {
            ttl: 128,
            latency_ms: 2.0,
        });
        assert_eq!(device.os_family(), Some(OsFamily::Windows));
        assert_eq!(
            device.kind(),
            DeviceKind::Computer,
            "a silent Windows machine is still a computer"
        );
    }

    #[test]
    fn kinds_have_distinct_padded_labels() {
        let kinds = [
            DeviceKind::Gateway,
            DeviceKind::ThisDevice,
            DeviceKind::Printer,
            DeviceKind::Camera,
            DeviceKind::Media,
            DeviceKind::Phone,
            DeviceKind::Server,
            DeviceKind::Computer,
            DeviceKind::Iot,
            DeviceKind::Unknown,
        ];
        let mut labels: Vec<String> = kinds.iter().map(DeviceKind::to_string).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), kinds.len());
        assert_eq!(format!("{:<8}|", DeviceKind::Phone), "Phone   |");
    }

    #[test]
    fn classifies_by_role_services_and_hints() {
        let peer = |services: &[Service], hints: &str| classify(Role::Peer, services, hints, false);

        assert_eq!(
            classify(Role::Gateway, &[Service::Ipp], "", false),
            DeviceKind::Gateway
        );
        assert_eq!(
            peer(&[Service::Http, Service::JetDirect], ""),
            DeviceKind::Printer
        );
        assert_eq!(
            peer(&[Service::Rtsp, Service::Http], ""),
            DeviceKind::Camera
        );
        assert_eq!(peer(&[], "linux upnp/1.0 sonos/70"), DeviceKind::Media);
        assert_eq!(classify(Role::Peer, &[], "", true), DeviceKind::Phone);
        assert_eq!(
            peer(&[Service::Smb, Service::Rdp], ""),
            DeviceKind::Computer
        );
        assert_eq!(peer(&[Service::Ssh, Service::Smb], ""), DeviceKind::Server);
        assert_eq!(peer(&[Service::Http], ""), DeviceKind::Iot);
        assert_eq!(peer(&[], "hp laserjet printer"), DeviceKind::Printer);
        assert_eq!(peer(&[], "hikvision"), DeviceKind::Camera);
        assert_eq!(peer(&[Service::Cast], ""), DeviceKind::Media);
        assert_eq!(peer(&[Service::AppleSync], ""), DeviceKind::Phone);
        assert_eq!(peer(&[], "galaxy-s24"), DeviceKind::Phone);
        assert_eq!(peer(&[Service::Vnc], ""), DeviceKind::Computer);
        assert_eq!(peer(&[], "shelly plug"), DeviceKind::Iot);
        assert_eq!(classify(Role::This, &[], "", false), DeviceKind::ThisDevice);
        assert_eq!(peer(&[], ""), DeviceKind::Unknown);
    }
}
