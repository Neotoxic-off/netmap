//! A Markdown report of everything known about the mapped networks.

use crate::device::{Device, Presence};
use crate::lookup::Netbios;
use crate::net::Interface;
use crate::scan;

const SECONDS_PER_DAY: u64 = 86_400;

/// `netmap-report-20261113-154800.md`: sortable, and never overwrites an earlier report.
pub fn file_name(now: u64) -> String {
    let stamp: String = date_time(now)
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    format!("netmap-report-{}-{}.md", &stamp[..8], &stamp[8..])
}

pub fn render(interfaces: &[Interface], devices: &[Device], now: u64) -> String {
    let online = devices.iter().filter(|device| device.is_online()).count();
    let mut lines = vec![
        "# Network report".to_owned(),
        String::new(),
        format!(
            "Generated {} UTC. {} devices ({online} online) on {} networks.",
            date_time(now),
            devices.len(),
            interfaces.len(),
        ),
    ];
    for interface in interfaces {
        let members: Vec<&Device> = devices
            .iter()
            .filter(|device| device.subnet == interface.subnet)
            .collect();
        lines.extend([
            String::new(),
            format!("## Network {}", interface.subnet),
            String::new(),
            format!(
                "This machine: {}. Devices: {}.",
                interface.ip,
                members.len()
            ),
            String::new(),
            "| Name | IP | MAC | Vendor | Type | OS | Status |".to_owned(),
            "|---|---|---|---|---|---|---|".to_owned(),
        ]);
        lines.extend(members.iter().map(|device| summary_row(device)));
        lines.extend(members.iter().flat_map(|device| device_section(device)));
    }
    lines.join("\n") + "\n"
}

fn summary_row(device: &Device) -> String {
    let cells = [
        text(device.name()),
        device.ip.to_string(),
        device.mac.map(|mac| mac.to_string()).unwrap_or_default(),
        text(device.vendor.as_deref().unwrap_or_default()),
        device.kind().to_string(),
        device
            .os_family()
            .map(|family| family.to_string())
            .unwrap_or_default(),
        status(device).to_owned(),
    ];
    format!("| {} |", cells.join(" | "))
}

fn device_section(device: &Device) -> Vec<String> {
    let fact =
        |label: &str, value: Option<String>| value.map(|value| format!("- {label}: {value}"));
    let upnp =
        |field: fn(&scan::Upnp) -> Option<&str>| device.upnp.as_ref().and_then(field).map(text);
    let netbios =
        |field: fn(&Netbios) -> Option<&str>| device.netbios.as_ref().and_then(field).map(text);
    let advertised = (!device.mdns.is_empty()).then(|| text(&device.mdns.join(", ")));
    let randomized = device.mac.is_some_and(|mac| mac.is_randomized());
    let scanned = device
        .ports_scanned
        .map_or("never".to_owned(), |at| date_time(at) + " UTC");

    let mut lines = vec![
        String::new(),
        format!("### {} ({})", text(device.name()), device.ip),
        String::new(),
    ];
    lines.extend(
        [
            fact("Type", Some(device.kind().to_string())),
            fact(
                "Status",
                Some(format!(
                    "{}, last seen {} UTC",
                    status(device),
                    date_time(device.last_seen)
                )),
            ),
            fact("First seen", Some(date_time(device.first_seen) + " UTC")),
            fact("MAC", device.mac.map(|mac| mac.to_string())),
            fact(
                "MAC kind",
                randomized.then(|| "private, randomized".to_owned()),
            ),
            fact("Vendor", device.vendor.as_deref().map(text)),
            fact("Hostname", device.hostname.as_deref().map(text)),
            fact("NetBIOS name", netbios(|netbios| netbios.name.as_deref())),
            fact("Workgroup", netbios(|netbios| netbios.workgroup.as_deref())),
            fact("Advertised services (mDNS)", advertised),
            fact(
                "OS family",
                device
                    .os_family()
                    .map(|family| format!("{family} (guessed from ping TTL)")),
            ),
            fact(
                "Ping",
                device
                    .ping
                    .map(|ping| format!("{:.1} ms, TTL {}", ping.latency_ms, ping.ttl)),
            ),
            fact("UPnP name", upnp(|upnp| upnp.friendly_name.as_deref())),
            fact(
                "UPnP manufacturer",
                upnp(|upnp| upnp.manufacturer.as_deref()),
            ),
            fact("UPnP model", upnp(|upnp| upnp.model.as_deref())),
            fact(
                "UPnP model number",
                upnp(|upnp| upnp.model_number.as_deref()),
            ),
            fact(
                "UPnP serial number",
                upnp(|upnp| upnp.serial_number.as_deref()),
            ),
            fact("UPnP device type", upnp(|upnp| upnp.device_type.as_deref())),
            fact("UPnP server", upnp(|upnp| upnp.server.as_deref())),
            fact("Web interface", upnp(|upnp| upnp.url.as_deref())),
            fact(
                "Open TCP ports",
                Some(format!("{} (full scan: {scanned})", device.probes.len())),
            ),
        ]
        .into_iter()
        .flatten(),
    );
    lines.extend(device.probes.iter().map(|probe| {
        let name = scan::port_name(probe.port).unwrap_or("unknown service");
        let banner = probe
            .banner
            .as_deref()
            .map(|banner| format!(": {}", text(banner)));
        format!(
            "  - {}/tcp {name}{}",
            probe.port,
            banner.unwrap_or_default()
        )
    }));
    lines
}

const fn status(device: &Device) -> &'static str {
    match device.presence {
        Presence::Online => "online",
        Presence::Offline => "offline",
        Presence::Checking => "being scanned",
    }
}

/// Names and banners come from the network: keep them from breaking a table or injecting markup.
fn text(untrusted: &str) -> String {
    untrusted
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('|', "\\|")
}

/// `2026-11-13 15:48:00` in UTC, without pulling in a date library.
pub fn date_time(unix: u64) -> String {
    let (days, seconds) = (unix / SECONDS_PER_DAY, unix % SECONDS_PER_DAY);
    // Days to civil date, after Howard Hinnant's `civil_from_days`, with years starting in March.
    let shifted = days + 719_468;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60,
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::device::Role;
    use crate::net::{Ping, Subnet};
    use crate::scan::{Probe, Upnp};

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
    const NOW: u64 = 1_700_000_000;

    fn device(host: u8, role: Role) -> Device {
        let ip = Ipv4Addr::new(192, 168, 1, host);
        Device {
            ip,
            subnet: Subnet::new(ip, 24),
            role,
            mac: None,
            hostname: None,
            vendor: None,
            upnp: None,
            ping: None,
            probes: Vec::new(),
            netbios: None,
            mdns: Vec::new(),
            label: None,
            first_seen: 0,
            last_seen: NOW,
            ports_scanned: None,
            presence: Presence::Offline,
        }
    }

    #[test]
    fn formats_dates_across_leap_years() {
        assert_eq!(date_time(0), "1970-01-01 00:00:00");
        assert_eq!(date_time(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(date_time(NOW), "2023-11-14 22:13:20");
        assert_eq!(date_time(1_735_689_599), "2024-12-31 23:59:59");
        assert_eq!(file_name(NOW), "netmap-report-20231114-221320.md");
    }

    #[test]
    fn reports_every_network_and_device() {
        let mut nas = device(7, Role::Peer);
        nas.presence = Presence::Online;
        nas.mac = "02:00:00:00:00:01".parse().ok();
        nas.hostname = Some("nas|<b>".to_owned());
        nas.vendor = Some("Acme & Co".to_owned());
        nas.ping = Some(Ping {
            ttl: 64,
            latency_ms: 1.26,
        });
        nas.ports_scanned = Some(NOW);
        nas.netbios = Some(Netbios {
            name: Some("NAS".to_owned()),
            workgroup: Some("HOME".to_owned()),
        });
        nas.mdns = vec!["_smb._tcp".to_owned(), "_afpovertcp._tcp".to_owned()];
        nas.probes = vec![
            Probe {
                port: 22,
                banner: Some("SSH-2.0-OpenSSH".to_owned()),
            },
            Probe {
                port: 4444,
                banner: None,
            },
        ];
        nas.upnp = Some(Upnp {
            server: Some("Linux UPnP/1.0".to_owned()),
            friendly_name: None,
            manufacturer: Some("Initech".to_owned()),
            model: Some("DS1".to_owned()),
            model_number: Some("1.2".to_owned()),
            serial_number: Some("SN42".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:Basic:1".to_owned()),
            url: Some("http://192.168.1.7/".to_owned()),
        });
        let scanning = Device {
            presence: Presence::Checking,
            ..device(1, Role::Gateway)
        };
        let lan = Interface {
            ip: ME,
            subnet: Subnet::new(ME, 24),
        };
        let empty = Interface {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            subnet: Subnet::new(Ipv4Addr::new(10, 0, 0, 2), 24),
        };

        let report = render(&[lan, empty], &[scanning, nas, device(9, Role::Peer)], NOW);
        let expected = [
            "# Network report",
            "Generated 2023-11-14 22:13:20 UTC. 3 devices (1 online) on 2 networks.",
            "## Network 192.168.1.0/24",
            "This machine: 192.168.1.20. Devices: 3.",
            "| Unknown device | 192.168.1.1 |  |  | Router |  | being scanned |",
            "| Unknown device | 192.168.1.9 |  |  | Unknown |  | offline |",
            "| nas\\|&lt;b> | 192.168.1.7 | 02:00:00:00:00:01 | Acme &amp; Co | Phone | Unix | online |",
            "### nas\\|&lt;b> (192.168.1.7)",
            "- Status: online, last seen 2023-11-14 22:13:20 UTC",
            "- First seen: 1970-01-01 00:00:00 UTC",
            "- MAC kind: private, randomized",
            "- OS family: Unix (guessed from ping TTL)",
            "- Ping: 1.3 ms, TTL 64",
            "- NetBIOS name: NAS",
            "- Workgroup: HOME",
            "- Advertised services (mDNS): _smb._tcp, _afpovertcp._tcp",
            "- UPnP manufacturer: Initech",
            "- UPnP model: DS1",
            "- UPnP model number: 1.2",
            "- UPnP serial number: SN42",
            "- UPnP device type: urn:schemas-upnp-org:device:Basic:1",
            "- UPnP server: Linux UPnP/1.0",
            "- Web interface: http://192.168.1.7/",
            "- Open TCP ports: 2 (full scan: 2023-11-14 22:13:20 UTC)",
            "  - 22/tcp SSH: SSH-2.0-OpenSSH",
            "  - 4444/tcp unknown service",
            "- Open TCP ports: 0 (full scan: never)",
            "## Network 10.0.0.0/24",
            "This machine: 10.0.0.2. Devices: 0.",
        ];
        for line in expected {
            assert!(
                report.lines().any(|found| found == line),
                "missing line {line:?}"
            );
        }
        assert!(report.ends_with('\n'));
    }
}
