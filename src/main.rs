//! netmap: scans the local networks, identifies their devices and maps them in a terminal UI.

mod cache;
mod device;
mod lookup;
mod net;
mod report;
mod scan;
mod tui;

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::thread;

use mac_oui::Oui;

use crate::device::{Device, Presence, Role};
use crate::lookup::Netbios;
use crate::net::{Interface, MacAddr, Ping};
use crate::scan::{Probe, Upnp};

/// How long a full port scan of a device stays good enough not to redo it.
const PORTS_FRESH_FOR: u64 = 24 * 60 * 60;

/// Raw results of one discovery pass, keyed by address.
#[derive(Default)]
struct Findings {
    arp: HashMap<Ipv4Addr, MacAddr>,
    probes: HashMap<Ipv4Addr, Vec<Probe>>,
    upnp: HashMap<Ipv4Addr, Upnp>,
    hostnames: HashMap<Ipv4Addr, String>,
    pings: HashMap<Ipv4Addr, Ping>,
    netbios: HashMap<Ipv4Addr, Netbios>,
    mdns: HashMap<Ipv4Addr, Vec<String>>,
}

/// How thorough one scan should be.
#[derive(Clone)]
struct Plan {
    /// The ports of the full scan.
    ports: RangeInclusive<u16>,
    /// Redo the full port scan of every device, however recent the last one.
    force: bool,
    now: u64,
}

impl Plan {
    /// Only devices that are there, and new or not fully scanned for a while, are worth it.
    fn needs_port_scan(&self, device: &Device) -> bool {
        let stale = |at: u64| self.now.saturating_sub(at) > PORTS_FRESH_FOR;
        device.is_online() && (self.force || device.ports_scanned.is_none_or(stale))
    }
}

fn main() -> io::Result<()> {
    let interfaces = net::interfaces()?;
    if interfaces.is_empty() {
        return Err(io::Error::other(
            "this machine is not connected to any IPv4 network",
        ));
    }
    let known = cache::path()
        .map(|path| cache::load(&path))
        .unwrap_or_default();
    tui::run(interfaces, known, scan_everything, remember)
}

/// The scan the UI runs: every TCP port of whatever needs it.
fn scan_everything(
    interfaces: &[Interface],
    known: &[Device],
    force: bool,
    report: &dyn Fn(Vec<Device>),
) -> Result<(), String> {
    let plan = Plan {
        ports: 1..=u16::MAX,
        force,
        now: cache::now(),
    };
    discover(interfaces, known, &plan, report)
}

/// Saves what the UI knows for the next start. Best effort: the map works the same without it.
fn remember(devices: &[Device]) {
    if let Some(path) = cache::path() {
        let _ = cache::save(&path, devices);
    }
}

/// One scan of every network we are on, reported twice: as soon as the devices are known,
/// then again once the ones that need it have had their full port scan.
fn discover(
    interfaces: &[Interface],
    known: &[Device],
    plan: &Plan,
    report: &dyn Fn(Vec<Device>),
) -> Result<(), String> {
    let vendors = Oui::default()?;
    let (probes, upnp, mdns) = thread::scope(|scope| {
        let searches: Vec<_> = interfaces
            .iter()
            .map(|interface| scope.spawn(|| scan::discover_upnp(interface.ip).unwrap_or_default()))
            .collect();
        let browses: Vec<_> = interfaces
            .iter()
            .map(|interface| {
                scope.spawn(|| lookup::discover_mdns(interface.ip).unwrap_or_default())
            })
            .collect();
        // One network at a time: each scan already runs a thread per host.
        let probes: HashMap<Ipv4Addr, Vec<Probe>> = interfaces
            .iter()
            .flat_map(|interface| scan::scan_services(interface.subnet))
            .collect();
        let upnp: HashMap<Ipv4Addr, Upnp> = searches
            .into_iter()
            .flat_map(|search| search.join().expect("UPnP discovery panicked"))
            .collect();
        let mdns: HashMap<Ipv4Addr, Vec<String>> = browses
            .into_iter()
            .flat_map(|browse| browse.join().expect("mDNS browsing panicked"))
            .collect();
        (probes, upnp, mdns)
    });
    // Read after the scan: probing is what fills the ARP table.
    let arp = net::arp_table();
    let seen = arp
        .keys()
        .chain(probes.keys())
        .chain(upnp.keys())
        .chain(mdns.keys());
    let addresses = addresses(interfaces, seen);
    let findings = Findings {
        hostnames: our_names(
            scan::hostnames(&addresses),
            interfaces,
            scan::own_hostname(),
        ),
        pings: ask_all(&addresses, net::ping),
        netbios: ask_all(&addresses, lookup::netbios),
        arp,
        probes,
        upnp,
        mdns,
    };
    let gateways = net::gateways(interfaces);
    let found = assemble(
        addresses, interfaces, &gateways, findings, &vendors, plan.now,
    );
    let mut devices = recall(found, known, interfaces, plan);
    report(devices.clone());

    let hosts: Vec<Ipv4Addr> = devices
        .iter()
        .filter(|device| device.presence == Presence::Checking)
        .map(|device| device.ip)
        .collect();
    if !hosts.is_empty() {
        let all_ports = scan::scan_ports(&hosts, plan.ports.clone());
        merge_ports(&mut devices, all_ports, plan.now);
    }
    report(devices);
    Ok(())
}

/// Our own addresses resolve through the hosts file, which tools like Docker rewrite
/// (`host.docker.internal`): the name the OS gives itself is the right one.
fn our_names(
    mut hostnames: HashMap<Ipv4Addr, String>,
    interfaces: &[Interface],
    own: Option<String>,
) -> HashMap<Ipv4Addr, String> {
    if let Some(name) = own {
        hostnames.extend(
            interfaces
                .iter()
                .map(|interface| (interface.ip, name.clone())),
        );
    }
    hostnames
}

/// Asks every address the same question at once; the ones with no answer are left out.
fn ask_all<T: Send>(
    addresses: &BTreeSet<Ipv4Addr>,
    ask: fn(Ipv4Addr) -> Option<T>,
) -> HashMap<Ipv4Addr, T> {
    thread::scope(|scope| {
        let questions: Vec<_> = addresses
            .iter()
            .map(|&ip| (ip, scope.spawn(move || ask(ip))))
            .collect();
        questions
            .into_iter()
            .filter_map(|(ip, question)| Some((ip, question.join().expect("a lookup panicked")?)))
            .collect()
    })
}

/// Every address seen on one of our networks, plus our own.
fn addresses<'a>(
    interfaces: &[Interface],
    seen: impl Iterator<Item = &'a Ipv4Addr>,
) -> BTreeSet<Ipv4Addr> {
    seen.copied()
        .filter(|ip| {
            interfaces
                .iter()
                .any(|interface| interface.subnet.contains(*ip))
        })
        .chain(interfaces.iter().map(|interface| interface.ip))
        .collect()
}

/// Turns raw findings into devices, all online and none fully scanned yet.
fn assemble(
    addresses: BTreeSet<Ipv4Addr>,
    interfaces: &[Interface],
    gateways: &[Ipv4Addr],
    mut findings: Findings,
    vendors: &Oui,
    now: u64,
) -> Vec<Device> {
    let mut devices: Vec<Device> = addresses
        .into_iter()
        .filter_map(|ip| {
            let ours = interfaces
                .iter()
                .find(|interface| interface.subnet.contains(ip))?;
            let mac = findings.arp.get(&ip).copied();
            Some(Device {
                ip,
                subnet: ours.subnet,
                role: match ip {
                    _ if interfaces.iter().any(|interface| interface.ip == ip) => Role::This,
                    _ if gateways.contains(&ip) => Role::Gateway,
                    _ => Role::Peer,
                },
                mac,
                hostname: findings.hostnames.remove(&ip),
                vendor: mac.and_then(|mac| vendor(vendors, mac)),
                upnp: findings.upnp.remove(&ip),
                ping: findings.pings.remove(&ip),
                probes: findings.probes.remove(&ip).unwrap_or_default(),
                netbios: findings.netbios.remove(&ip),
                mdns: findings.mdns.remove(&ip).unwrap_or_default(),
                label: None,
                first_seen: now,
                last_seen: now,
                ports_scanned: None,
                presence: Presence::Online,
            })
        })
        .collect();
    sort(&mut devices);
    devices
}

/// Devices come grouped by network, gateway first, then by address.
fn sort(devices: &mut [Device]) {
    devices.sort_by_key(|device| (device.subnet, device.role != Role::Gateway, device.ip));
}

/// Completes what was just found with what earlier scans learned: facts a device did not
/// repeat this time, its ports when their scan is still fresh, and the devices that are
/// away right now (kept, offline, while we are still on their network).
fn recall(
    mut found: Vec<Device>,
    known: &[Device],
    interfaces: &[Interface],
    plan: &Plan,
) -> Vec<Device> {
    for device in &mut found {
        let Some(past) = known.iter().find(|past| past.same_device(device)) else {
            continue;
        };
        device.ports_scanned = past.ports_scanned;
        device.first_seen = past.first_seen;
        device.label.clone_from(&past.label);
        device.hostname = device.hostname.take().or_else(|| past.hostname.clone());
        device.upnp = device.upnp.take().or_else(|| past.upnp.clone());
        device.netbios = device.netbios.take().or_else(|| past.netbios.clone());
        if device.mdns.is_empty() {
            device.mdns.clone_from(&past.mdns);
        }
        if !plan.needs_port_scan(device) {
            add_ports(device, past.probes.clone());
        }
    }
    let away: Vec<Device> = known
        .iter()
        .filter(|past| {
            interfaces
                .iter()
                .any(|interface| interface.subnet == past.subnet)
        })
        .filter(|past| !found.iter().any(|device| device.same_device(past)))
        .map(|past| Device {
            presence: Presence::Offline,
            ping: None,
            ..past.clone()
        })
        .collect();
    // Whoever still needs its full port scan stays "checking" until that scan is done.
    for device in &mut found {
        if plan.needs_port_scan(device) {
            device.presence = Presence::Checking;
        }
    }
    found.extend(away);
    sort(&mut found);
    found
}

/// Gives the devices that were waiting for their full scan their ports, and marks them done. The quick scan waits longer per port,
/// so anything only it caught is kept.
fn merge_ports(devices: &mut [Device], mut all_ports: HashMap<Ipv4Addr, Vec<Probe>>, now: u64) {
    for device in devices
        .iter_mut()
        .filter(|device| device.presence == Presence::Checking)
    {
        add_ports(device, all_ports.remove(&device.ip).unwrap_or_default());
        device.ports_scanned = Some(now);
        device.presence = Presence::Online;
    }
}

/// Adds the ports the device does not list yet.
fn add_ports(device: &mut Device, ports: Vec<Probe>) {
    let known: Vec<u16> = device.probes.iter().map(|probe| probe.port).collect();
    device.probes.extend(
        ports
            .into_iter()
            .filter(|probe| !known.contains(&probe.port)),
    );
    device.probes.sort_by_key(|probe| probe.port);
}

fn vendor(vendors: &Oui, mac: MacAddr) -> Option<String> {
    let entry = vendors.lookup_by_mac(&mac.to_string()).ok()??;
    Some(entry.company_name.clone())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::net::Subnet;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 254);
    const NAS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 7);
    const ME_VIRTUAL: Ipv4Addr = Ipv4Addr::new(172, 20, 0, 1);
    const VM: Ipv4Addr = Ipv4Addr::new(172, 20, 5, 9);
    const NOW: u64 = 1_700_000_000;

    fn lan() -> Interface {
        Interface {
            ip: ME,
            subnet: Subnet::new(ME, 24),
        }
    }

    fn virtual_network() -> Interface {
        Interface {
            ip: ME_VIRTUAL,
            subnet: Subnet::new(ME_VIRTUAL, 20),
        }
    }

    fn plan(force: bool) -> Plan {
        Plan {
            ports: 1..=1,
            force,
            now: NOW,
        }
    }

    fn open(ports: &[u16]) -> Vec<Probe> {
        ports
            .iter()
            .map(|&port| Probe { port, banner: None })
            .collect()
    }

    fn ports(device: &Device) -> Vec<u16> {
        device.probes.iter().map(|probe| probe.port).collect()
    }

    /// The devices a scan of the home LAN finds at `NOW`, each with the given quick-scan ports.
    fn found(hosts: &[(Ipv4Addr, &[u16])]) -> Vec<Device> {
        let vendors = Oui::default().unwrap();
        let probes = hosts.iter().map(|(ip, ports)| (*ip, open(ports))).collect();
        let findings = Findings {
            probes,
            ..Findings::default()
        };
        let seen = hosts.iter().map(|(ip, _)| *ip).collect();
        assemble(seen, &[lan()], &[ROUTER], findings, &vendors, NOW)
    }

    /// Runs the real discovery on the smallest network this machine is on, with a one-port full scan.
    #[test]
    fn discovers_a_real_network_and_reports_twice() {
        let interfaces = net::interfaces().unwrap();
        let smallest = interfaces
            .into_iter()
            .min_by_key(|interface| interface.subnet.hosts().count());
        let Some(interface) = smallest else { return }; // Offline: nothing to discover.
        let reports = RefCell::new(Vec::new());
        let collect = |devices| reports.borrow_mut().push(devices);
        discover(&[interface], &[], &plan(false), &collect).unwrap();

        // A second run remembers the first: nothing is new, so no port needs scanning again.
        let first = reports.borrow().last().cloned().unwrap();
        discover(&[interface], &first, &plan(false), &collect).unwrap();

        let reports = reports.into_inner();
        assert_eq!(reports.len(), 4);
        for devices in &reports {
            let ours: Vec<&Device> = devices
                .iter()
                .filter(|device| device.role == Role::This)
                .collect();
            assert_eq!(
                ours.iter().map(|device| device.ip).collect::<Vec<_>>(),
                [interface.ip]
            );
            assert!(devices
                .iter()
                .all(|device| device.subnet == interface.subnet));
            assert_eq!(
                ours[0].hostname,
                scan::own_hostname(),
                "named by the OS, not the hosts file"
            );
        }
        assert!(reports[1]
            .iter()
            .all(|device| device.ports_scanned == Some(NOW)));
        assert!(
            reports[0].len() <= reports[3].len(),
            "known devices are never forgotten"
        );
    }

    #[test]
    fn our_own_addresses_carry_our_real_name() {
        let resolved = || {
            HashMap::from([
                (ME, "host.docker.internal".to_owned()),
                (NAS, "nas.lan".to_owned()),
            ])
        };
        let interfaces = [lan(), virtual_network()];
        let named = our_names(resolved(), &interfaces, Some("DESKTOP-ABC".to_owned()));
        assert_eq!(
            named[&ME], "DESKTOP-ABC",
            "the hosts file does not get to rename us"
        );
        assert_eq!(
            (named[&ME_VIRTUAL].as_str(), named[&NAS].as_str()),
            ("DESKTOP-ABC", "nas.lan")
        );
        assert_eq!(
            our_names(resolved(), &interfaces, None),
            resolved(),
            "no name known: left as is"
        );
    }

    #[test]
    fn lookups_keep_only_the_addresses_that_answer() {
        // 192.0.2.0/24 is reserved for documentation: nothing there answers.
        let silent = Ipv4Addr::new(192, 0, 2, 1);
        assert!(ask_all(&BTreeSet::from([silent]), net::ping).is_empty());
        let even_hosts = |ip: Ipv4Addr| ip.octets()[3].is_multiple_of(2).then_some(ip.octets()[3]);
        let answers = ask_all(&BTreeSet::from([NAS, ME, ROUTER]), even_hosts);
        assert_eq!(answers, HashMap::from([(ME, 20), (ROUTER, 254)]));
    }

    #[test]
    fn keeps_addresses_of_our_networks_and_always_ourselves() {
        let seen = [NAS, Ipv4Addr::new(10, 0, 0, 1), VM, NAS];
        let found = addresses(&[lan(), virtual_network()], seen.iter());
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            [ME_VIRTUAL, VM, NAS, ME]
        );
    }

    #[test]
    fn assembles_devices_per_network_gateway_first() {
        let cisco: MacAddr = "00:00:0c:12:34:56".parse().unwrap();
        let echo = Ping {
            ttl: 64,
            latency_ms: 1.5,
        };
        let findings = Findings {
            arp: HashMap::from([(ROUTER, cisco)]),
            probes: HashMap::from([(NAS, open(&[22]))]),
            upnp: HashMap::from([(ROUTER, Upnp::default())]),
            hostnames: HashMap::from([(NAS, "nas.lan".to_owned())]),
            pings: HashMap::from([(NAS, echo)]),
            netbios: HashMap::from([(
                NAS,
                Netbios {
                    name: Some("NAS".to_owned()),
                    workgroup: None,
                },
            )]),
            mdns: HashMap::from([(NAS, vec!["_smb._tcp".to_owned()])]),
        };
        let vendors = Oui::default().unwrap();
        let interfaces = [lan(), virtual_network()];
        let stray = Ipv4Addr::new(10, 0, 0, 1);
        let seen = BTreeSet::from([NAS, ME, ROUTER, VM, ME_VIRTUAL, stray]);
        let devices = assemble(seen, &interfaces, &[ROUTER], findings, &vendors, NOW);

        let summary: Vec<(Ipv4Addr, Role)> = devices
            .iter()
            .map(|device| (device.ip, device.role))
            .collect();
        let expected = [
            (ME_VIRTUAL, Role::This),
            (VM, Role::Peer),
            (ROUTER, Role::Gateway),
            (NAS, Role::Peer),
            (ME, Role::This),
        ];
        assert_eq!(
            summary, expected,
            "addresses outside our networks are dropped"
        );
        assert_eq!(devices[1].subnet, virtual_network().subnet);
        let (router, nas) = (&devices[2], &devices[3]);
        assert!(router
            .vendor
            .as_deref()
            .is_some_and(|vendor| vendor.contains("Cisco")));
        assert!(router.upnp.is_some() && router.mac == Some(cisco));
        assert_eq!(
            (nas.hostname.as_deref(), ports(nas), nas.mac),
            (Some("nas.lan"), vec![22], None)
        );
        assert_eq!((nas.ping, nas.subnet), (Some(echo), lan().subnet));
        assert!(devices
            .iter()
            .all(|device| device.is_online() && device.last_seen == NOW));
        assert!(devices.iter().all(|device| device.ports_scanned.is_none()));
    }

    #[test]
    fn unknown_vendor_prefixes_resolve_to_nothing() {
        let vendors = Oui::default().unwrap();
        assert_eq!(vendor(&vendors, "02:00:00:00:00:01".parse().unwrap()), None);
    }

    #[test]
    fn only_new_or_stale_devices_need_a_port_scan() {
        let mut device = found(&[(NAS, &[])]).remove(0);
        assert!(plan(false).needs_port_scan(&device), "never scanned");
        device.ports_scanned = Some(NOW - PORTS_FRESH_FOR);
        assert!(
            !plan(false).needs_port_scan(&device),
            "scanned within the day"
        );
        assert!(
            plan(true).needs_port_scan(&device),
            "unless a full rescan is asked for"
        );
        device.ports_scanned = Some(NOW - PORTS_FRESH_FOR - 1);
        assert!(plan(false).needs_port_scan(&device), "scanned too long ago");
        device.presence = Presence::Offline;
        assert!(
            !plan(true).needs_port_scan(&device),
            "a device that is away cannot be scanned"
        );
    }

    #[test]
    fn recalls_what_earlier_scans_learned() {
        let mut past_nas = found(&[(NAS, &[22, 8080])]).remove(0);
        past_nas.ports_scanned = Some(NOW - 60);
        past_nas.first_seen = NOW - 2_592_000;
        past_nas.label = Some("Media box".to_owned());
        past_nas.hostname = Some("nas.lan".to_owned());
        past_nas.upnp = Some(Upnp::default());
        past_nas.netbios = Some(Netbios {
            name: Some("NAS".to_owned()),
            workgroup: None,
        });
        past_nas.mdns = vec!["_smb._tcp".to_owned()];
        let mut past_printer = found(&[(Ipv4Addr::new(192, 168, 1, 30), &[631])]).remove(0);
        past_printer.last_seen = NOW - 3_600;
        past_printer.ping = Some(Ping {
            ttl: 255,
            latency_ms: 4.0,
        });
        let mut elsewhere = past_printer.clone();
        elsewhere.subnet = virtual_network().subnet;
        let known = [past_nas, past_printer, elsewhere];

        let devices = recall(
            found(&[(NAS, &[445]), (ME, &[])]),
            &known,
            &[lan()],
            &plan(false),
        );
        let (nas, me, printer) = (&devices[0], &devices[1], &devices[2]);
        assert_eq!(devices.len(), 3, "devices of networks we left are dropped");
        assert_eq!(ports(nas), [22, 445, 8080], "a fresh port scan is reused");
        assert_eq!(
            (nas.ports_scanned, nas.hostname.as_deref()),
            (Some(NOW - 60), Some("nas.lan"))
        );
        assert!(nas.upnp.is_some() && nas.is_online());
        assert_eq!(
            (nas.first_seen, nas.name()),
            (NOW - 2_592_000, "Media box"),
            "known for a month"
        );
        assert_eq!(me.first_seen, NOW, "never seen before");
        assert!(
            nas.netbios.is_some() && nas.mdns == ["_smb._tcp"],
            "silent this time, remembered"
        );
        assert_eq!((me.ports_scanned, me.presence), (None, Presence::Checking));
        assert_eq!(
            (printer.presence, printer.ping, printer.last_seen),
            (Presence::Offline, None, NOW - 3_600)
        );
        assert_eq!(ports(printer), [631]);

        let forced = recall(found(&[(NAS, &[445])]), &known, &[lan()], &plan(true));
        assert_eq!(
            ports(&forced[0]),
            [445],
            "a full rescan starts from what is open now"
        );
    }

    #[test]
    fn merges_full_scan_ports_into_the_scanned_devices_only() {
        let mut devices = found(&[(NAS, &[445, 22]), (ME, &[])]);
        let fresh = HashMap::from([(NAS, open(&[22, 8080])), (ME, open(&[135]))]);
        devices[0].presence = Presence::Checking;
        merge_ports(&mut devices, fresh, NOW);
        assert!(
            devices.iter().all(Device::is_online),
            "scanned or not, both are there"
        );
        assert_eq!(
            (ports(&devices[0]), devices[0].ports_scanned),
            (vec![22, 445, 8080], Some(NOW))
        );
        assert_eq!(
            (ports(&devices[1]), devices[1].ports_scanned),
            (vec![], None)
        );
    }
}
