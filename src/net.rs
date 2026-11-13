//! Local network facts: our interfaces and their subnets, gateways, the ARP table and ping.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

use if_addrs::IfAddr;
use serde::{Deserialize, Serialize};

/// shortcut: networks wider than /20 are scanned only on the /20 around our address,
/// widen when huge flat LANs matter (a /16 is 65 534 hosts to probe).
const WIDEST_PREFIX: u8 = 20;
/// A /31 or /32 has no neighbours to look for.
const NARROWEST_PREFIX: u8 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Locally administered bit: phones and laptops set it when they randomize their MAC.
    pub fn is_randomized(self) -> bool {
        self.0[0] & 0b10 != 0
    }

    fn is_multicast(self) -> bool {
        self.0[0] & 0b01 != 0
    }
}

impl FromStr for MacAddr {
    type Err = ();

    /// Accepts `aa:bb:..` and `aa-bb-..`, with or without leading zeros (macOS drops them).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 6];
        let mut parts = text.split([':', '-']);
        for byte in &mut bytes {
            *byte = u8::from_str_radix(parts.next().ok_or(())?, 16).map_err(|_| ())?;
        }
        parts.next().is_none().then_some(Self(bytes)).ok_or(())
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// An IPv4 network in CIDR form. Orders by address, then by size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Subnet {
    network: u32,
    prefix: u8,
}

impl Subnet {
    /// The network of `prefix` bits that `ip` belongs to.
    pub fn new(ip: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        Self {
            network: u32::from(ip) & Self::mask(prefix),
            prefix,
        }
    }

    fn mask(prefix: u8) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix) == self.network
    }

    /// Every address a device can have: all but the network and broadcast addresses.
    pub fn hosts(self) -> impl Iterator<Item = Ipv4Addr> {
        let broadcast = self.network | !Self::mask(self.prefix);
        (self.network.saturating_add(1)..broadcast).map(Ipv4Addr::from)
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

/// One of our own addresses and the network it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    pub ip: Ipv4Addr,
    pub subnet: Subnet,
}

/// Round-trip time and remaining hop count of one ICMP echo.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ping {
    pub ttl: u8,
    pub latency_ms: f64,
}

/// Every network this machine is connected to, one entry per subnet.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut found: Vec<Interface> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| match interface.addr {
            IfAddr::V4(address) => scannable(address.ip, address.netmask),
            IfAddr::V6(_) => None,
        })
        .collect();
    found.sort_by_key(|interface| interface.subnet);
    found.dedup_by_key(|interface| interface.subnet);
    Ok(found)
}

/// Loopback, self-assigned (169.254.x.x) and point-to-point addresses have no LAN to map.
fn scannable(ip: Ipv4Addr, netmask: Ipv4Addr) -> Option<Interface> {
    let prefix = u8::try_from(u32::from(netmask).leading_ones()).ok()?;
    let has_lan = !ip.is_loopback() && !ip.is_link_local() && prefix <= NARROWEST_PREFIX;
    has_lan.then(|| Interface {
        ip,
        subnet: Subnet::new(ip, prefix.max(WIDEST_PREFIX)),
    })
}

/// The command that prints the default routes, per OS.
#[cfg(windows)]
const DEFAULT_ROUTE: (&str, &[&str]) = ("route", &["print", "0.0.0.0"]);
#[cfg(target_os = "macos")]
const DEFAULT_ROUTE: (&str, &[&str]) = ("route", &["-n", "get", "default"]);
#[cfg(not(any(windows, target_os = "macos")))]
const DEFAULT_ROUTE: (&str, &[&str]) = ("ip", &["route", "show", "default"]);

/// One echo request, one second to answer.
#[cfg(windows)]
const PING_ARGS: [&str; 4] = ["-n", "1", "-w", "1000"];
#[cfg(not(windows))]
const PING_ARGS: [&str; 4] = ["-c", "1", "-W", "1"];

/// The gateway of each interface that has one.
pub fn gateways(interfaces: &[Interface]) -> Vec<Ipv4Addr> {
    let (program, args) = DEFAULT_ROUTE;
    let routes = command_output(program, args);
    interfaces
        .iter()
        .filter_map(|interface| parse_gateway(&routes, interface.subnet, interface.ip))
        .collect()
}

/// Every neighbour the OS has resolved, on any interface.
pub fn arp_table() -> HashMap<Ipv4Addr, MacAddr> {
    parse_arp(&command_output("arp", &["-a"]))
}

pub fn ping(ip: Ipv4Addr) -> Option<Ping> {
    let target = ip.to_string();
    let mut args = PING_ARGS.to_vec();
    args.push(&target);
    parse_ping(&command_output("ping", &args))
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// The default-route line of every OS lists the gateway as its first address inside our subnet.
fn parse_gateway(routes: &str, subnet: Subnet, me: Ipv4Addr) -> Option<Ipv4Addr> {
    const DEFAULT_ROUTE_PREFIXES: [&str; 3] = ["0.0.0.0", "default", "gateway"];
    routes
        .lines()
        .map(str::trim_start)
        .filter(|line| {
            DEFAULT_ROUTE_PREFIXES
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .flat_map(str::split_whitespace)
        .filter_map(|token| token.parse::<Ipv4Addr>().ok())
        .find(|ip| subnet.contains(*ip) && *ip != me)
}

fn parse_arp(table: &str) -> HashMap<Ipv4Addr, MacAddr> {
    table
        .lines()
        .filter_map(|line| {
            let tokens = || {
                line.split_whitespace()
                    .map(|token| token.trim_matches(['(', ')']))
            };
            let ip = tokens().find_map(|token| token.parse::<Ipv4Addr>().ok())?;
            let mac = tokens().find_map(|token| token.parse::<MacAddr>().ok())?;
            (!mac.is_multicast()).then_some((ip, mac))
        })
        .collect()
}

/// Reads the reply line of `ping` in any language: only `ttl=` and `ms` are relied upon.
fn parse_ping(output: &str) -> Option<Ping> {
    let reply = output
        .lines()
        .map(str::to_lowercase)
        .find(|line| line.contains("ttl="))?;
    let (_, after_ttl) = reply.split_once("ttl=")?;
    let (before_unit, _) = reply.rsplit_once("ms")?;
    let ttl = after_ttl
        .split(|character: char| !character.is_ascii_digit())
        .next()?;
    let latency = before_unit
        .trim_end()
        .rsplit(|character: char| !(character.is_ascii_digit() || character == '.'))
        .next()?;
    Some(Ping {
        ttl: ttl.parse().ok()?,
        latency_ms: latency.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 42);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    #[test]
    fn parses_mac_formats() {
        assert_eq!(
            "AA-BB-CC-00-11-22".parse(),
            Ok(MacAddr([0xaa, 0xbb, 0xcc, 0, 0x11, 0x22]))
        );
        assert_eq!(
            "a:b:c:0:11:22".parse(),
            Ok(MacAddr([0xa, 0xb, 0xc, 0, 0x11, 0x22]))
        );
        assert!("192.168.1.1".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:00:11:22:33".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_flags_and_display() {
        let fixed: MacAddr = "00:1A:2b:00:11:22".parse().unwrap();
        let random: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        assert_eq!(fixed.to_string(), "00:1a:2b:00:11:22");
        assert!(!fixed.is_randomized() && random.is_randomized());
    }

    #[test]
    fn subnets_of_any_size_list_their_hosts() {
        let home = Subnet::new(ME, 24);
        let hosts: Vec<Ipv4Addr> = home.hosts().collect();
        assert_eq!(home.to_string(), "192.168.1.0/24");
        assert_eq!(
            (hosts.len(), hosts[0], hosts[253]),
            (254, ROUTER, Ipv4Addr::new(192, 168, 1, 254))
        );
        assert!(hosts.iter().all(|host| home.contains(*host)));
        assert!(!home.contains(Ipv4Addr::new(192, 168, 2, 1)));

        let office = Subnet::new(Ipv4Addr::new(10, 1, 6, 9), 22);
        assert_eq!(
            (office.to_string(), office.hosts().count()),
            ("10.1.4.0/22".to_owned(), 1022)
        );
        assert!(
            office.contains(Ipv4Addr::new(10, 1, 7, 255))
                && !office.contains(Ipv4Addr::new(10, 1, 8, 0))
        );

        let tiny = Subnet::new(ME, 30);
        assert_eq!(
            tiny.hosts().collect::<Vec<_>>(),
            [Ipv4Addr::new(192, 168, 1, 41), ME]
        );
        assert_eq!(Subnet::new(ME, 0).to_string(), "0.0.0.0/0");
        assert_eq!(
            Subnet::new(ME, 99),
            Subnet::new(ME, 32),
            "a prefix cannot exceed 32 bits"
        );
        assert!(
            home < office.max(home) || office < home,
            "subnets have a total order"
        );
    }

    #[test]
    fn keeps_only_interfaces_with_a_lan() {
        let mask = |prefix: u8| Ipv4Addr::from(Subnet::mask(prefix));
        let home = scannable(ME, mask(24)).unwrap();
        assert_eq!((home.ip, home.subnet), (ME, Subnet::new(ME, 24)));
        let wide = scannable(Ipv4Addr::new(10, 1, 6, 9), mask(8)).unwrap();
        assert_eq!(
            wide.subnet.to_string(),
            "10.1.0.0/20",
            "huge networks are narrowed"
        );

        assert_eq!(scannable(Ipv4Addr::LOCALHOST, mask(8)), None);
        assert_eq!(scannable(Ipv4Addr::new(169, 254, 3, 4), mask(16)), None);
        assert_eq!(scannable(ME, mask(32)), None);
    }

    #[test]
    fn parses_arp_tables_and_drops_broadcast() {
        let windows = "Interface: 192.168.1.42 --- 0xb\n  192.168.1.1   aa-bb-cc-00-11-22  dynamic\n  192.168.1.255  ff-ff-ff-ff-ff-ff  static\n  224.0.0.22  01-00-5e-00-00-16  static";
        let unix = "? (192.168.1.1) at aa:bb:cc:00:11:22 [ether] on eth0\n? (192.168.1.9) at <incomplete> on eth0";
        for table in [windows, unix] {
            let arp = parse_arp(table);
            assert_eq!(arp.len(), 1);
            assert_eq!(arp[&ROUTER].to_string(), "aa:bb:cc:00:11:22");
        }
    }

    #[test]
    fn finds_gateway_on_every_os() {
        let outputs = [
            "Active Routes:\n  0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.42  25",
            "default via 192.168.1.1 dev eth0 src 192.168.1.42",
            "   route to: default\n    gateway: 192.168.1.1\n  interface: en0",
        ];
        for output in outputs {
            assert_eq!(parse_gateway(output, Subnet::new(ME, 24), ME), Some(ROUTER));
        }
        let other_network = Subnet::new(Ipv4Addr::new(10, 0, 0, 5), 24);
        assert_eq!(parse_gateway(outputs[0], other_network, ME), None);
    }

    #[test]
    fn parses_ping_replies_in_any_language() {
        let replies = [
            ("Reply from 192.168.1.1: bytes=32 time=3ms TTL=64", 64, 3.0),
            (
                "Réponse de 192.168.1.1 : octets=32 temps<1ms TTL=128",
                128,
                1.0,
            ),
            (
                "Antwort von 192.168.1.1: Bytes=32 Zeit=12 ms TTL=255",
                255,
                12.0,
            ),
            (
                "PING 192.168.1.1\n64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.045 ms",
                64,
                0.045,
            ),
        ];
        for (output, ttl, latency_ms) in replies {
            assert_eq!(parse_ping(output), Some(Ping { ttl, latency_ms }));
        }
        assert_eq!(parse_ping("Request timed out."), None);
        assert_eq!(parse_ping("TTL=64 but no duration"), None);
        assert_eq!(parse_ping("time=1ms TTL=999"), None, "a TTL is one byte");
    }

    #[test]
    fn reads_this_machine_network_state() {
        assert_eq!(command_output("netmap-no-such-program", &[]), "");
        assert_eq!(
            ping(Ipv4Addr::new(192, 0, 2, 1)),
            None,
            "documentation addresses never answer"
        );

        let interfaces = interfaces().unwrap();
        for gateway in gateways(&interfaces) {
            assert!(interfaces
                .iter()
                .any(|interface| interface.subnet.contains(gateway)));
            assert!(interfaces.iter().all(|interface| interface.ip != gateway));
        }
        for (index, interface) in interfaces.iter().enumerate() {
            assert!(interface.subnet.contains(interface.ip));
            assert!(interfaces[index + 1..]
                .iter()
                .all(|other| other.subnet != interface.subnet));
        }
        assert!(arp_table().keys().all(|ip| !ip.is_unspecified()));
    }
}
