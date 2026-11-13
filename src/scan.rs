//! Active probing: TCP services, UPnP discovery and reverse DNS.

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::net::Subnet;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const HTTP_TIMEOUT: Duration = Duration::from_secs(1);
const BANNER_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_BANNER_CHARS: usize = 80;
/// Short on purpose: a LAN host answers in a few ms, and Windows waits the whole timeout on closed ports.
const DEEP_TIMEOUT: Duration = Duration::from_millis(200);
const DEEP_WORKERS: usize = 1024;
const SSDP_WINDOW: Duration = Duration::from_secs(3);
const SSDP_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);
const M_SEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
const MAX_DESCRIPTION_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Ftp,
    Ssh,
    Telnet,
    Dns,
    Http,
    Https,
    Smb,
    Rtsp,
    Ipp,
    Mqtt,
    Rdp,
    Vnc,
    Cast,
    JetDirect,
    Plex,
    AppleSync,
}

impl Service {
    pub const ALL: [Self; 16] = [
        Self::Ftp,
        Self::Ssh,
        Self::Telnet,
        Self::Dns,
        Self::Http,
        Self::Https,
        Self::Smb,
        Self::Rtsp,
        Self::Ipp,
        Self::Mqtt,
        Self::Rdp,
        Self::Vnc,
        Self::Cast,
        Self::JetDirect,
        Self::Plex,
        Self::AppleSync,
    ];

    pub const fn port(self) -> u16 {
        match self {
            Self::Ftp => 21,
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Dns => 53,
            Self::Http => 80,
            Self::Https => 443,
            Self::Smb => 445,
            Self::Rtsp => 554,
            Self::Ipp => 631,
            Self::Mqtt => 1883,
            Self::Rdp => 3389,
            Self::Vnc => 5900,
            Self::Cast => 8009,
            Self::JetDirect => 9100,
            Self::Plex => 32400,
            Self::AppleSync => 62078,
        }
    }
}

/// Usual protocol of well-known TCP ports. A name is a hint, not proof of what runs there.
const PORT_NAMES: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (88, "Kerberos"),
    (110, "POP3"),
    (111, "RPC"),
    (135, "MSRPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (515, "LPD"),
    (548, "AFP"),
    (554, "RTSP"),
    (587, "SMTP"),
    (631, "IPP"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1883, "MQTT"),
    (2049, "NFS"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5000, "UPnP"),
    (5357, "WSD"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (7000, "AirPlay"),
    (8008, "Cast"),
    (8009, "Cast"),
    (8080, "HTTP"),
    (8443, "HTTPS"),
    (8883, "MQTT TLS"),
    (9100, "JetDirect"),
    (27017, "MongoDB"),
    (32400, "Plex"),
    (62078, "Apple Sync"),
];

pub fn port_name(port: u16) -> Option<&'static str> {
    PORT_NAMES
        .iter()
        .find(|(known, _)| *known == port)
        .map(|(_, name)| *name)
}

/// An open TCP port and whatever it announced about itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub port: u16,
    pub banner: Option<String>,
}

impl Probe {
    pub fn service(&self) -> Option<Service> {
        Service::ALL
            .into_iter()
            .find(|service| service.port() == self.port)
    }
}

/// What a device says about itself over UPnP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Upnp {
    pub server: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub model_number: Option<String>,
    pub serial_number: Option<String>,
    pub device_type: Option<String>,
    /// The device's own web interface, when it advertises one.
    pub url: Option<String>,
}

/// Probes every host of the subnet; hosts with no open service are left out.
/// The probes also fill the OS ARP table, which is how silent hosts get found.
pub fn scan_services(subnet: Subnet) -> HashMap<Ipv4Addr, Vec<Probe>> {
    thread::scope(|scope| {
        let scans: Vec<_> = subnet
            .hosts()
            .map(|ip| (ip, scope.spawn(move || probe_host(ip))))
            .collect();
        scans
            .into_iter()
            .map(|(ip, scan)| (ip, scan.join().expect("port probe panicked")))
            .filter(|(_, probes)| !probes.is_empty())
            .collect()
    })
}

fn probe_host(ip: Ipv4Addr) -> Vec<Probe> {
    Service::ALL
        .into_iter()
        .filter_map(|service| probe_port(ip, service.port(), CONNECT_TIMEOUT))
        .collect()
}

/// Tries every given TCP port of the given hosts; only hosts with open ports come back.
/// UDP is not scanned: without raw sockets an open UDP port looks the same as a filtered one.
pub fn scan_ports(hosts: &[Ipv4Addr], ports: RangeInclusive<u16>) -> HashMap<Ipv4Addr, Vec<Probe>> {
    let total = hosts.len() * ports.len();
    let next = AtomicUsize::new(0);
    let found: Mutex<HashMap<Ipv4Addr, Vec<Probe>>> = Mutex::default();
    thread::scope(|scope| {
        for _ in 0..DEEP_WORKERS.min(total) {
            scope.spawn(|| loop {
                let task = next.fetch_add(1, Ordering::Relaxed);
                if task >= total {
                    break;
                }
                // Hosts are interleaved so no single device takes the whole burst.
                let ip = hosts[task % hosts.len()];
                let offset =
                    u16::try_from(task / hosts.len()).expect("task index within port range");
                let port = ports.start() + offset;
                if let Some(probe) = probe_port(ip, port, DEEP_TIMEOUT) {
                    found
                        .lock()
                        .expect("a port worker panicked")
                        .entry(ip)
                        .or_default()
                        .push(probe);
                }
            });
        }
    });
    let mut found = found.into_inner().expect("a port worker panicked");
    found
        .values_mut()
        .for_each(|probes| probes.sort_by_key(|probe| probe.port));
    found
}

fn probe_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<Probe> {
    let stream = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), timeout).ok()?;
    Some(Probe {
        port,
        banner: banner(port == Service::Http.port(), stream),
    })
}

/// HTTP names its server once asked; most other talkative services (SSH, FTP, SMTP…) greet first.
fn banner(is_http: bool, mut stream: TcpStream) -> Option<String> {
    if is_http {
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").ok()?;
    }
    stream.set_read_timeout(Some(BANNER_TIMEOUT)).ok()?;
    let mut buffer = [0u8; 1024];
    let length = stream.read(&mut buffer).ok()?;
    let text = String::from_utf8_lossy(&buffer[..length]);
    let banner = if is_http {
        header(&text, "server")?
    } else {
        text.lines().next()?
    };
    Some(
        clean(banner)
            .chars()
            .take(MAX_BANNER_CHARS)
            .collect::<String>(),
    )
    .filter(|banner| !banner.is_empty())
}

/// Everything a device sends is untrusted: strip control characters before it reaches the terminal.
pub fn clean(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .collect()
}

pub fn discover_upnp(me: Ipv4Addr) -> io::Result<HashMap<Ipv4Addr, Upnp>> {
    ssdp_search(me, SSDP_GROUP.into(), SSDP_WINDOW)
}

/// Asks `target` who is there and listens for `window`; the first answer of each device wins.
fn ssdp_search(
    me: Ipv4Addr,
    target: SocketAddr,
    window: Duration,
) -> io::Result<HashMap<Ipv4Addr, Upnp>> {
    let socket = UdpSocket::bind((me, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    socket.send_to(M_SEARCH.as_bytes(), target)?;

    let mut replies: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        // Timeouts and ICMP resets are expected here: keep listening until the deadline.
        let Ok((length, SocketAddr::V4(sender))) = socket.recv_from(&mut buffer) else {
            continue;
        };
        replies
            .entry(*sender.ip())
            .or_insert_with(|| String::from_utf8_lossy(&buffer[..length]).into_owned());
    }

    Ok(replies
        .into_iter()
        .map(|(ip, reply)| {
            let description = header(&reply, "location")
                .and_then(|location| fetch_description(ip, location))
                .unwrap_or_default();
            let field = |tag: &str| xml_text(&description, tag).map(clean);
            let upnp = Upnp {
                server: header(&reply, "server").map(clean),
                friendly_name: field("friendlyName"),
                manufacturer: field("manufacturer"),
                model: field("modelName"),
                model_number: field("modelNumber"),
                serial_number: field("serialNumber"),
                device_type: field("deviceType"),
                url: field("presentationURL"),
            };
            (ip, upnp)
        })
        .collect())
}

/// Reverse-resolves every address at once; addresses without a name are left out.
pub fn hostnames(addresses: &BTreeSet<Ipv4Addr>) -> HashMap<Ipv4Addr, String> {
    thread::scope(|scope| {
        let lookups: Vec<_> = addresses
            .iter()
            .map(|&ip| (ip, scope.spawn(move || hostname(ip))))
            .collect();
        lookups
            .into_iter()
            .filter_map(|(ip, lookup)| Some((ip, lookup.join().expect("DNS lookup panicked")?)))
            .collect()
    })
}

/// The name this machine gives itself.
pub fn own_hostname() -> Option<String> {
    dns_lookup::get_hostname()
        .ok()
        .map(|name| clean(&name))
        .filter(|name| !name.is_empty())
}

fn hostname(ip: Ipv4Addr) -> Option<String> {
    dns_lookup::lookup_addr(&IpAddr::V4(ip))
        .ok()
        .filter(|name| name.parse::<IpAddr>().is_err())
        .map(|name| clean(&name))
}

fn header<'a>(message: &'a str, name: &str) -> Option<&'a str> {
    message.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn fetch_description(device: Ipv4Addr, location: &str) -> Option<String> {
    let (authority, path) = location.strip_prefix("http://")?.split_once('/')?;
    let address: SocketAddrV4 = authority.parse().ok()?;
    // LOCATION is untrusted input: only ever fetch from the device that answered.
    if *address.ip() != device {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(&address.into(), HTTP_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).ok()?;
    // One write: a server that answers and hangs up mid-request resets the connection.
    let request = format!("GET /{path} HTTP/1.0\r\nHost: {authority}\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut description = Vec::new();
    // A read timeout still leaves the bytes received so far, which is usually enough.
    let _ = stream
        .take(MAX_DESCRIPTION_BYTES)
        .read_to_end(&mut description);
    Some(String::from_utf8_lossy(&description).into_owned())
}

fn xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..end].trim()).filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn reads_ssdp_headers_case_insensitively() {
        let reply = "HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 Sonos/70\r\nLocation: http://192.168.1.5:1400/desc.xml\r\n\r\n";
        assert_eq!(header(reply, "server"), Some("Linux UPnP/1.0 Sonos/70"));
        assert_eq!(
            header(reply, "location"),
            Some("http://192.168.1.5:1400/desc.xml")
        );
        assert_eq!(header(reply, "st"), None);
    }

    #[test]
    fn extracts_xml_text() {
        let xml = "<device><friendlyName> Salon </friendlyName></device>";
        assert_eq!(xml_text(xml, "friendlyName"), Some("Salon"));
        assert_eq!(xml_text("<friendlyName>cut off", "friendlyName"), None);
        assert_eq!(xml_text(xml, "modelName"), None);
    }

    #[test]
    fn refuses_location_on_another_host() {
        let device = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(
            fetch_description(device, "http://10.0.0.1:80/desc.xml"),
            None
        );
        assert_eq!(fetch_description(device, "ftp://192.168.1.5:21/x"), None);
    }

    /// A one-shot local TCP server: reads the request if asked to, then answers and hangs up.
    fn serve(reads_request: bool, response: &'static str) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            if reads_request {
                let _ = stream.read(&mut [0u8; 512]).unwrap();
            }
            stream.write_all(response.as_bytes()).unwrap();
        });
        (port, server)
    }

    #[test]
    fn probes_open_and_closed_ports() {
        let (port, server) = serve(false, "220 hello\x07\r\nmore");
        let probe = probe_port(Ipv4Addr::LOCALHOST, port, CONNECT_TIMEOUT).unwrap();
        assert_eq!(
            (probe.port, probe.banner.as_deref()),
            (port, Some("220 hello"))
        );
        assert_eq!(probe.service(), None);
        server.join().unwrap();
        assert!(probe_port(Ipv4Addr::LOCALHOST, port, CONNECT_TIMEOUT).is_none());
    }

    #[test]
    fn reads_http_server_banner_and_tolerates_silence() {
        let connect = |port: u16| TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();

        let (port, server) = serve(true, "HTTP/1.0 200 OK\r\nServer: nginx/1.27\r\n\r\n");
        assert_eq!(banner(true, connect(port)).as_deref(), Some("nginx/1.27"));
        server.join().unwrap();

        let (port, server) = serve(true, "HTTP/1.0 200 OK\r\n\r\n");
        assert_eq!(banner(true, connect(port)), None, "no Server header");
        server.join().unwrap();

        let (port, server) = serve(false, "");
        assert_eq!(banner(false, connect(port)), None, "nothing sent");
        server.join().unwrap();
    }

    #[test]
    fn scans_a_port_range_across_hosts() {
        let (port, server) = serve(false, "hi\r\n");
        let hosts = [Ipv4Addr::LOCALHOST];
        let found = scan_ports(&hosts, port..=port);
        server.join().unwrap();
        assert_eq!(
            found[&Ipv4Addr::LOCALHOST]
                .iter()
                .map(|probe| probe.port)
                .collect::<Vec<_>>(),
            [port]
        );
        assert!(
            scan_ports(&hosts, port..=port).is_empty(),
            "the server is gone"
        );
        assert!(scan_ports(&[], 1..=u16::MAX).is_empty());
    }

    #[test]
    fn scans_known_services_of_a_subnet() {
        let loopback = Subnet::new(Ipv4Addr::LOCALHOST, 24);
        for (ip, probes) in scan_services(loopback) {
            assert!(loopback.contains(ip));
            assert!(!probes.is_empty() && probes.iter().all(|probe| probe.service().is_some()));
        }
    }

    #[test]
    fn known_ports_have_names() {
        let mut ports: Vec<u16> = Service::ALL.into_iter().map(Service::port).collect();
        assert!(
            ports.iter().all(|port| port_name(*port).is_some()),
            "every classified service is named"
        );
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), Service::ALL.len());

        assert!(
            PORT_NAMES.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "sorted, no duplicates"
        );
        assert_eq!(
            (port_name(22), port_name(5432), port_name(4)),
            (Some("SSH"), Some("PostgreSQL"), None)
        );
        let ssh = Probe {
            port: 22,
            banner: None,
        };
        assert_eq!(ssh.service(), Some(Service::Ssh));
    }

    #[test]
    fn learns_a_device_identity_over_upnp() {
        const DESCRIPTION: &str =
            "HTTP/1.0 200 OK\r\n\r\n<root><friendlyName>Lamp\x1b</friendlyName>\
            <manufacturer>Acme</manufacturer><modelName>L1</modelName></root>";
        let (http_port, http) = serve(true, DESCRIPTION);
        let device = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = device.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (length, asker) = device.recv_from(&mut request).unwrap();
            assert!(request[..length].starts_with(b"M-SEARCH"));
            let reply = format!(
                "HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0\r\nLOCATION: http://127.0.0.1:{http_port}/desc.xml\r\n\r\n"
            );
            // Sent twice: only the first answer of a device counts.
            device.send_to(reply.as_bytes(), asker).unwrap();
            device.send_to(b"HTTP/1.1 200 OK\r\n\r\n", asker).unwrap();
        });

        let found = ssdp_search(Ipv4Addr::LOCALHOST, address, Duration::from_millis(600)).unwrap();
        responder.join().unwrap();
        http.join().unwrap();
        let upnp = &found[&Ipv4Addr::LOCALHOST];
        assert_eq!(upnp.server.as_deref(), Some("Linux UPnP/1.0"));
        assert_eq!(upnp.friendly_name.as_deref(), Some("Lamp"));
        assert_eq!(upnp.manufacturer.as_deref(), Some("Acme"));
        assert_eq!(upnp.model.as_deref(), Some("L1"));
    }

    #[test]
    fn upnp_discovery_survives_a_silent_network() {
        // Loopback has no UPnP devices: either nothing answers or multicast is refused outright.
        assert!(discover_upnp(Ipv4Addr::LOCALHOST).map_or(true, |found| found.is_empty()));
    }

    #[test]
    fn this_machine_knows_its_own_name() {
        let name = own_hostname().expect("every machine has a hostname");
        assert!(!name.is_empty() && name.parse::<IpAddr>().is_err());
    }

    #[test]
    fn resolves_hostnames_and_skips_the_nameless() {
        // 192.0.2.0/24 is reserved for documentation: nothing there has a name.
        let nameless = Ipv4Addr::new(192, 0, 2, 1);
        let names = hostnames(&BTreeSet::from([Ipv4Addr::LOCALHOST, nameless]));
        assert!(!names.contains_key(&nameless));
        assert!(names
            .values()
            .all(|name| !name.is_empty() && name.parse::<IpAddr>().is_err()));
    }

    #[test]
    fn strips_terminal_escapes() {
        assert_eq!(clean("SSH-2.0\x1b[2J\r"), "SSH-2.0[2J");
    }
}
