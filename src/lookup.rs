//! Name services devices answer to: mDNS (Bonjour) service advertising and NetBIOS names.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::scan::clean;

const MDNS_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(224, 0, 0, 251), 5353);
const MDNS_WINDOW: Duration = Duration::from_secs(2);
/// "Which service types exist here?": a PTR question for `_services._dns-sd._udp.local`,
/// with the bit asking for answers sent straight back to us.
const SERVICE_QUERY: &[u8] =
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x80\x01";
const RECORD_PTR: usize = 12;
/// A name may be compressed by pointing at earlier bytes; a hostile one could point in circles.
const MAX_POINTER_JUMPS: usize = 16;
const MAX_SERVICES_PER_DEVICE: usize = 64;

const NETBIOS_PORT: u16 = 137;
const NETBIOS_TIMEOUT: Duration = Duration::from_millis(700);
/// "What are your names?": a node status request for the wildcard name `*`.
const NODE_STATUS_QUERY: &[u8] =
    b"\x4e\x4d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01";
/// Where the name table starts in a node status reply, and the size of each entry.
const NODE_NAMES_AT: usize = 57;
const NODE_NAME_ENTRY: usize = 18;

/// The Windows-style identity of a device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Netbios {
    pub name: Option<String>,
    pub workgroup: Option<String>,
}

/// The service types each device advertises over mDNS, like `_airplay._tcp`.
pub fn discover_mdns(me: Ipv4Addr) -> io::Result<HashMap<Ipv4Addr, Vec<String>>> {
    mdns_browse(me, MDNS_GROUP.into(), MDNS_WINDOW)
}

fn mdns_browse(
    me: Ipv4Addr,
    target: SocketAddr,
    window: Duration,
) -> io::Result<HashMap<Ipv4Addr, Vec<String>>> {
    let socket = UdpSocket::bind((me, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    socket.send_to(SERVICE_QUERY, target)?;

    let mut found: HashMap<Ipv4Addr, Vec<String>> = HashMap::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        // Timeouts and ICMP resets are expected here: keep listening until the deadline.
        let Ok((length, SocketAddr::V4(sender))) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let services = found.entry(*sender.ip()).or_default();
        for service in advertised_services(&buffer[..length]) {
            if !services.contains(&service) && services.len() < MAX_SERVICES_PER_DEVICE {
                services.push(service);
            }
        }
    }
    found.retain(|_, services| !services.is_empty());
    found.values_mut().for_each(|services| services.sort());
    Ok(found)
}

/// The service types named by the PTR records of an mDNS response. A response cut short
/// or malformed still gives what came before the damage.
fn advertised_services(message: &[u8]) -> Vec<String> {
    let mut services = Vec::new();
    let _ = collect_services(message, &mut services);
    services
}

fn collect_services(message: &[u8], services: &mut Vec<String>) -> Option<()> {
    let number = |at: usize| {
        Some(usize::from(u16::from_be_bytes([
            *message.get(at)?,
            *message.get(at + 1)?,
        ])))
    };
    let (questions, records) = (number(4)?, number(6)? + number(8)? + number(10)?);
    let mut at = 12;
    for _ in 0..questions {
        at = read_name(message, at)?.1 + 4;
    }
    for _ in 0..records {
        let (_, header) = read_name(message, at)?;
        let (record_type, length, data) = (number(header)?, number(header + 8)?, header + 10);
        if record_type == RECORD_PTR {
            let (name, _) = read_name(message, data)?;
            // Service types start with an underscore; instance names do not.
            if let Some(service) = name
                .strip_suffix(".local")
                .filter(|name| name.starts_with('_'))
            {
                services.push(clean(service));
            }
        }
        at = data + length;
    }
    Some(())
}

/// Reads a DNS name at `start`; returns it with the position right after it.
fn read_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let (mut at, mut after, mut jumps) = (start, None, 0);
    loop {
        let length = usize::from(*message.get(at)?);
        if length == 0 {
            return Some((labels.join("."), after.unwrap_or(at + 1)));
        }
        if length & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return None;
            }
            let low = usize::from(*message.get(at + 1)?);
            // The name ends where its first pointer does, wherever the pointer leads.
            after.get_or_insert(at + 2);
            at = (length & 0x3F) << 8 | low;
        } else {
            let label = message.get(at + 1..at + 1 + length)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            at += 1 + length;
        }
    }
}

/// The NetBIOS name and workgroup of a device, when it answers on UDP 137.
pub fn netbios(ip: Ipv4Addr) -> Option<Netbios> {
    netbios_at(SocketAddr::from((ip, NETBIOS_PORT)))
}

fn netbios_at(target: SocketAddr) -> Option<Netbios> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.set_read_timeout(Some(NETBIOS_TIMEOUT)).ok()?;
    socket.send_to(NODE_STATUS_QUERY, target).ok()?;
    let mut buffer = [0u8; 1024];
    let (length, sender) = socket.recv_from(&mut buffer).ok()?;
    // Only the device we asked may answer for itself.
    if sender.ip() != target.ip() {
        return None;
    }
    parse_node_status(&buffer[..length])
}

fn parse_node_status(reply: &[u8]) -> Option<Netbios> {
    let count = usize::from(*reply.get(NODE_NAMES_AT - 1)?);
    let mut found = Netbios::default();
    let (entries, _) = reply.get(NODE_NAMES_AT..)?.as_chunks::<NODE_NAME_ENTRY>();
    for entry in entries.iter().take(count) {
        let (name, suffix, flags) = (&entry[..15], entry[15], entry[16]);
        // Suffix 0 marks the plain machine name, or the workgroup when the group bit is set.
        if suffix != 0 {
            continue;
        }
        let text = clean(String::from_utf8_lossy(name).trim_end());
        let slot = if flags & 0x80 == 0 {
            &mut found.name
        } else {
            &mut found.workgroup
        };
        if slot.is_none() && !text.is_empty() {
            *slot = Some(text);
        }
    }
    (found != Netbios::default()).then_some(found)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    /// A DNS name without compression.
    fn name(labels: &[&str]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for label in labels {
            bytes.push(u8::try_from(label.len()).unwrap());
            bytes.extend(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn record(owner: &[u8], record_type: u8, data: &[u8]) -> Vec<u8> {
        let length = u8::try_from(data.len()).unwrap();
        [
            owner,
            &[0, record_type, 0, 1, 0, 0, 0, 120, 0, length],
            data,
        ]
        .concat()
    }

    /// What a device advertising AirPlay and a printer queue would answer.
    fn mdns_response() -> Vec<u8> {
        let browse = name(&["_services", "_dns-sd", "_udp", "local"]);
        let pointer_to_question = [0xC0, 12];
        [
            vec![0, 0, 0x84, 0, 0, 1, 0, 2, 0, 1, 0, 1],
            [browse, vec![0, 12, 0, 1]].concat(),
            record(
                &pointer_to_question,
                12,
                &name(&["_airplay", "_tcp", "local"]),
            ),
            record(&pointer_to_question, 12, &name(&["_ipp", "_tcp", "local"])),
            record(&name(&["tv", "local"]), 1, &[192, 168, 1, 5]),
            record(
                &pointer_to_question,
                12,
                &name(&["Living Room", "_airplay", "_tcp", "local"]),
            ),
        ]
        .concat()
    }

    fn node_status(names: &[(&str, u8, u8)]) -> Vec<u8> {
        let mut reply = vec![0u8; NODE_NAMES_AT - 1];
        reply.push(u8::try_from(names.len()).unwrap());
        for (name, suffix, flags) in names {
            reply.extend(format!("{name:<15}").as_bytes());
            reply.extend([*suffix, *flags, 0]);
        }
        reply.extend([0u8; 6]); // The MAC address that closes the table.
        reply
    }

    #[test]
    fn queries_are_well_formed() {
        assert_eq!(SERVICE_QUERY.len(), 12 + 30 + 4);
        assert_eq!(
            read_name(SERVICE_QUERY, 12),
            Some(("_services._dns-sd._udp.local".to_owned(), 42))
        );
        assert_eq!(NODE_STATUS_QUERY.len(), 12 + 34 + 4);
    }

    #[test]
    fn reads_plain_and_compressed_names() {
        let message = [
            name(&["tv", "local"]),
            vec![3, b'n', b'a', b's', 0xC0, 3],
            vec![9],
        ]
        .concat();
        assert_eq!(read_name(&message, 0), Some(("tv.local".to_owned(), 10)));
        assert_eq!(
            read_name(&message, 10),
            Some(("nas.local".to_owned(), 16)),
            "pointer to `local`"
        );
        assert_eq!(read_name(&message, 3), Some(("local".to_owned(), 10)));
        assert_eq!(read_name(&message, 16), None, "label running past the end");
        assert_eq!(read_name(&message, 99), None);
        assert_eq!(read_name(&[0xC0], 0), None, "pointer cut in half");
        assert_eq!(read_name(&[0xC0, 0], 0), None, "pointer to itself");
    }

    #[test]
    fn lists_service_types_and_survives_damage() {
        let response = mdns_response();
        assert_eq!(
            advertised_services(&response),
            ["_airplay._tcp", "_ipp._tcp"]
        );
        let cut = &response[..response.len() - 30];
        assert_eq!(
            advertised_services(cut),
            ["_airplay._tcp", "_ipp._tcp"],
            "what came before the cut"
        );
        assert!(advertised_services(&response[..20]).is_empty());
        assert!(advertised_services(&[]).is_empty());
        assert!(
            advertised_services(SERVICE_QUERY).is_empty(),
            "a question advertises nothing"
        );
    }

    #[test]
    fn browses_services_over_mdns() {
        let device = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = device.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (length, asker) = device.recv_from(&mut request).unwrap();
            assert_eq!(&request[..length], SERVICE_QUERY);
            // Sent twice, plus noise: services are listed once and garbage is ignored.
            device.send_to(&mdns_response(), asker).unwrap();
            device.send_to(&mdns_response(), asker).unwrap();
            device.send_to(b"not dns", asker).unwrap();
        });

        let found = mdns_browse(Ipv4Addr::LOCALHOST, address, Duration::from_millis(600)).unwrap();
        responder.join().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[&Ipv4Addr::LOCALHOST], ["_airplay._tcp", "_ipp._tcp"]);

        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let nobody = mdns_browse(
            Ipv4Addr::LOCALHOST,
            silent.local_addr().unwrap(),
            Duration::from_millis(300),
        );
        assert!(nobody.unwrap().is_empty());
        // Loopback has no Bonjour devices: either nothing answers or multicast is refused outright.
        assert!(discover_mdns(Ipv4Addr::LOCALHOST).map_or(true, |found| found.is_empty()));
    }

    #[test]
    fn parses_netbios_name_tables() {
        let reply = node_status(&[
            ("DESKTOP-ABC", 0x20, 0x04),
            ("DESKTOP-ABC", 0x00, 0x04),
            ("WORKGROUP", 0x00, 0x84),
            ("OTHERNAME", 0x00, 0x04),
        ]);
        let expected = Netbios {
            name: Some("DESKTOP-ABC".to_owned()),
            workgroup: Some("WORKGROUP".to_owned()),
        };
        assert_eq!(parse_node_status(&reply), Some(expected));

        let nameless = node_status(&[("WORKGROUP", 0x00, 0x84)]);
        assert_eq!(parse_node_status(&nameless).unwrap().name, None);
        assert_eq!(
            parse_node_status(&node_status(&[("FILESERVER", 0x20, 0x04)])),
            None
        );
        assert_eq!(
            parse_node_status(&node_status(&[("", 0x00, 0x04)])),
            None,
            "blank name"
        );
        assert_eq!(
            parse_node_status(&reply[..NODE_NAMES_AT - 1]),
            None,
            "cut before the table"
        );
        assert_eq!(parse_node_status(&[0u8; 10]), None);
    }

    #[test]
    fn asks_a_device_for_its_netbios_name() {
        let device = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = device.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (length, asker) = device.recv_from(&mut request).unwrap();
            assert_eq!(&request[..length], NODE_STATUS_QUERY);
            device
                .send_to(&node_status(&[("NAS\x1b", 0x00, 0x04)]), asker)
                .unwrap();
        });
        let found = netbios_at(address).unwrap();
        responder.join().unwrap();
        assert_eq!(
            found.name.as_deref(),
            Some("NAS"),
            "control characters are stripped"
        );

        // 192.0.2.0/24 is reserved for documentation: nothing there answers.
        assert_eq!(netbios(Ipv4Addr::new(192, 0, 2, 1)), None);
    }

    #[test]
    fn ignores_netbios_answers_from_someone_else() {
        let impostor = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = impostor.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (_, asker) = impostor.recv_from(&mut request).unwrap();
            impostor
                .send_to(&node_status(&[("EVIL", 0x00, 0x04)]), asker)
                .unwrap();
        });
        // Asked through another loopback address than the one the answer comes back from.
        let asked = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), port));
        assert_eq!(netbios_at(asked), None);
        // Unblocks the responder if the question never reached it on this platform.
        let _ = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .send_to(b"", (Ipv4Addr::LOCALHOST, port));
        responder.join().unwrap();
    }
}
