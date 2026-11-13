//! Remembers devices between runs, so starting the tool does not mean rescanning everything.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::device::Device;

/// The environment variable holding the user's cache root, and our folder under it.
#[cfg(windows)]
const CACHE_DIR: (&str, &str) = ("LOCALAPPDATA", "netmap");
#[cfg(not(windows))]
const CACHE_DIR: (&str, &str) = ("HOME", ".cache/netmap");
const FILE_NAME: &str = "devices.json";

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Where devices are remembered; `None` when the user has no cache folder.
pub fn path() -> Option<PathBuf> {
    let (variable, folder) = CACHE_DIR;
    Some(
        PathBuf::from(env::var_os(variable)?)
            .join(folder)
            .join(FILE_NAME),
    )
}

/// A missing or unreadable file is simply an empty memory: the next scan rebuilds it.
pub fn load(path: &Path) -> Vec<Device> {
    let json = fs::read(path).ok();
    let mut devices: Vec<Device> = json
        .and_then(|json| serde_json::from_slice(&json).ok())
        .unwrap_or_default();
    // Memories written before first sightings were recorded: the last one is the best guess.
    for device in devices.iter_mut().filter(|device| device.first_seen == 0) {
        device.first_seen = device.last_seen;
    }
    devices
}

pub fn save(path: &Path, devices: &[Device]) -> io::Result<()> {
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)?;
    }
    // Written aside then renamed: a crash mid-write must not corrupt the previous memory.
    let draft = path.with_extension("json.tmp");
    fs::write(&draft, serde_json::to_vec_pretty(devices)?)?;
    fs::rename(draft, path)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::device::{Presence, Role};
    use crate::net::{Ping, Subnet};
    use crate::scan::{Probe, Upnp};

    fn scratch(name: &str) -> PathBuf {
        let folder = env::temp_dir().join(format!("netmap-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&folder);
        folder
    }

    fn nas() -> Device {
        let ip = Ipv4Addr::new(192, 168, 1, 7);
        Device {
            ip,
            subnet: Subnet::new(ip, 24),
            role: Role::Peer,
            mac: "00:00:0c:12:34:56".parse().ok(),
            hostname: Some("nas.lan".to_owned()),
            vendor: Some("Acme".to_owned()),
            upnp: Some(Upnp {
                model: Some("DS1".to_owned()),
                ..Upnp::default()
            }),
            ping: Some(Ping {
                ttl: 64,
                latency_ms: 1.5,
            }),
            probes: vec![Probe {
                port: 22,
                banner: Some("SSH-2.0".to_owned()),
            }],
            netbios: None,
            mdns: Vec::new(),
            label: None,
            first_seen: 0,
            last_seen: 1_700_000_000,
            ports_scanned: Some(1_699_999_000),
            presence: Presence::Online,
        }
    }

    #[test]
    fn remembers_devices_but_not_that_they_were_online() {
        let folder = scratch("roundtrip");
        let path = folder.join("deep").join(FILE_NAME);
        save(&path, &[nas()]).unwrap();
        save(&path, &[nas()]).unwrap(); // Overwrites the previous memory.

        let loaded = load(&path);
        assert_eq!(loaded.len(), 1);
        let (device, original) = (&loaded[0], nas());
        assert!(
            !device.is_online(),
            "a remembered device is unconfirmed until rescanned"
        );
        assert_eq!(
            (device.ip, device.subnet, device.mac),
            (original.ip, original.subnet, original.mac)
        );
        assert_eq!(
            (device.last_seen, device.ports_scanned),
            (1_700_000_000, Some(1_699_999_000))
        );
        assert_eq!((device.name(), device.ping), ("nas.lan", original.ping));
        assert_eq!(
            device.upnp.as_ref().and_then(|upnp| upnp.model.as_deref()),
            Some("DS1")
        );
        assert_eq!(device.probes[0].banner.as_deref(), Some("SSH-2.0"));
        assert_eq!(
            device.first_seen, 1_700_000_000,
            "an old memory has no first sighting"
        );
        assert!(!path.with_extension("json.tmp").exists());
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn missing_or_corrupt_memory_is_empty() {
        let folder = scratch("corrupt");
        let path = folder.join(FILE_NAME);
        assert!(load(&path).is_empty());
        fs::create_dir_all(&folder).unwrap();
        fs::write(&path, "{ not json").unwrap();
        assert!(load(&path).is_empty());
        fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn cache_lives_in_the_user_cache_folder() {
        assert!(now() > 1_700_000_000);
        let path = path().expect("test machines have a user profile");
        assert!(path.ends_with(Path::new(CACHE_DIR.1).join(FILE_NAME)));
    }
}
