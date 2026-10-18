//! Network address rules shared by everything that fetches a URL taken from
//! attacker-controlled text: the directory's owner-file check and the
//! daemon's (SPEC §13.2.4: only public addresses after DNS resolution).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_public(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19)))
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let s = ip.segments();
    // Global unicast only, without documentation, Teredo, 6to4, NAT64 and
    // the other IETF special-purpose blocks.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] == 0x0db8)
        && !(s[0] == 0x2001 && s[1] < 0x0200)
        && s[0] != 0x2002
        && !(s[0] == 0x0064 && s[1] == 0xff9b)
}

/// Whether `ip` may be connected to: public unicast only. Loopback,
/// private, shared (CGNAT), link-local, unique local, multicast,
/// documentation, benchmarking, 6to4, Teredo, NAT64 and the other IETF
/// special-purpose blocks are refused, and an IPv4-mapped IPv6 address is
/// judged as its IPv4 address.
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_public(v4),
        IpAddr::V6(v6) => v6_public(v6),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn cases(key: &str) -> Vec<(IpAddr, String)> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/public-addresses.json"
        );
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        raw[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["ip"].as_str().unwrap().parse().unwrap(),
                    c["why"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn only_public_unicast_is_allowed() {
        let blocked = cases("blocked");
        let allowed = cases("allowed");
        assert!(blocked.len() > 30 && allowed.len() > 5);
        for (ip, why) in blocked {
            assert!(!is_public_ip(ip), "{ip} ({why}) must be blocked");
        }
        for (ip, why) in allowed {
            assert!(is_public_ip(ip), "{ip} ({why}) must be allowed");
        }
    }
}
