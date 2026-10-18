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

/// The IPv6 special-purpose and non-global blocks, each refused by its own
/// rule (the IANA IPv6 Special-Purpose Address Registry and RFC 9637), so
/// that none of them depends on the `2000::/3` rule below.
fn v6_special(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let zero = |n: usize| s[..n].iter().all(|x| *x == 0);
    // ::/96: unspecified, loopback and the deprecated IPv4-compatible form.
    zero(6)
        // ::ffff:0:0:0/96, IPv4-translated (SIIT).
        || (zero(4) && s[4] == 0xffff && s[5] == 0)
        // 64:ff9b::/96 and 64:ff9b:1::/48, NAT64.
        || (s[0] == 0x0064 && s[1] == 0xff9b)
        // 100::/64, discard-only.
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        // 2001::/23, IETF protocol assignments: Teredo, benchmarking
        // (2001:2::/48), ORCHIDv2 (2001:20::/28) and the rest.
        || (s[0] == 0x2001 && s[1] < 0x0200)
        // 2001:db8::/32 and 3fff::/20, documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x3fff && s[1] < 0x1000)
        // 2002::/16, 6to4.
        || s[0] == 0x2002
        // fc00::/7 unique local, fe80::/10 link-local, fec0::/10
        // site-local, ff00::/8 multicast.
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] & 0xff00) == 0xff00
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    // Global unicast only, without the special-purpose blocks.
    !v6_special(ip) && (ip.segments()[0] & 0xe000) == 0x2000
}

/// Whether `ip` may be connected to: public unicast only. Loopback,
/// private, shared (CGNAT), link-local, unique local, multicast,
/// documentation (including `3fff::/20`), benchmarking, 6to4, Teredo, NAT64,
/// `ORCHIDv2`, discard-only, site-local, IPv4-compatible and -translated, and
/// the other IETF special-purpose blocks are refused, and an IPv4-mapped
/// IPv6 address is judged as its IPv4 address.
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

    /// Review L5: every blocked IPv6 class is refused by its own rule, not
    /// only because it falls outside `2000::/3`, so narrowing that rule can't
    /// let one through.
    #[test]
    fn every_blocked_ipv6_class_is_named() {
        for (ip, why) in cases("blocked") {
            let IpAddr::V6(v6) = ip else { continue };
            if v6.to_ipv4_mapped().is_some() {
                continue;
            }
            assert!(v6_special(v6), "{ip} ({why}) has no rule of its own");
        }
        for (ip, why) in cases("allowed") {
            if let IpAddr::V6(v6) = ip {
                assert!(!v6_special(v6), "{ip} ({why})");
            }
        }
    }
}
