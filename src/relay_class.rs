//! Relay-URL classification: is a relay reachable from off the local network?
//!
//! A single shared predicate so the reconnect supervisor, startup wiring, and
//! the persisted public-relay set all agree on what counts as an off-LAN
//! ("public") relay versus a LAN-only one. Hoisted out of `daemon/mod.rs` so
//! these callers share one classifier rather than re-deriving the rule.

/// Whether a relay URL is reachable from OFF the local network.
///
/// A public/domain relay or a globally-routable IP (e.g. `https://umbra.computer/`)
/// is an off-LAN lifeline. A private/link-local/loopback IP relay
/// (`http://192.168.x:3340`, `10/8`, `172.16/12`, `169.254/16`, `fc00::/7`,
/// `fe80::/10`) is LAN-only — useless once the laptop leaves that LAN.
///
/// An unparseable URL is treated as NOT off-LAN-reachable: it cannot be dialed
/// via relay, so it can never be the lifeline we protect from eviction.
///
/// This classification is consulted for the eviction decision (never special-cased
/// in the dial path — verdict A: an https domain relay and an http-ip relay take
/// the identical dial path) and for gating which relays may enter the persisted
/// public-relay set (a private LAN-IP relay must never be homed on off-LAN).
///
/// `RelayUrl` derefs to `url::Url`, so we read `host_str()` and try to parse it
/// as an `IpAddr`: a domain host fails the parse and is therefore off-LAN —
/// exactly the semantics we want — while an IP host is classified by the std
/// reachability methods. IPv6 link-local (`fe80::/10`) and unique-local
/// (`fc00::/7`) are matched bit-wise because the corresponding `Ipv6Addr` helpers
/// are unstable on this toolchain.
pub fn relay_is_offlan_reachable(relay_url: &str) -> bool {
    let Ok(parsed) = relay_url.parse::<iroh::RelayUrl>() else {
        return false; // unparseable → not a dial-able relay lifeline.
    };
    let Some(host) = parsed.host_str() else {
        return false; // no host → not reachable.
    };
    // `host_str()` returns IPv6 hosts in bracketed notation (`[fe80::1]`), which
    // fails `IpAddr` parsing — strip the brackets so the IP path classifies them
    // instead of falling through to the domain branch.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        // A domain host (e.g. `umbra.computer`) doesn't parse as an IP — it is a
        // genuine off-LAN route.
        return true;
    };
    match ip {
        std::net::IpAddr::V4(v4) => !(v4.is_private() || v4.is_link_local() || v4.is_loopback()),
        std::net::IpAddr::V6(v6) => {
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
            !(v6.is_loopback() || is_link_local || is_unique_local)
        }
    }
}

#[cfg(test)]
mod classification_tests {
    use super::relay_is_offlan_reachable;

    /// A public/domain relay or globally-routable IP is an off-LAN lifeline:
    /// these are the genuine routes home when the laptop leaves its LAN.
    #[test]
    fn public_and_domain_relays_are_offlan_reachable() {
        assert!(relay_is_offlan_reachable("https://umbra.computer/"));
        assert!(relay_is_offlan_reachable("http://example.com:3340/"));
        // A globally-routable IPv6 (Cloudflare) — not loopback/link/unique-local.
        assert!(relay_is_offlan_reachable("http://[2606:4700::1]:3340/"));
    }

    /// Private/link-local/loopback IPv4 relays are LAN-only — useless off-LAN.
    #[test]
    fn private_link_local_and_loopback_ipv4_are_lan_only() {
        assert!(!relay_is_offlan_reachable("http://192.168.68.52:3340/")); // 192.168/16
        assert!(!relay_is_offlan_reachable("http://10.0.0.5:3340/")); // 10/8
        assert!(!relay_is_offlan_reachable("http://172.16.0.1:3340/")); // 172.16/12
        assert!(!relay_is_offlan_reachable("http://169.254.1.1:3340/")); // 169.254/16 link-local
        assert!(!relay_is_offlan_reachable("http://127.0.0.1:3340/")); // loopback
    }

    /// IPv6 link-local (`fe80::/10`), unique-local (`fc00::/7`), and loopback are
    /// LAN-only, matched bit-wise since the std helpers are unstable.
    #[test]
    fn link_local_and_unique_local_ipv6_are_lan_only() {
        assert!(!relay_is_offlan_reachable("http://[fe80::1]:3340/")); // link-local
        assert!(!relay_is_offlan_reachable("http://[fc00::1]:3340/")); // unique-local
        assert!(!relay_is_offlan_reachable("http://[::1]:3340/")); // loopback
    }

    /// An unparseable / garbage URL can't be dialed as a relay, so it is never
    /// the lifeline we protect from eviction — classified NOT off-LAN-reachable.
    #[test]
    fn unparseable_url_is_not_offlan_reachable() {
        assert!(!relay_is_offlan_reachable("not a url"));
        assert!(!relay_is_offlan_reachable(""));
    }
}
