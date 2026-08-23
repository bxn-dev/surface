use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns whether an address is suitable for hosted outbound scanning.
#[must_use]
pub fn is_global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => global_v4(address),
        IpAddr::V6(address) => global_v6(address),
    }
}

fn global_v4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .iter()
    .any(|(network, prefix)| in_v4_prefix(value, *network, *prefix))
}

const fn in_v4_prefix(address: u32, network: u32, prefix: u32) -> bool {
    let mask = u32::MAX << (32 - prefix);
    address & mask == network & mask
}

fn global_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return global_v4(mapped);
    }
    let value = u128::from(address);
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !in_v6_prefix(
            value,
            u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
            7,
        )
        && !in_v6_prefix(
            value,
            u128::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            10,
        )
        && !in_v6_prefix(
            value,
            u128::from(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0)),
            10,
        )
        && !in_v6_prefix(
            value,
            u128::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
            32,
        )
}

const fn in_v6_prefix(address: u128, network: u128, prefix: u32) -> bool {
    let mask = u128::MAX << (128 - prefix);
    address & mask == network & mask
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_global_unicast;

    #[test]
    fn rejects_non_global_categories() {
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
            IpAddr::V6("fe80::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
            IpAddr::V6("2001:db8::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
        ] {
            assert!(!is_global_unicast(address), "{address}");
        }
        assert!(is_global_unicast(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_global_unicast(IpAddr::V6(
            "2606:4700:4700::1111"
                .parse()
                .unwrap_or(Ipv6Addr::LOCALHOST)
        )));
    }
}
