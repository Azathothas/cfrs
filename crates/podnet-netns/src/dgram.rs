//! The limits of a datagram that the seccomp backend relays for the
//! program.

use crate::prelude::*;

/// The largest datagram that the supervisor reads from the program: the
/// largest payload of a UDP datagram. A longer length gets `EMSGSIZE`, as
/// the kernel gives, with no read and no allocation (issue 303).
pub(crate) const MAX_DATAGRAM: usize = 65535;

/// The largest SOCKS5 UDP datagram (header and payload) that the relay
/// sends: the largest UDP payload over IPv4. It also fits in a frame of the
/// UDP in the stream (a `u16` length).
pub(crate) const MAX_RELAYED: usize = 65507;

/// The longest name in a SOCKS5 address (ATYP 3 has a length byte).
pub(crate) const MAX_NAME: usize = 255;

/// Whether a payload of `len` bytes to `ip` (or to the name `name`) fits in
/// one SOCKS5 UDP datagram of the relay. `Err` is the errno for the
/// program: `EINVAL` for a name over 255 bytes (T-066: before, the name was
/// cut, and the datagram went to a different name), `EMSGSIZE` for a
/// datagram that is too large.
pub(crate) fn fits_relay(len: usize, ip: IpAddr, name: Option<&str>) -> Result<(), i32> {
    let header = match (name, ip) {
        (Some(name), _) if name.len() > MAX_NAME => {
            let start: String = name.chars().take(40).collect();
            eprintln!(
                "podnet-netns: UDP to the name {start}... ({} bytes) refused with EINVAL: \
                 SOCKS5 carries a name of 255 bytes at most, and this one is over 255 bytes",
                name.len()
            );
            return Err(libc::EINVAL);
        }
        (Some(name), _) => 4 + 1 + name.len() + 2,
        (None, IpAddr::V4(_)) => 10,
        (None, IpAddr::V6(_)) => 22,
    };
    match len.saturating_add(header) <= MAX_RELAYED {
        true => Ok(()),
        false => Err(libc::EMSGSIZE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_name_gets_einval_and_a_large_datagram_gets_emsgsize() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(fits_relay(10, ip, Some(&"a".repeat(255))), Ok(()));
        assert_eq!(
            fits_relay(10, ip, Some(&"a".repeat(256))),
            Err(libc::EINVAL)
        );
        assert_eq!(fits_relay(MAX_RELAYED - 10, ip, None), Ok(()));
        assert_eq!(fits_relay(MAX_RELAYED - 9, ip, None), Err(libc::EMSGSIZE));
        let name = Some("stun.example");
        assert_eq!(fits_relay(MAX_RELAYED - 18, ip, name), Err(libc::EMSGSIZE));
        assert_eq!(fits_relay(MAX_RELAYED - 19, ip, name), Ok(()));
    }
}
