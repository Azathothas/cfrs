//! The services of other parties that podnet uses (the relay, the edge of
//! Cloudflare's tunnels and its roots, the quick tunnels, WARP, 1.1.1.1 and
//! Pinggy): the data of `pod-services` (PodUtils/podcrates), each value with
//! its source and the date when it was read. `pod-services` checks its
//! built-in set when it builds, so a missing service or fact here is a
//! defect of that set, and panics.

pub use pod_services::{Endpoint, Service};

/// The built-in service `id`.
pub fn get(id: &str) -> &'static Service {
    pod_services::get(id).unwrap_or_else(|| panic!("pod-services holds no service {id}"))
}

/// The endpoint `name` of the service `id`.
pub fn endpoint(id: &str, name: &str) -> &'static Endpoint {
    get(id)
        .endpoint(name)
        .unwrap_or_else(|| panic!("{id} of pod-services has no endpoint {name}"))
}

/// The endpoints of the role `role` of the service `id`, in order.
pub fn endpoints_of(id: &str, role: &str) -> Vec<&'static Endpoint> {
    let all = get(id).endpoints().iter();
    all.filter(|e| e.role() == Some(role)).collect()
}

/// The addresses of the endpoints of the role `role` of the service `id`.
/// An endpoint can give its address as its host, with no list of
/// addresses: `socket_addrs` takes the host then; `ip_addrs` does not.
pub fn ips_of(id: &str, role: &str) -> Vec<std::net::IpAddr> {
    let addrs = endpoints_of(id, role)
        .into_iter()
        .flat_map(|e| e.socket_addrs());
    addrs.map(|a| a.ip()).collect()
}

/// The text fact `name` of the service `id`.
pub fn text(id: &str, name: &str) -> &'static str {
    get(id)
        .text(name)
        .unwrap_or_else(|| panic!("{id} of pod-services holds no text {name}"))
}

/// The edge of Cloudflare's tunnels.
pub const EDGE: &str = "cloudflare-tunnel-edge";
/// WARP.
pub const WARP: &str = "cloudflare-warp";
/// 1.1.1.1: plain DNS and the trace.
pub const ONE: &str = "cloudflare-dns";
/// The quick tunnels of Cloudflare.
pub const QUICK: &str = "trycloudflare";

/// The port of the edge's endpoints of the role `h2` (7844).
pub fn edge_port() -> u16 {
    endpoints_of(EDGE, "h2").first().map_or(7844, |e| e.port())
}

/// The default provisioning endpoint of the quick tunnels, as cloudflared's
/// flag `quick-service`: `https://` and the host of the endpoint `api`.
pub fn default_quick_service() -> String {
    format!("https://{}", endpoint(QUICK, "api").host())
}

/// A name of the edge, for the choice of the proxy (`NO_PROXY` may name it):
/// the host of the endpoint `h2-region1`.
pub fn edge_region_name() -> &'static str {
    endpoint(EDGE, "h2-region1").host()
}

/// The default targets of `warp probe`: the trace of 1.1.1.1 on its IPv4
/// address, and the edge at the fact `warp-probe-address` on the port of the
/// role `h2`.
pub fn probe_targets() -> Vec<String> {
    let v4 = endpoint(ONE, "trace")
        .socket_addrs()
        .into_iter()
        .find(|a| a.is_ipv4());
    let edge = format!("{}:{}", text(EDGE, "warp-probe-address"), edge_port());
    v4.map(|a| a.to_string())
        .into_iter()
        .chain([edge])
        .collect()
}

/// The relay of `--transport relay` when no other is given: the URL of the
/// endpoint `default` of `ajam-relay`.
pub fn default_relay() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| endpoint("ajam-relay", "default").url())
}

/// The resolver that names go to through the WARP tunnel: the endpoint
/// `udp-1` of 1.1.1.1.
pub fn tunnel_resolver() -> std::net::SocketAddr {
    let addrs = endpoint(ONE, "udp-1").socket_addrs();
    addrs
        .first()
        .copied()
        .expect("udp-1 of pod-services is an address")
}

/// The name of the DNS query of the check of WARP's data path: the fact
/// `check-name` of 1.1.1.1.
pub fn check_name() -> &'static str {
    text(ONE, "check-name")
}

/// The first address of the endpoint `name` of WARP.
fn warp_address(name: &str) -> &'static str {
    let first = endpoint(WARP, name).addresses().first();
    first
        .map(|a| a.as_ref())
        .unwrap_or_else(|| panic!("{name} of WARP has no address"))
}

/// The address of the MASQUE front door: the endpoint `masque-v4` of WARP.
pub fn masque_address() -> &'static str {
    warp_address("masque-v4")
}

/// The IPv6 address of the MASQUE front door (the IPv6-only kit: the doctor
/// gave "0 of 3 legs" on a host where the tunnel worked over IPv6): the
/// endpoint `masque-v6` of WARP.
pub fn masque_address_v6() -> &'static str {
    warp_address("masque-v6")
}

/// The values of WARP's API and of its MASQUE front door.
pub mod warp {
    use super::{endpoint, text, WARP};

    /// The API host, on TCP 443: the endpoint `api`.
    pub fn api_base() -> String {
        endpoint(WARP, "api").url()
    }

    /// A second name of the same API: podnet tries it after a dial, TLS or
    /// 5xx failure of the first. A proxy allowlist can have one name and not
    /// the other. The endpoint `api-second`.
    pub fn api_second() -> String {
        endpoint(WARP, "api-second").url()
    }

    /// The version segment of the API. It must agree with the build number
    /// of [`client_version`]; the service refuses a pair that does not. The
    /// fact `api-version`.
    pub fn api_version() -> &'static str {
        text(WARP, "api-version")
    }

    /// The value of `CF-Client-Version`: the fact `client-version`.
    pub fn client_version() -> &'static str {
        text(WARP, "client-version")
    }

    /// The `User-Agent` of the Android client, which the service expects:
    /// the fact `user-agent`.
    pub fn user_agent() -> &'static str {
        text(WARP, "user-agent")
    }

    /// The SNI of the MASQUE front door (the endpoint `masque-v4`).
    pub fn masque_sni() -> &'static str {
        endpoint(WARP, "masque-v4").server_name()
    }

    /// The MASQUE port of the front door: 443; the API may give others.
    pub fn masque_port() -> u16 {
        endpoint(WARP, "masque-v4").port()
    }

    /// The `:authority` of the CONNECT-IP request. Only the host matters:
    /// Cloudflare reads it as a hint of routing. The fact `connect-uri`.
    pub fn connect_uri() -> &'static str {
        text(WARP, "connect-uri")
    }
}

#[cfg(test)]
mod tests {
    /// The fallback nameservers of `warp tun` and the nameserver of the raw
    /// pod (live run 42222905277: an empty list made warp run --backend
    /// netns-raw panic after the take of pod-services).
    // An endpoint of the role udp gives its address as its host, with no
    // list of addresses: socket_addrs takes the host, ip_addrs does not.
    #[test]
    fn the_nameservers_of_the_service_are_1_1_1_1_and_1_0_0_1() {
        let want: Vec<std::net::IpAddr> =
            vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()];
        assert_eq!(crate::warp::route::nameservers_of_service(), want);
    }
}
