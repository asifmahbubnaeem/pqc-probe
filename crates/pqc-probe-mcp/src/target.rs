//! Turn what a model passes as `host` into a host and an optional port.
//!
//! Language models rarely pass a bare hostname: they send `https://example.com/`,
//! `example.com:443` or `git@github.com`. Rejecting those wastes a tool call and teaches the
//! model nothing, so the common shapes are cleaned up here. The result still goes through
//! the core's `validate_host` and the hosted policy, so cleaning never widens what is allowed.

/// Returns `(host, port_from_input)`.
pub fn split_host(input: &str) -> (String, Option<u16>) {
    let mut s = input.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    // IPv4 only, so a single ':' can only mean host:port.
    if let Some((h, p)) = s.split_once(':') {
        if !p.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), Some(port));
            }
        }
    }
    (s.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_the_shapes_models_send() {
        let cases = [
            ("example.com", ("example.com", None)),
            ("  example.com  ", ("example.com", None)),
            ("https://example.com/", ("example.com", None)),
            (
                "https://example.com:8443/path?q=1",
                ("example.com", Some(8443)),
            ),
            ("example.com:443", ("example.com", Some(443))),
            ("git@github.com", ("github.com", None)),
            ("ssh://git@github.com:22", ("github.com", Some(22))),
            ("1.2.3.4:2222", ("1.2.3.4", Some(2222))),
        ];
        for (input, (host, port)) in cases {
            assert_eq!(
                split_host(input),
                (host.to_string(), port),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn leaves_a_non_numeric_port_for_validation_to_reject() {
        assert_eq!(
            split_host("example.com:abc"),
            ("example.com:abc".to_string(), None)
        );
    }
}
