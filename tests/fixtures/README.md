# Public proxy/TLS test credentials

`proxy-test-root.pem`, `proxy-test-leaf.der` and `proxy-test-key.der` are **public loopback test fixtures**, not deployment credentials. The unencrypted PKCS8 leaf key is deliberately included so Rust TLS servers can run offline. Never install this CA or use the key for a real service.

The leaf is valid 2020-01-01 through 2039-01-01, with SANs `localhost`, `relay.invalid`, `proxy.invalid` and `127.0.0.1`. The root expires 2040-01-01. Clients trust it only via an explicit per-client `--ca-cert`; no Windows/OS certificate store is modified.

`generate-proxy-certs.ps1` uses native .NET CertificateRequest/RSA APIs. It stores no root private key and performs no network requests. Regeneration intentionally creates new keys and certificate bytes; it is a reproducible recipe, **not** a byte-deterministic operation. Fixture hashes must be refreshed when regenerating.

Recording HTTP/HTTPS CONNECT/SOCKS5 servers in `tests/support/proxy.rs` bind only random loopback ports, forward only an allowlisted fixture hostname and one known loopback target, and are terminated with their owning test. `relay.invalid` cannot be reached directly by public DNS; it is intentionally mapped by the fixture proxy to prove the remote-DNS/tunnel route. These fixtures are not a public proxy deployment or proof of a real public relay/provider.
