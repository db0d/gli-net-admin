# gli-net-admin

Administrative tools for a GL.iNet Router

## Components

### Router admin proxy

[router-admin-proxy](./router-admin-proxy) is an explicit mitmproxy proxy for the router admin UI. The router's web configuration rejects a DNS name in the HTTP `Host` header, so the proxy rewrites that header for one configured destination and leaves every other TLS connection untouched.

DNS, the macOS LaunchAgent, certificate trust, and the local network setup are documented in [router-admin-proxy/README.md](./router-admin-proxy/README.md).
