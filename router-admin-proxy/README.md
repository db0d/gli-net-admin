# Router admin hostname workaround

This is one component of gli-net-admin. Run the commands below from
`router-admin-proxy/`.

Use an explicit mitmproxy browser proxy to access a router whose admin interface
rejects a DNS name in the HTTP `Host` header.

The defaults in [src/router_admin_interface_bypass.py](./src/router_admin_interface_bypass.py)
are:

| Setting | Environment variable | Default |
| --- | --- | --- |
| Browser destination | `ROUTER_DESTINATION` | `router.dbod.local` |
| Router target | `ROUTER_TARGET` | `192.168.8.1` |
| Local proxy |  | `127.0.0.1:8080` |

Leave the variables unset to use this network's defaults. For another router,
set them in the shell that starts mitmproxy and again before installing the
LaunchAgent. The service stores the values from that install environment.
Change them later by uninstalling and installing again.

```bash
export ROUTER_DESTINATION=router.example
export ROUTER_TARGET=192.168.1.1
```

`ROUTER_DESTINATION` is the hostname the browser opens. `ROUTER_TARGET` is the
address the router accepts. The proxy intercepts both, connects to the target,
and sends the target in the `Host` header. Each value is a hostname or IPv4
address, without a scheme, path, or port.

## How it works

1. The browser sends an HTTPS `CONNECT` request to the local proxy.
2. The addon checks the CONNECT destination, not TLS SNI. SNI is supplied by the
   browser, not the router, and is not required for this workaround.
3. Only the exact configured destination or target is eligible for TLS
   interception. Domain matching is case-insensitive and accepts a trailing dot.
4. For requests to the destination name, the addon changes the upstream
   destination and HTTP `Host` header (or HTTP/2 `:authority`) to the target.
   The scheme, port, path, query, method, and body are preserved. Nonstandard
   ports remain in the Host value. Requests already addressed to the target
   need no rewrite.

All other TLS destinations, including `mitm.it`, are passed through without
decryption. A router-like substring or a router SNI on an unrelated CONNECT
destination does not enable interception. An unknown destination is also marked
for passthrough, not interception.

Passthrough still transports encrypted traffic through the proxy; it is not a
direct network bypass. The browser sees and validates the original website's
certificate. Plain HTTP traffic is not encrypted and is still parsed by the
proxy, but the addon does not modify non-router HTTP requests.

## 1. Set up the uv project

Install [uv](https://docs.astral.sh/uv/getting-started/installation/).
For example, if you use Homebrew:

```bash
brew install uv
```

From your copy of this project:

```bash
cd /path/to/gli-net-admin/router-admin-proxy
uv sync --frozen
```

The project uses Python 3.12 by default (`.python-version`) and pins mitmproxy
12.2.3 in `pyproject.toml`. `uv.lock` locks its transitive dependencies.
uv creates/manages `.venv` and can download Python if needed; no activation or
manual pip installation is required. Keep the lockfile with the project.

## 2. Configure DNS and network access

Configure local DNS so that:

```text
router.dbod.local -> 192.168.8.1
```

The name must resolve to the router, **not** the machine running mitmproxy.
Alternatively, add this entry to `/etc/hosts` on the proxy machine:

```text
192.168.8.1 router.dbod.local
```

Names ending in `.local` have special multicast-DNS behavior on macOS. If your
DNS setup is unreliable, use the hosts entry or choose another local name and
set `ROUTER_DESTINATION` to that name. Point the hosts entry at `ROUTER_TARGET`.

The proxy machine must be able to reach the router's HTTPS port.
On macOS, open **System Settings -> Privacy & Security -> Local Network** and
allow the application launching mitmproxy (Terminal, iTerm, or VS Code).
Restart that application after changing its permission.

## 3. Start the proxy

For an interactive terminal session, from the project directory:

```bash
uv run --frozen mitmproxy \
  --mode regular \
  --listen-host 127.0.0.1 \
  --listen-port 8080 \
  --set connection_strategy=lazy \
  --set ssl_insecure=true \
  -s src/router_admin_interface_bypass.py
```

Keep this process running while browsing through it. The loopback listener
restricts proxy access to this machine. Lazy connections avoid unnecessary
early upstream connections before the interception decision.

**Certificate policy:** `ssl_insecure=true` allows the router's self-signed
certificate, but is a global mitmproxy option, not a per-host trust exception.
With this addon, unrelated TLS destinations are passed through and the browser
still validates their original certificates. Do not add other interception
addons or broaden the allowlist and assume that upstream verification remains
enabled for those newly intercepted connections.

This setup does not authenticate the router's upstream TLS certificate and
therefore cannot protect the router connection against an active network
impersonator. Use it only on a trusted network.

For verified upstream TLS instead, remove `--set ssl_insecure=true`, export and
independently verify the router certificate or its issuing CA as PEM, and add:

```bash
--set ssl_verify_upstream_trusted_ca=/absolute/path/to/router-ca.pem
```

Certificate hostname verification still applies. A certificate covering only
the IP may not validate when mitmproxy initially connects using the DNS name.
Trusting a CA alone does not fix a hostname mismatch.

### Optional: install a macOS service for your user

[install/macos/service.py](./install/macos/service.py) installs a **LaunchAgent**,
not a system daemon. It runs only in your logged-in GUI user session, starts at
login, and restarts if the proxy exits. It does not run before login or after
logout. Do **not** use `sudo`.

Service scripts are split by operating system: macOS is `install/macos`, and
`install/linux` is the matching location for a Linux installer.

Stop any interactive mitmproxy instance first; the installer refuses to proceed
if port 8080 is already occupied. Then run:

```bash
uv run --frozen python install/macos/service.py install
uv run --frozen python install/macos/service.py status
```

Installation starts the service immediately and verifies that its local HTTP
proxy responds. If startup fails, the installer unloads the new service and
removes its plist; it reports the error and retains logs for diagnosis.
An existing installation is not overwritten.

The service uses the same router-only addon, loopback listener, lazy connections,
and `ssl_insecure=true` policy described above. Its plist records
`ROUTER_DESTINATION` and `ROUTER_TARGET` from the install environment, or the
defaults when those variables are unset. It runs headless `mitmdump`
directly from the project's `.venv`; launchd does not need uv on its PATH and
does not download/install anything at login. It uses your existing
`~/.mitmproxy` CA/configuration, so existing browser trust is preserved.
Avoid adding global interception addons or settings to that configuration.

Installed files:

- LaunchAgent: `~/Library/LaunchAgents/local.router-admin-proxy.plist`
- Logs: `~/Library/Logs/local.router-admin-proxy/stdout.log` and `stderr.log`

To follow logs:

```bash
tail -f "$HOME/Library/Logs/local.router-admin-proxy/stdout.log" \
  "$HOME/Library/Logs/local.router-admin-proxy/stderr.log"
```

Logs may contain router URLs and proxy errors. They are not automatically
rotated; manage them as sensitive local diagnostics. No flow-dump file is enabled.

**Permissions and location:** keep the project and `.venv` at a stable path.
Prefer a location outside macOS-protected Desktop/Documents/Downloads folders
for unattended execution (for example `~/Projects/gli-net-admin`). The
LaunchAgent stores absolute paths inside `router-admin-proxy/`.
If moving the project, recreate its environment with `uv sync --frozen` before
installing. macOS may require Local Network permission for the service's Python
process even when Terminal/VS Code already has permission. If launchd cannot
read a protected project directory, move the project rather than assuming the
terminal's permission carries over. Inspect the logs for access errors.

The installer does **not** change system network proxy settings, DNS, or privacy
permissions. It does trust the public certificates in [certs](./certs) for SSL
in your login keychain. The same trust step can be run on its own:

```bash
uv run --frozen python install/macos/trust_certs.py
```

Put one public certificate in each `.pem`, `.crt`, or `.cer` file. A CA is
trusted as a root. Any other certificate is trusted only as itself. Files that
contain a private key are refused. macOS may prompt for your login keychain
password. Complete the proxy and DNS steps below yourself.

To remove the service, first disable your network HTTP/HTTPS proxy settings:

```bash
uv run --frozen python install/macos/service.py uninstall
```

Uninstall unloads only this user's job and deletes its plist. It retains the
project, logs, keychain trust, and network settings. To reinstall/restart after changes,
uninstall and install again. If you move the project or recreate `.venv`,
reinstall the service so its absolute paths remain correct.

## 4. Route browser traffic through the network's HTTP/HTTPS proxy

Starting mitmproxy does not automatically route browser traffic through it.
Configure a proxy on the network connection you are actually using.

### macOS (Chrome and other browsers using system proxy settings)

1. Open **System Settings -> Network**.
2. Select your active connection, such as **Wi-Fi** or **Ethernet**.
3. Click **Details...**, then select **Proxies**.
4. Turn on **Web Proxy (HTTP)** and enter:
   - **Server:** `127.0.0.1`
   - **Port:** `8080`
5. Turn on **Secure Web Proxy (HTTPS)** and enter the same server and port:
   - **Server:** `127.0.0.1`
   - **Port:** `8080`
6. Leave proxy authentication disabled for both entries. Do not enable
   **SOCKS Proxy** for this setup.
7. In **Bypass proxy settings for these Hosts & Domains**, remove entries that
   cover the router IP/domain, such as `192.168.*` or `*.local`. If present,
   disable **Exclude simple hostnames** when using a single-label router name.
   Preserve unrelated bypass entries.
8. Click **OK** and **Apply** if shown to save the settings.
9. Open a new browser connection to `http://mitm.it` to check that traffic
   reaches the proxy, then continue with the CA installation below.

These settings apply to the selected network service. If you switch from Wi-Fi
to Ethernet, configure the proxy on that connection too. Applications that do
not honor system proxy settings require their own explicit proxy configuration.

The HTTPS proxy setting uses the same regular HTTP proxy listener; it does not
mean the browser should establish TLS to the proxy itself.

Chrome normally uses the macOS system proxy settings. Extensions, managed
policies, or VPN software may override them.

## 5. Trust mitmproxy's CA in the browser

The browser must trust mitmproxy's certificate for the intercepted router.
This is separate from mitmproxy accepting the router's self-signed certificate.

Certificates already exported into `certs/` are trusted when you install the
LaunchAgent, or when you run `install/macos/trust_certs.py` directly. To trust
the CA generated by this mitmproxy instance, copy only its public certificate
into that directory:

```bash
cp "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" certs/mitmproxy-ca-cert.pem
uv run --frozen python install/macos/trust_certs.py
```

`~/.mitmproxy/mitmproxy-ca-cert.pem` appears after mitmproxy's first startup.
You can also visit **http://mitm.it** through the proxy and follow its macOS
instructions. Restart Chrome if needed.

Only install your own locally generated mitmproxy CA. Do not share the CA's
private key or import a private-key file into the browser. The trust script
rejects a file that contains a private key.

## 6. Browse and verify

Open:

```text
https://router.dbod.local/
```

Router HTTP flows should appear in mitmproxy, and the event log should show:

```text
Rewrote router request host from router.dbod.local to 192.168.8.1
```

Visiting `https://192.168.8.1/` is also eligible for interception, but does not
produce the domain rewrite message.

An unrelated HTTPS site should retain its normal certificate issuer rather
than showing a mitmproxy-issued certificate. Its decrypted HTTP requests should
not appear in the proxy; connection/TCP events can still appear.

To test the router without browser proxy-bypass settings:

```bash
curl -v --noproxy "" \
  --proxy http://127.0.0.1:8080 \
  --cacert "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" \
  --connect-timeout 10 --max-time 20 \
  https://router.dbod.local/ -o /dev/null
```

Do not use curl's `-k`: the browser/curl should still validate mitmproxy's
certificate even though mitmproxy is configured to accept the router's.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `ERR_TUNNEL_CONNECTION_FAILED` or CONNECT 502 | Check mitmproxy's event log (`E` in the terminal UI), or the LaunchAgent logs if running as a service. This can occur before ClientHello. |
| `No route to host` | Check macOS Local Network permission for the launching application, LAN connectivity, router IP, VPN, and firewall settings. |
| Upstream self-signed certificate verification error | Confirm this dedicated instance was started with `ssl_insecure=true`, or configure verified upstream trust as described above. |
| Browser/curl distrusts the proxy certificate | Install/trust this instance's mitmproxy CA; upstream `ssl_insecure` does not change client trust. |
| No router HTTP flows | Confirm the browser uses the HTTP/HTTPS proxy and does not bypass the local domain/IP. Existing tunnels may require restarting the browser after addon changes. |
| DNS resolution failure | Check resolution on the proxy machine; `.local` may need a hosts entry. |
| Login still fails after the Host rewrite | Inspect router flows. The addon does not rewrite `Origin`, `Referer`, redirects, cookies, or application content; separate router checks may require additional investigation. |

## Tests

```bash
uv run --frozen python -m unittest discover -s tests -v
```

Tests cover destination-only TLS interception, missing SNI/address, unrelated
destinations including `mitm.it`, exact hostname matching, HTTP Host and HTTP/2
authority rewriting, preservation of request data, LaunchAgent generation,
startup failure cleanup, readiness checks, user-scoped removal, and login-keychain
trust commands. Service and certificate tests mock `launchctl` and `security`;
they do not install a real LaunchAgent or change the keychain.

## Stop and restore

Disable the system/browser HTTP and HTTPS proxy settings before stopping
mitmproxy; otherwise proxied browsing will fail. Quit interactive mitmproxy with
`q`, or uninstall the LaunchAgent using the command above.
Remove the mitmproxy CA trust when no longer needed, and undo any DNS/hosts
overrides you added solely for this setup.
