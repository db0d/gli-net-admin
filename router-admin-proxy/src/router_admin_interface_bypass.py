"""Rewrite the router's HTTP Host while using an explicit browser proxy.

Only the configured destination and target are intercepted; other TLS
connections pass through without decryption. See README.md for setup and
certificate policy.

``ROUTER_DESTINATION`` is the hostname the browser opens. ``ROUTER_TARGET`` is
the address the router accepts. Both fall back to the defaults below.
"""

import logging
import os

from mitmproxy import http, tls
from mitmproxy.net.http import url

ROUTER_HOST = "router.dbod.local"
ROUTER_IP = "192.168.8.1"
DESTINATION_VARIABLE = "ROUTER_DESTINATION"
TARGET_VARIABLE = "ROUTER_TARGET"


class ConfigError(ValueError):
    """A destination or target override is not a bare hostname or IP."""


def router_destination() -> str:
    """Hostname the browser connects to."""
    return _setting(DESTINATION_VARIABLE, ROUTER_HOST)


def router_target() -> str:
    """Address sent upstream and placed in the Host header."""
    return _setting(TARGET_VARIABLE, ROUTER_IP)


def tls_clienthello(data: tls.ClientHelloData) -> None:
    """Intercept only explicit router destinations, never based on SNI alone."""
    address = data.context.server.address
    try:
        allowed = {_identity(router_destination()), _identity(router_target())}
    except ConfigError:
        data.ignore_connection = True
        raise
    if address is None or _identity(address[0]) not in allowed:
        data.ignore_connection = True


def request(flow: http.HTTPFlow) -> None:
    """Rewrite only the router alias, preserving the scheme, port and path."""
    destination = router_destination()
    target = router_target()
    if _identity(flow.request.host) != _identity(destination):
        return
    flow.request.host = target
    flow.request.host_header = url.hostport(flow.request.scheme, target, flow.request.port)
    logging.info("Rewrote router request host from %s to %s", destination, target)


def _setting(name: str, default: str) -> str:
    raw = os.environ.get(name, default)
    host = raw.strip().rstrip(".")
    if (
        not host
        or any(character.isspace() for character in host)
        or any(character in host for character in "/\\?#@:")
    ):
        raise ConfigError(
            f"{name} must be a hostname or IPv4 address without a scheme, path, or port"
        )
    return host


def _identity(host: str) -> str:
    return host.rstrip(".").casefold()
