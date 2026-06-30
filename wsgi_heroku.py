"""
WSGI entrypoint for Redash on Heroku.

Redash wraps the app with Werkzeug ProxyFix (x_host=1), which trusts
X-Forwarded-Host for redirect URL generation. Clients can supply that header
directly; Heroku forwards it even though the router does not trust it.

On Heroku the authoritative public hostname is already in the Host header.
Non-allowlisted X-Forwarded-Host values are stripped before Redash's ProxyFix
runs; allowlisted values are passed through for trusted proxy setups.
"""
import os
from urllib.parse import urlparse

from redash import create_app


def _parse_redash_host(value):
    if not value:
        return None, None
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    host = (parsed.netloc or parsed.path).lower()
    scheme = parsed.scheme or "https"
    return host, scheme


def _allowed_hosts():
    hosts = set()
    primary, _ = _parse_redash_host(os.environ.get("REDASH_HOST", ""))
    if primary:
        hosts.add(primary)
    for entry in os.environ.get("REDASH_ALLOWED_HOSTS", "").split(","):
        entry = entry.strip().lower()
        if entry:
            hosts.add(entry)
    return hosts


def _host_matches_allowlist(host_value, allowed_hosts):
    if not allowed_hosts:
        return True
    if not host_value:
        return False

    host_value = host_value.lower()
    hostname = host_value.split(":")[0]
    for allowed in allowed_hosts:
        if host_value == allowed:
            return True
        if hostname == allowed.split(":")[0]:
            return True
    return False


def _as_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


STRIP_X_FORWARDED_HOST = _as_bool("REDASH_STRIP_X_FORWARDED_HOST", True)
VALIDATE_HOST = _as_bool("REDASH_VALIDATE_HOST", True)

flask_app = create_app()

redash_host, redash_scheme = _parse_redash_host(os.environ.get("REDASH_HOST", ""))
if redash_host:
    flask_app.config["SERVER_NAME"] = redash_host
    if redash_scheme:
        flask_app.config["PREFERRED_URL_SCHEME"] = redash_scheme

allowed_hosts = _allowed_hosts()


def app(environ, start_response):
    if STRIP_X_FORWARDED_HOST:
        forwarded_host = environ.get("HTTP_X_FORWARDED_HOST")
        if forwarded_host and not _host_matches_allowlist(forwarded_host, allowed_hosts):
            environ.pop("HTTP_X_FORWARDED_HOST", None)

    if VALIDATE_HOST and not _host_matches_allowlist(environ.get("HTTP_HOST", ""), allowed_hosts):
        environ["HTTP_HOST"] = redash_host

    return flask_app(environ, start_response)
