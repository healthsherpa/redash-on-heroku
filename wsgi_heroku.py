"""
WSGI entrypoint for Redash on Heroku.

Redash wraps the app with Werkzeug ProxyFix (x_host=1), which trusts
X-Forwarded-Host for redirect URL generation. Clients can supply that header
directly; Heroku forwards it even though the router does not trust it.

On Heroku the authoritative public hostname is already in the Host header, so
we strip X-Forwarded-Host before the request reaches Redash and optionally pin
Flask's SERVER_NAME to REDASH_HOST.
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


def _host_is_allowed(host_header, allowed_hosts):
    if not allowed_hosts:
        return True
    if not host_header:
        return False

    host_header = host_header.lower()
    hostname = host_header.split(":")[0]
    for allowed in allowed_hosts:
        if host_header == allowed:
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
        environ.pop("HTTP_X_FORWARDED_HOST", None)

    if VALIDATE_HOST and allowed_hosts:
        if not _host_is_allowed(environ.get("HTTP_HOST", ""), allowed_hosts):
            start_response(
                "400 Bad Request",
                [("Content-Type", "text/plain; charset=utf-8")],
            )
            return [b"Invalid Host header"]

    return flask_app(environ, start_response)
