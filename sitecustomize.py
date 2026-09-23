"""Rewrite Heroku Redis TLS URLs before Redash imports redis-py.

Heroku Key-Value Store requires TLS (rediss://) and uses self-signed
certificates. Redash 10.1 calls redis.from_url() without ssl_cert_reqs=None,
which raises CERTIFICATE_VERIFY_FAILED on session/page load. Addon updates
overwrite REDIS_URL / REDASH_REDIS_URL, so inject ssl_cert_reqs=none here at
process start instead of relying on a sticky config var.

Docker sets PYTHONPATH=/app so site.py auto-imports this file. Do not copy it
into system site-packages; the redash/redash:10.1.0 image cannot write there.
"""
import os
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_REDIS_URL_VARS = ("REDASH_REDIS_URL", "REDIS_URL", "RQ_REDIS_URL")


def _with_ssl_cert_reqs_none(url):
    if not url:
        return url
    parsed = urlparse(url)
    if parsed.scheme != "rediss":
        return url
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key.lower() == "ssl_cert_reqs" for key, _ in query):
        return url
    query.append(("ssl_cert_reqs", "none"))
    return urlunparse(parsed._replace(query=urlencode(query)))


def rewrite_heroku_redis_urls(environ=None):
    env = os.environ if environ is None else environ
    for name in _REDIS_URL_VARS:
        current = env.get(name)
        if not current:
            continue
        rewritten = _with_ssl_cert_reqs_none(current)
        if rewritten != current:
            env[name] = rewritten


rewrite_heroku_redis_urls()
