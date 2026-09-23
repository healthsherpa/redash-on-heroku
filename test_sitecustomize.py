import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Homebrew (and some distros) already ship a sitecustomize; load this repo's
# file by path so the tests exercise our rewrite, not the interpreter's hook.
_SPEC = importlib.util.spec_from_file_location(
    "heroku_sitecustomize",
    Path(__file__).resolve().parent / "sitecustomize.py",
)
sitecustomize = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sitecustomize)

_REDIS_URL_VARS = sitecustomize._REDIS_URL_VARS
_with_ssl_cert_reqs_none = sitecustomize._with_ssl_cert_reqs_none
rewrite_heroku_redis_urls = sitecustomize.rewrite_heroku_redis_urls


class WithSslCertReqsNoneTest(unittest.TestCase):
    def test_empty_and_none_unchanged(self):
        self.assertEqual(_with_ssl_cert_reqs_none(""), "")
        self.assertIsNone(_with_ssl_cert_reqs_none(None))

    def test_redis_scheme_unchanged(self):
        url = "redis://dummy-redis:6379/0"
        self.assertEqual(_with_ssl_cert_reqs_none(url), url)

    def test_rediss_without_query_appends_param(self):
        url = "rediss://:dummy-pass@dummy-redis:6379/0"
        self.assertEqual(
            _with_ssl_cert_reqs_none(url),
            "rediss://:dummy-pass@dummy-redis:6379/0?ssl_cert_reqs=none",
        )

    def test_preserves_existing_query_params(self):
        url = "rediss://dummy-redis:6379/0?foo=bar"
        self.assertEqual(
            _with_ssl_cert_reqs_none(url),
            "rediss://dummy-redis:6379/0?foo=bar&ssl_cert_reqs=none",
        )

    def test_leaves_existing_ssl_cert_reqs_alone(self):
        url = "rediss://dummy-redis:6379/0?ssl_cert_reqs=required"
        self.assertEqual(_with_ssl_cert_reqs_none(url), url)

    def test_ssl_cert_reqs_check_is_case_insensitive(self):
        url = "rediss://dummy-redis:6379/0?SSL_CERT_REQS=none"
        self.assertEqual(_with_ssl_cert_reqs_none(url), url)

    def test_preserves_fragment(self):
        url = "rediss://dummy-redis:6379/0#health"
        self.assertEqual(
            _with_ssl_cert_reqs_none(url),
            "rediss://dummy-redis:6379/0?ssl_cert_reqs=none#health",
        )

    def test_preserves_query_and_fragment(self):
        url = "rediss://dummy-redis:6379/0?foo=bar#health"
        self.assertEqual(
            _with_ssl_cert_reqs_none(url),
            "rediss://dummy-redis:6379/0?foo=bar&ssl_cert_reqs=none#health",
        )

    def test_preserves_encoded_password(self):
        url = "rediss://:p%40ss%3Aword@dummy-redis:6379/0"
        self.assertEqual(
            _with_ssl_cert_reqs_none(url),
            "rediss://:p%40ss%3Aword@dummy-redis:6379/0?ssl_cert_reqs=none",
        )


class RewriteHerokuRedisUrlsTest(unittest.TestCase):
    def test_rewrites_only_rediss_vars_that_lack_ssl_cert_reqs(self):
        environ = {
            "REDASH_REDIS_URL": "rediss://dummy-redis:6379/0",
            "REDIS_URL": "redis://dummy-redis:6379/0",
            "RQ_REDIS_URL": "rediss://dummy-redis:6379/0?ssl_cert_reqs=none",
            "UNRELATED": "rediss://dummy-redis:6379/0",
        }
        rewrite_heroku_redis_urls(environ)
        self.assertEqual(
            environ["REDASH_REDIS_URL"],
            "rediss://dummy-redis:6379/0?ssl_cert_reqs=none",
        )
        self.assertEqual(environ["REDIS_URL"], "redis://dummy-redis:6379/0")
        self.assertEqual(
            environ["RQ_REDIS_URL"],
            "rediss://dummy-redis:6379/0?ssl_cert_reqs=none",
        )
        self.assertEqual(environ["UNRELATED"], "rediss://dummy-redis:6379/0")

    def test_skips_missing_and_empty_vars(self):
        environ = {"REDASH_REDIS_URL": ""}
        rewrite_heroku_redis_urls(environ)
        self.assertEqual(environ["REDASH_REDIS_URL"], "")

    def test_idempotent(self):
        environ = {"REDIS_URL": "rediss://dummy-redis:6379/0"}
        rewrite_heroku_redis_urls(environ)
        first = dict(environ)
        rewrite_heroku_redis_urls(environ)
        self.assertEqual(environ, first)

    def test_covers_all_documented_var_names(self):
        self.assertEqual(
            _REDIS_URL_VARS,
            ("REDASH_REDIS_URL", "REDIS_URL", "RQ_REDIS_URL"),
        )


class PythonpathAutoloadTest(unittest.TestCase):
    def test_sitecustomize_autoloads_when_repo_is_on_pythonpath(self):
        """Docker sets PYTHONPATH=/app so site.py imports /app/sitecustomize.py."""
        repo = str(Path(__file__).resolve().parent)
        env = os.environ.copy()
        env["PYTHONPATH"] = repo
        env["REDIS_URL"] = "rediss://dummy-redis:6379/0"
        env["REDASH_REDIS_URL"] = "rediss://dummy-redis:6379/1"
        env["RQ_REDIS_URL"] = "redis://dummy-redis:6379/2"
        script = (
            "import os;"
            "print(os.environ['REDIS_URL']);"
            "print(os.environ['REDASH_REDIS_URL']);"
            "print(os.environ['RQ_REDIS_URL'])"
        )
        output = subprocess.check_output(
            [sys.executable, "-c", script],
            env=env,
            cwd=tempfile.gettempdir(),
            text=True,
        )
        redis_url, redash_url, rq_url = output.strip().splitlines()
        self.assertEqual(
            redis_url,
            "rediss://dummy-redis:6379/0?ssl_cert_reqs=none",
        )
        self.assertEqual(
            redash_url,
            "rediss://dummy-redis:6379/1?ssl_cert_reqs=none",
        )
        self.assertEqual(rq_url, "redis://dummy-redis:6379/2")


if __name__ == "__main__":
    unittest.main()
