import base64
import logging

from redash.query_runner import (
    BaseSQLQueryRunner,
    register,
    TYPE_STRING,
    TYPE_BOOLEAN,
    TYPE_DATETIME,
    TYPE_INTEGER,
    TYPE_FLOAT,
)
from redash.utils import json_dumps

logger = logging.getLogger(__name__)

try:
    import snowflake.connector
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    import os

    enabled = True
except ImportError:
    enabled = False


TYPES_MAP = {
    "TEXT": TYPE_STRING,
    "BOOLEAN": TYPE_BOOLEAN,
    "DATE": TYPE_DATETIME,
    "TIMESTAMP": TYPE_DATETIME,
    "TIMESTAMP_LTZ": TYPE_DATETIME,
    "TIMESTAMP_TZ": TYPE_DATETIME,
    "TIMESTAMP_NTZ": TYPE_DATETIME,
    "NUMBER": TYPE_FLOAT,
    "FLOAT": TYPE_FLOAT,
    "REAL": TYPE_FLOAT,
    "DOUBLE": TYPE_FLOAT,
    "INT": TYPE_INTEGER,
    "INTEGER": TYPE_INTEGER,
}


class SnowflakeKeyPairEnv(BaseSQLQueryRunner):
    should_annotate_query = False

    @classmethod
    def configuration_schema(cls):
        return {
            "type": "object",
            "properties": {
                "account": {"type": "string"},
                "user": {"type": "string"},
                "warehouse": {"type": "string"},
                "database": {"type": "string"},
                "role": {"type": "string"},
                "schema": {"type": "string"},
                # only the NAME of the env var is stored in DB
                "private_key_env_var": {"type": "string"},
                "private_key_pwd": {"type": "string"},
            },
            "order": [
                "account",
                "user",
                "warehouse",
                "database",
                "schema",
                "role",
                "private_key_env_var",
                "private_key_pwd",
            ],
            "required": ["account", "user", "warehouse", "database", "private_key_env_var"],
            "secret": ["private_key_env_var", "private_key_pwd"],
        }

    @classmethod
    def enabled(cls):
        return enabled

    def _get_connection(self):
        params = {
            "account": self.configuration.get("account"),
            "user": self.configuration.get("user"),
            "warehouse": self.configuration.get("warehouse"),
            "database": self.configuration.get("database"),
            "schema": self.configuration.get("schema"),
            "role": self.configuration.get("role"),
        }

        env_var = self.configuration.get("private_key_env_var")
        if env_var:
            pem_b64 = os.environ.get(env_var)
            if not pem_b64:
                raise Exception(f"Environment variable {env_var} not set")
            pkey_bytes = base64.b64decode(pem_b64)
            passphrase = self.configuration.get("private_key_pwd")
            private_key = serialization.load_pem_private_key(
                pkey_bytes,
                password=passphrase.encode() if passphrase else None,
                backend=default_backend(),
            )
            pkb = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            params["private_key"] = pkb

        logger.debug("Snowflake connect with params: %s", params.keys())
        return snowflake.connector.connect(**params)

    def run_query(self, query, user):
        connection = self._get_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(query)
            columns = self.fetch_columns(
                [(col[0], TYPES_MAP.get(col[1], TYPE_STRING)) for col in cursor.description]
            )
            rows = [dict(zip((c["name"] for c in columns), r)) for r in cursor]
            data = {"columns": columns, "rows": rows}
            error = None
            json_data = json_dumps(data, default=str)
        except Exception as e:
            logger.exception("Snowflake query failed")
            error = str(e)
            json_data = None
        finally:
            cursor.close()
            connection.close()
        return json_data, error


register(SnowflakeKeyPairEnv)
