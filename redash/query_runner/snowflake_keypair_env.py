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
    noop_query = "SELECT 1"
    should_annotate_query = False
    
    @classmethod
    def name(cls):
        return "Snowflake (Key Pair Auth)"
    
    @classmethod
    def type(cls):
        return "snowflake_keypair_env"
    
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
        logger.error("=== SNOWFLAKE CONNECTION ATTEMPT ===")
        logger.error("Configuration: %s", self.configuration)
        
        params = {
            "account": self.configuration.get("account"),
            "user": self.configuration.get("user"),
            "warehouse": self.configuration.get("warehouse"),
            "database": self.configuration.get("database"),
            "schema": self.configuration.get("schema"),
            "role": self.configuration.get("role"),
        }
        logger.error("Connection params: %s", params)

        env_var = self.configuration.get("private_key_env_var")
        logger.error("Private key env var: %s", env_var)
        
        if env_var:
            pem_b64 = os.environ.get(env_var)
            if not pem_b64:
                logger.error("Environment variable %s not set!", env_var)
                raise Exception(f"Environment variable {env_var} not set")
            logger.error("Private key loaded: %d bytes", len(pem_b64))
            
            try:
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
                logger.error("Private key processed successfully")
            except Exception as e:
                logger.error("Private key processing failed: %s", str(e))
                raise

        logger.error("Attempting Snowflake connection...")
        try:
            connection = snowflake.connector.connect(**params)
            logger.error("Snowflake connection successful!")
            return connection
        except Exception as e:
            logger.error("Snowflake connection failed: %s", str(e))
            raise

    def test_connection(self):
        """Test the connection by running a simple query"""
        try:
            logger.info("Testing Snowflake connection...")
            connection = self._get_connection()
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                logger.info("Snowflake connection test successful: %s", result)
            finally:
                cursor.close()
                connection.close()
        except Exception as e:
            logger.error("Snowflake connection test failed: %s", str(e))
            raise e

    def run_query(self, query, user):
        logger.info("Running Snowflake query: %s", query[:100] if len(query) > 100 else query)
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
            logger.info("Snowflake query successful, returned %d rows", len(rows))
        except Exception as e:
            logger.exception("Snowflake query failed")
            error = str(e)
            json_data = None
        finally:
            cursor.close()
            connection.close()
        return json_data, error


register(SnowflakeKeyPairEnv)
