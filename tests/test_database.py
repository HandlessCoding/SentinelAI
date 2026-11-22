"""Check the effective libpq configuration without opening a connection."""

import os
import socket
import unittest
from unittest.mock import patch

from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg

from backend.database import DatabaseConfigurationError, database_url


class DatabaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {"SENTINELAI_DB_PASSWORD": "fixture-password"}, clear=True))
        self.enterContext(patch("backend.database.dotenv_values", return_value={}))

    def connection_parameters(self, host):
        with patch.dict(os.environ, {"SENTINELAI_DB_HOST": host}):
            return PGDialect_psycopg().create_connect_args(database_url())[1]

    def test_literal_loopback_address_overrides_inherited_connection_defaults(self):
        with patch.dict(os.environ, {"PGHOSTADDR": "192.0.2.1", "PGSERVICE": "other-service"}):
            for address in ("127.0.0.1", "::1"):
                with self.subTest(address=address):
                    params = self.connection_parameters(address)
                    self.assertEqual((params["host"], params["hostaddr"]), (address, address))

    def test_localhost_pins_each_loopback_address_in_resolver_order(self):
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 5432, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 5432)),
        ]
        with (
            patch("socket.getaddrinfo", return_value=answers + answers[:1]),
            patch.dict(os.environ, {"SENTINELAI_DB_PORT": "55432", "PGPORT": "60000"}),
        ):
            params = self.connection_parameters("localhost")
        self.assertEqual(params["host"], "localhost,localhost")
        self.assertEqual(params["hostaddr"], "::1,127.0.0.1")
        self.assertEqual(params["port"], 55432)

    def test_localhost_rejects_nonloopback_empty_and_failed_resolution(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 5432))]
        for result in (answers, [], OSError("fixture lookup failure")):
            with self.subTest(result=result), patch("socket.getaddrinfo") as lookup:
                if isinstance(result, OSError):
                    lookup.side_effect = result
                else:
                    lookup.return_value = result
                with self.assertRaisesRegex(DatabaseConfigurationError, "loopback"):
                    self.connection_parameters("localhost")

    def test_connection_policy_rejects_other_hosts_and_invalid_ports(self):
        for host in ("db.example", "0.0.0.0", "::", "127.0.0.1,192.0.2.1", "[::1]", "::1%1"):
            with self.subTest(host=host), self.assertRaises(DatabaseConfigurationError):
                self.connection_parameters(host)
        with patch.dict(os.environ, {"SENTINELAI_DB_PORT": "65536"}):
            with self.assertRaisesRegex(DatabaseConfigurationError, "valid PostgreSQL port"):
                database_url()
