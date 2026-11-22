"""Check local HTTP boundaries with model doubles and synthetic bodies."""

import unittest
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

from backend.database import get_session
from backend.main import app, create_app


class RequestLimitTests(unittest.TestCase):
    def setUp(self):
        self.model = Mock(model_version="fixture-model", decision_threshold=0.5)
        self.model.predict.return_value = []
        self.app = create_app(lambda: self.model)
        self.database = Mock(side_effect=AssertionError("Request should fail before database access"))
        self.app.dependency_overrides[get_session] = self.database
        self.client = self.enterContext(TestClient(self.app, base_url="http://127.0.0.1"))

    def test_all_json_routes_require_explicit_uncompressed_json(self):
        routes = [
            ("POST", "/predict"),
            ("POST", "/analyze"),
            ("POST", "/incidents"),
            ("PATCH", "/incidents/596fcd38-3ea5-4d76-9a0d-d811d76ac2a7"),
            ("POST", "/incidents/596fcd38-3ea5-4d76-9a0d-d811d76ac2a7/notes"),
        ]
        for method, path in routes:
            for headers in (
                {},
                {"Content-Type": "text/plain"},
                {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            ):
                with self.subTest(path=path, headers=headers):
                    response = self.client.request(method, path, headers=headers, content=b"{}")
                    self.assertEqual(response.status_code, 415, response.text)
        self.model.predict.assert_not_called()
        self.database.assert_not_called()

    def test_rejects_oversized_and_invalid_declared_lengths(self):
        for value, status in (("2097153", 413), ("-1", 400), ("unknown", 400)):
            with self.subTest(value=value):
                response = self.client.post(
                    "/predict", content=b"",
                    headers={"Content-Type": "application/json", "Content-Length": value},
                )
                self.assertEqual(response.status_code, status, response.text)
        self.model.predict.assert_not_called()

    def test_accepts_a_body_exactly_at_cap_with_json_parameters(self):
        valid = b'{"records":[{}]}'
        with patch("backend.request_limits.MAX_JSON_BYTES", len(valid)):
            response = self.client.post(
                "/predict", content=valid, headers={"Content-Type": "application/json; charset=utf-8"}
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.model.predict.assert_called_once_with([{}])

    def test_json_and_csv_reject_ambiguous_body_headers(self):
        for path, media in (("/predict", "application/json"), ("/csv/preview", "text/csv")):
            for extra, status in (
                ([("Content-Length", "0"), ("Content-Length", "0")], 400),
                ([("Content-Length", "+0")], 400),
                ([("Content-Type", media)], 415),
                ([("Content-Encoding", "identity"), ("Content-Encoding", "identity")], 415),
            ):
                with self.subTest(path=path, headers=extra):
                    response = self.client.post(path, content=b"", headers=[("Content-Type", media), *extra])
                    self.assertEqual(response.status_code, status, response.text)
        self.model.predict.assert_not_called()


class StreamedRequestLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_caps_actual_stream_with_missing_or_underreported_length(self):
        model = Mock()
        application = create_app(lambda: model)
        database = Mock(side_effect=AssertionError("Large request reached a database dependency"))
        application.dependency_overrides[get_session] = database

        async def payload():
            yield b'{"records": ['
            yield b'{"fixture": "long enough to exceed the test cap"}]}'

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://127.0.0.1"
        ) as client:
            for length in (None, "1"):
                for path in ("/predict", "/analyze"):
                    with self.subTest(length=length, path=path):
                        headers = {"Content-Type": "application/json"}
                        if length is not None:
                            headers["Content-Length"] = length
                        with patch("backend.request_limits.MAX_JSON_BYTES", 24):
                            response = await client.post(path, headers=headers, content=payload())
                        self.assertEqual(response.status_code, 413, response.text)
                        self.assertEqual(
                            response.json(), {"detail": "JSON request bodies must be at most 2 MiB."}
                        )
        model.predict.assert_not_called()
        database.assert_not_called()


class LocalHostGuardTests(unittest.TestCase):
    def test_module_and_factory_accept_loopback_and_reject_other_hosts(self):
        for application in (app, create_app(Mock())):
            # Exercise request middleware without starting the prediction model.
            client = TestClient(application, base_url="http://127.0.0.1")
            self.addCleanup(client.close)
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/health", headers={"Host": "localhost:5173"}).status_code, 200)
            self.assertEqual(client.get("/health", headers={"Host": "example.invalid"}).status_code, 400)
