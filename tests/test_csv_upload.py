"""Exercise the bounded CSV preview endpoint with small synthetic uploads."""

import csv
from io import StringIO
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.schemas import MAX_BATCH_SIZE
from ml.inference import FEATURE_TYPES


SAMPLE = dict.fromkeys(FEATURE_TYPES, "0")
SAMPLE.update(proto="tcp", state="FIN", service="-", is_ftp_login="4")


def make_csv(rows, columns=None):
    text = StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=columns or list(FEATURE_TYPES))
    writer.writeheader()
    writer.writerows(rows)
    return text.getvalue().encode("utf-8")


class CSVUploadTests(unittest.TestCase):
    def setUp(self):
        self.model = Mock()
        self.client = self.enterContext(TestClient(create_app(lambda: self.model), base_url="http://127.0.0.1"))
        self.headers = {"Content-Type": "text/csv; charset=utf-8"}

    def upload(self, body):
        return self.client.post("/csv/preview", content=body, headers=self.headers)

    def test_preview_rejects_a_record_that_cannot_fit_in_a_json_request(self):
        long_field = "\x01" * 120_000
        body = make_csv([{**SAMPLE, "proto": long_field, "service": long_field, "state": long_field}])
        self.assertLess(len(body), 2 * 1024**2)
        response = self.upload(body)
        self.assertEqual(response.status_code, 413)
        self.assertIn("Record 1", response.json()["detail"])

    def test_preview_preserves_record_order_and_strips_optional_metadata(self):
        rows = [
            {**SAMPLE, "id": "wire-1", "label": "metadata", "attack_cat": "ignored"},
            {**SAMPLE, "proto": "quoted,value", "dur": "0.5", "id": "wire-2", "label": "", "attack_cat": ""},
        ]
        response = self.upload(b"\xef\xbb\xbf" + make_csv(rows, list(rows[0])))
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["columns"], list(FEATURE_TYPES))
        self.assertEqual(result["records"], [
            SAMPLE, {**SAMPLE, "proto": "quoted,value", "dur": "0.5"},
        ])
        self.assertEqual(result["batch_size"], MAX_BATCH_SIZE)
        self.assertRegex(result["upload_id"], r"^[a-f0-9]{64}$")
        self.model.predict.assert_not_called()

    def test_preview_id_ignores_header_order_and_metadata_but_tracks_predictors(self):
        rows = [SAMPLE, {**SAMPLE, "dur": "1.5"}]
        original = self.upload(make_csv(rows)).json()["upload_id"]
        other_columns = [*reversed(FEATURE_TYPES), "id", "label"]
        same = self.upload(make_csv([{**row, "id": "2", "label": "1"} for row in rows], other_columns))
        changed = self.upload(make_csv([rows[0], {**rows[1], "dur": "2.5"}]))
        reversed_rows = self.upload(make_csv(reversed(rows)))
        self.assertEqual(original, same.json()["upload_id"])
        self.assertNotEqual(original, changed.json()["upload_id"])
        self.assertNotEqual(original, reversed_rows.json()["upload_id"])

    def test_rejects_missing_duplicate_and_unrecognized_columns(self):
        for header, detail in [
            (b"proto,service\n", "missing columns"),
            (b"proto,proto\n", "duplicate column names"),
            (b",".join(name.encode() for name in FEATURE_TYPES) + b",sample-unknown\n", "unrecognized"),
        ]:
            with self.subTest(detail=detail):
                response = self.upload(header)
                self.assertEqual(response.status_code, 422)
                self.assertIn(detail, response.json()["detail"])
                self.assertNotIn("sample-unknown", response.json()["detail"])

    def test_rejects_empty_invalid_encoding_and_malformed_csv(self):
        header = make_csv([])
        for body, detail in [
            (b"", "empty"),
            (b"\xff\xff", "UTF-8"),
            (b"\x00", "null"),
            (header, "at least one record"),
            (header + b"1,2\n", "expected 42"),
            (header + b'"unclosed\n', "Invalid CSV"),
        ]:
            with self.subTest(detail=detail):
                response = self.upload(body)
                self.assertEqual(response.status_code, 422)
                self.assertIn(detail, response.json()["detail"])

    def test_rejects_invalid_feature_values_with_record_and_field(self):
        for field, invalid, detail in [
            ("dur", "NaN", "expected a finite number"),
            ("spkts", "1.5", "expected an integer"),
            ("proto", " ", "value is missing"),
        ]:
            with self.subTest(field=field):
                response = self.upload(make_csv([SAMPLE, {**SAMPLE, field: invalid}]))
                self.assertEqual(response.status_code, 422)
                self.assertEqual(
                    response.json()["detail"], f"Record 2, field {field!r}: {detail}",
                )

    def test_enforces_stream_and_declared_byte_limits(self):
        with patch("backend.csv_uploads.MAX_CSV_BYTES", 8):
            declared = self.upload(b"123456789")
            streamed = self.upload(iter([b"1234", b"56789"]))
        self.assertEqual(declared.status_code, 413)
        self.assertEqual(streamed.status_code, 413)

    def test_enforces_record_bound(self):
        with patch("backend.csv_uploads.MAX_CSV_RECORDS", 2):
            accepted = self.upload(make_csv([SAMPLE, SAMPLE]))
            rejected = self.upload(make_csv([SAMPLE, SAMPLE, SAMPLE]))
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(rejected.status_code, 413)
        self.assertIn("at most 2 records", rejected.json()["detail"])

    def test_rejects_non_csv_and_compressed_requests(self):
        wrong_type = self.client.post("/csv/preview", json={"rows": []})
        compressed = self.client.post(
            "/csv/preview", content=b"gzip", headers={**self.headers, "Content-Encoding": "gzip"}
        )
        self.assertEqual(wrong_type.status_code, 415)
        self.assertEqual(compressed.status_code, 415)
