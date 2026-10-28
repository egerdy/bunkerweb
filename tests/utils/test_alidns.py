"""Run with unittest; no real cloud credentials or DNS writes."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

from darabonba.exceptions import ResponseException

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src/common/utils"))
from alidns import AliDNSClient, AliDNSCredentials, AliDNSError, record_fingerprint


def response(payload):
    return {"body": payload, "statusCode": 200, "headers": {}}


class AliDNSTests(unittest.TestCase):
    def setUp(self):
        self.client = AliDNSClient(AliDNSCredentials("test-id", "not-a-real-secret", "fake-token"), ["example.com"])
        self.session = Mock()
        self.client._sdk.call_api = self.session.post
        self.record = {
            "RecordId": "123",
            "DomainName": "example.com",
            "RR": "acceptance",
            "Type": "TXT",
            "Value": "first",
            "Line": "default",
            "TTL": 600,
            "Status": "ENABLE",
        }

    def test_secrets_are_not_represented(self):
        credentials = AliDNSCredentials("test-id", "not-a-real-secret", "fake-token")
        for secret in ("test-id", "not-a-real-secret", "fake-token"):
            self.assertNotIn(secret, repr(credentials))
            self.assertNotIn(secret, repr(self.client))

    def test_uses_official_sdk_https_models_and_explicit_retry_policy(self):
        from alibabacloud_alidns20150109.client import Client

        self.assertIsInstance(self.client._sdk, Client)
        self.assertFalse(self.client._sdk._retry_options.retryable)
        self.assertEqual(self.client._sdk._endpoint, "alidns.aliyuncs.com")
        self.session.post.return_value = response({"RecordId": "456", "RequestId": "id-1"})
        self.client.add_record("EXAMPLE.COM.", {"RR": "acceptance", "Type": "TXT", "Value": "test"})
        params, request, runtime = self.session.post.call_args.args
        self.assertEqual(params.action, "AddDomainRecord")
        self.assertEqual(params.protocol, "HTTPS")
        self.assertEqual(request.query["DomainName"], "example.com")
        self.assertEqual(runtime.connect_timeout, 5000)
        self.assertEqual(runtime.read_timeout, 20000)
        self.assertFalse(runtime.ignore_ssl)

    def test_outside_domain_never_calls_cloud(self):
        with self.assertRaisesRegex(AliDNSError, "DomainOutsideScope"):
            self.client.list_records("other.com")
        self.session.post.assert_not_called()

    def test_record_id_from_other_zone_cannot_be_deleted(self):
        self.session.post.return_value = response({**self.record, "DomainName": "other.com"})
        with self.assertRaisesRegex(AliDNSError, "RecordOutsideScope"):
            self.client.delete_record("example.com", "123", record_fingerprint(self.record))
        self.assertEqual(self.session.post.call_count, 1)

    def test_stale_form_never_writes(self):
        self.session.post.return_value = response({**self.record, "Value": "changed-in-cloud"})
        with self.assertRaisesRegex(AliDNSError, "RecordChanged"):
            self.client.update_record("example.com", "123", {"RR": "acceptance", "Type": "TXT", "Value": "new"}, record_fingerprint(self.record))
        self.assertEqual(self.session.post.call_count, 1)

    def test_delete_checks_current_record_then_writes_once(self):
        self.session.post.side_effect = [response(self.record), response({"RecordId": "123"})]
        self.client.delete_record("example.com", "123", record_fingerprint(self.record))
        self.assertEqual([call.args[0].action for call in self.session.post.call_args_list], ["DescribeDomainRecordInfo", "DeleteDomainRecord"])

    def test_write_timeout_is_unknown_and_not_retried(self):
        self.session.post.side_effect = TimeoutError("sensitive transport details")
        with self.assertRaises(AliDNSError) as error:
            self.client.add_record("example.com", {"RR": "acceptance", "Type": "TXT", "Value": "test"})
        self.assertTrue(error.exception.outcome_unknown)
        self.assertNotIn("sensitive", str(error.exception))
        self.assertEqual(self.session.post.call_count, 1)

    def test_read_timeout_is_not_a_possible_write(self):
        self.session.post.side_effect = TimeoutError()
        with self.assertRaises(AliDNSError) as error:
            self.client.list_records("example.com")
        self.assertFalse(error.exception.outcome_unknown)

    def test_provider_error_message_and_invalid_request_id_are_not_exposed(self):
        self.session.post.side_effect = ResponseException(
            code="InvalidAccessKeyId.NotFound", message="not-a-real-secret", status_code=403, data={"RequestId": {"bad": "value"}}
        )
        with self.assertRaises(AliDNSError) as error:
            self.client.list_records("example.com")
        self.assertEqual(str(error.exception), "InvalidAccessKeyId.NotFound")
        self.assertEqual(error.exception.request_id, "")

    def test_ambiguous_server_error_is_unknown(self):
        self.session.post.side_effect = ResponseException(code="InternalError", message="internal", status_code=503)
        with self.assertRaises(AliDNSError) as error:
            self.client.add_record("example.com", {"RR": "acceptance", "Type": "TXT", "Value": "test"})
        self.assertTrue(error.exception.outcome_unknown)

    def test_missing_write_receipt_is_unknown(self):
        self.session.post.return_value = response({"RequestId": "receipt-without-record"})
        with self.assertRaises(AliDNSError) as error:
            self.client.add_record("example.com", {"RR": "acceptance", "Type": "TXT", "Value": "test"})
        self.assertTrue(error.exception.outcome_unknown)

    def test_validation_prevents_invalid_calls(self):
        for values in (
            {"RR": "x", "Type": "TXT", "Value": "v", "TTL": True},
            {"RR": "x", "Type": "TXT", "Value": "v", "AccessKeyId": "injected"},
            {"RR": "x", "Type": "MX", "Value": "mail.example.com"},
        ):
            with self.assertRaises(AliDNSError):
                self.client.add_record("example.com", values)
        for size in (True, 0, 501):
            with self.assertRaisesRegex(AliDNSError, "InvalidPagination"):
                self.client.list_records("example.com", page_size=size)
        self.session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
