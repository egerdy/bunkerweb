"""Compatibility/record ownership checks for the selected third-party adapter."""

import unittest
from importlib.metadata import entry_points, version
from unittest.mock import Mock, patch
from io import BytesIO

from certbot_dns_aliyun_next.dns_aliyun_next import _AliCloudDNSHelper, Authenticator
from certbot_dns_aliyun_next.aliyun_client import AliCloudDNSClient
from darabonba.core import DaraCore
from darabonba.response import DaraResponse


class AliyunNextTests(unittest.TestCase):
    def setUp(self):
        self.helper = _AliCloudDNSHelper("fake-id", "fake-secret", "cn-hangzhou", 600)
        self.helper.client = Mock()
        self.helper.client.list_zones.return_value = ["example.com", "test.example.com"]
        self.helper.client.get_domain_records.return_value = []
        self.helper.client.add_domain_record.return_value = "new-record-id"

    def test_certbot_58_discovers_authenticator(self):
        self.assertEqual(version("certbot"), "5.8.0")
        entry = next(item for item in entry_points(group="certbot.plugins") if item.name == "dns-aliyun-next")
        self.assertIs(entry.load(), Authenticator)

    def test_real_sdk_request_path_uses_compatible_runtime_and_parses_response(self):
        client = AliCloudDNSClient("fake-id", "fake-secret")
        response = DaraResponse()
        response.status_code = 200
        response.headers = {}
        response.body = BytesIO(b'{"TotalCount":1,"Domains":{"Domain":[{"DomainName":"example.com"}]}}')
        with patch.object(DaraCore, "do_action", return_value=response) as transport:
            self.assertEqual(client.list_zones(), ["example.com"])
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.args[0].protocol, "HTTPS")

    def test_creates_in_longest_matching_zone_and_cleans_own_id(self):
        name = "_acme-challenge.new.test.example.com"
        self.helper.add_txt_record(name, "challenge-one")
        self.helper.client.add_domain_record.assert_called_once_with("test.example.com", "_acme-challenge.new", "TXT", "challenge-one", 600)
        self.helper.del_txt_record(name, "challenge-one")
        self.helper.client.delete_domain_record.assert_called_once_with("new-record-id")

    def test_preexisting_identical_record_is_not_deleted(self):
        self.helper.client.get_domain_records.return_value = [{"record_id": "preexisting", "value": "challenge-one"}]
        self.helper.add_txt_record("_acme-challenge.test.example.com", "challenge-one")
        self.helper.del_txt_record("_acme-challenge.test.example.com", "challenge-one")
        self.helper.client.add_domain_record.assert_not_called()
        self.helper.client.delete_domain_record.assert_not_called()

    def test_other_txt_value_is_not_replaced_or_deleted(self):
        self.helper.client.get_domain_records.return_value = [{"record_id": "someone-elses", "value": "other-challenge"}]
        name = "_acme-challenge.test.example.com"
        self.helper.add_txt_record(name, "challenge-one")
        self.helper.del_txt_record(name, "unknown-value")
        self.helper.client.delete_domain_record.assert_not_called()
        self.helper.del_txt_record(name, "challenge-one")
        self.helper.client.delete_domain_record.assert_called_once_with("new-record-id")
        self.helper.client.update_domain_record.assert_not_called()

    def test_duplicate_challenge_waits_for_last_cleanup(self):
        name = "_acme-challenge.test.example.com"
        self.helper.add_txt_record(name, "challenge-one")
        self.helper.add_txt_record(name, "challenge-one")
        self.helper.del_txt_record(name, "challenge-one")
        self.helper.client.delete_domain_record.assert_not_called()
        self.helper.del_txt_record(name, "challenge-one")
        self.helper.client.delete_domain_record.assert_called_once_with("new-record-id")


if __name__ == "__main__":
    unittest.main()
