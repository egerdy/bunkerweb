"""Record filters must reach the provider before pagination."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src/common/utils"), str(ROOT / "misc/plugins/dnsmanager/ui/blueprints")]
from alidns import AliDNSClient, AliDNSCredentials, AliDNSError
from bw_dnsmanager.record_filters import list_records
import test_dnsmanager as fixtures


class FilterTests(unittest.TestCase):
    def test_filter_uses_official_sdk_models_and_retains_cloud_total(self):
        c = AliDNSClient(AliDNSCredentials("fake-id", "fake-secret"), ["example.com"])
        c._sdk.call_api = Mock(return_value={"body": {"DomainRecords": {"Record": []}, "TotalCount": 125}, "statusCode": 200, "headers": {}})
        payload = list_records(c, "example.com", 2, 50, "www", "CNAME")
        params, request, runtime = c._sdk.call_api.call_args.args
        self.assertEqual(params.action, "DescribeDomainRecords")
        self.assertEqual(request.query["RRKeyWord"], "www")
        self.assertEqual(request.query["Type"], "CNAME")
        self.assertEqual(request.query["PageNumber"], "2")
        self.assertEqual(request.query["SearchMode"], "ADVANCED")
        self.assertEqual(payload["TotalCount"], 125)

    def test_empty_filters_use_existing_pagination(self):
        c = Mock()
        list_records(c, "example.com", 3, 50)
        c.list_records.assert_called_once_with("example.com", 3, 50)
        c._call.assert_not_called()

    def test_invalid_filter_is_rejected_before_cloud_call(self):
        for rr, kind in [("x" * 254, "A"), ("www\x00", "A"), ("www", "INVALID")]:
            c = Mock()
            with self.assertRaisesRegex(AliDNSError, "InvalidRecordFilter"):
                list_records(c, "example.com", 1, 50, rr, kind)
            c._call.assert_not_called()
            c.list_records.assert_not_called()

    def test_http_query_filters_before_paginating(self):
        fixtures.HTTPTests.setUpClass()
        f = fixtures.HTTPTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.cloud._call.return_value = {"DomainRecords": {"Record": []}, "TotalCount": 125}
        reply = f.client.get("/dnsmanager/records?account=" + f.account_id + "&domain=example.com&page=2&rr=www&type=cname", headers={"X-Test-User": "reader"})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json["total"], 125)
        self.assertEqual(reply.json["page"], 2)
        f.cloud._call.assert_called_once_with(
            "DescribeDomainRecords", DomainName="example.com", PageNumber=2, PageSize=50, RRKeyWord="www", SearchMode="ADVANCED", Type="CNAME"
        )


if __name__ == "__main__":
    unittest.main()
