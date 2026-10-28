"""Provider-side record filtering; never filter only the visible page."""

from alidns import AliDNSError

RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "REDIRECT_URL", "FORWARD_URL"}


def list_records(client, domain, page, page_size, rr="", record_type=""):
    if not isinstance(rr, str) or len(rr) > 253 or any(ord(char) < 32 for char in rr):
        raise AliDNSError("InvalidRecordFilter")
    if record_type and record_type not in RECORD_TYPES:
        raise AliDNSError("InvalidRecordFilter")
    if not rr and not record_type:
        return client.list_records(domain, page, page_size)
    # This adapter currently uses the official AliDNS request model via the
    # existing guarded SDK call. RR/type filters and pagination are cloud-side.
    values = {"DomainName": domain, "PageNumber": page, "PageSize": page_size}
    if rr:
        values.update(RRKeyWord=rr, SearchMode="ADVANCED")
    if record_type:
        values["Type"] = record_type
    return client._call("DescribeDomainRecords", **values)
