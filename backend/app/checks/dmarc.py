import dns.resolver
import dns.exception
from typing import Dict, Any, List
from app.models import CheckResult, CheckStatus
from app.resolver import get_dns_resolver


def parse_dmarc_tags(raw_record: str) -> Dict[str, str]:
    tags = {}
    parts = raw_record.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def check_dmarc(domain: str, timeout: float = 3.0) -> CheckResult:
    """
    Checks DMARC record for the given domain:
    - Query TXT record at _dmarc.<domain>.
    - Pass if 'v=DMARC1' present and policy is enforcing (quarantine/reject).
    - Parse policy (p=none/quarantine/reject), pct=, rua=/ruf= reporting addresses.
    - Flag: missing record, p=none (monitoring only, not enforcing), pct < 100.
    """
    dmarc_domain = f"_dmarc.{domain}"
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": f"No TXT record found at {dmarc_domain}."
            },
            recommendation=f"Create a DMARC TXT record at '_dmarc.{domain}' (e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}') to instruct mail receivers how to handle failed authentication."
        )
    except dns.exception.Timeout:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.UNKNOWN,
            details={
                "found": False,
                "record": None,
                "message": "DNS query timed out while resolving DMARC record."
            },
            recommendation=f"DNS query timed out for {dmarc_domain}. Check nameserver responsiveness."
        )
    except Exception as e:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": f"DNS resolution error: {str(e)}"
            },
            recommendation=f"Publish a DMARC record at '_dmarc.{domain}' once nameserver errors are resolved."
        )

    dmarc_records: List[str] = []
    for rdata in answers:
        txt_strings = [part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings]
        combined = "".join(txt_strings).strip()
        if combined.startswith("v=DMARC1"):
            dmarc_records.append(combined)

    if not dmarc_records:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": f"TXT records exist at {dmarc_domain} but none start with 'v=DMARC1'."
            },
            recommendation=f"Add a valid DMARC record starting with 'v=DMARC1' at '_dmarc.{domain}'."
        )

    if len(dmarc_records) > 1:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.WARN,
            details={
                "found": True,
                "record": dmarc_records[0],
                "all_records": dmarc_records,
                "multiple_records": True,
                "message": f"Multiple DMARC records found ({len(dmarc_records)}). Only one DMARC record is permitted per RFC 7489."
            },
            recommendation=f"Remove duplicate DMARC records at '_dmarc.{domain}' to prevent receiving MTAs from ignoring DMARC policies."
        )

    record = dmarc_records[0]
    tags = parse_dmarc_tags(record)
    policy = tags.get("p", "").lower()
    subdomain_policy = tags.get("sp", "").lower()
    pct = tags.get("pct", "100")
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")

    try:
        pct_int = int(pct)
    except ValueError:
        pct_int = 100

    details: Dict[str, Any] = {
        "found": True,
        "record": record,
        "policy": policy,
        "subdomain_policy": subdomain_policy if subdomain_policy else policy,
        "pct": pct_int,
        "rua": rua,
        "ruf": ruf,
        "tags": tags
    }

    # Evaluation
    if not policy:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Specify a policy tag 'p=' (e.g. 'p=quarantine' or 'p=reject') in your DMARC record at '_dmarc.{domain}'."
        )

    if policy == "none":
        return CheckResult(
            name="DMARC",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Upgrade your DMARC policy at '_dmarc.{domain}' from 'p=none' to 'p=quarantine' or 'p=reject' to actively block spoofed emails."
        )

    if pct_int < 100:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Increase DMARC 'pct' tag from {pct_int}% to 100% at '_dmarc.{domain}' to ensure enforcement across all outbound mail."
        )

    if not rua:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.PASS,
            details={**details, "warning": "No rua aggregate reporting tag defined."},
            recommendation=f"Add an aggregate reporting address 'rua=mailto:dmarc-reports@{domain}' to your DMARC record to receive authentication failure reports."
        )

    return CheckResult(
        name="DMARC",
        status=CheckStatus.PASS,
        details=details,
        recommendation=None
    )
