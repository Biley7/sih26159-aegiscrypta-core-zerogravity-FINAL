import dns.resolver
import dns.exception
from typing import Dict, Any, List
from app.models import CheckResult, CheckStatus
from app.resolver import get_dns_resolver


def check_spf(domain: str, timeout: float = 3.0) -> CheckResult:
    """
    Checks SPF record for the given domain:
    - Query TXT records at the root domain.
    - Pass if a record starting with 'v=spf1' exists.
    - Flag issues: missing record, multiple SPF records, overly permissive '+all' or bare 'all',
      too many DNS lookups (>10, per RFC 7208 limit approximation).
    """
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="SPF",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": f"No TXT records found for {domain}."
            },
            recommendation=f"Add a valid SPF TXT record at '{domain}' (e.g. 'v=spf1 include:_spf.example.com -all') to authorize legitimate mail senders and stop spoofing."
        )
    except dns.exception.Timeout:
        return CheckResult(
            name="SPF",
            status=CheckStatus.UNKNOWN,
            details={
                "found": False,
                "record": None,
                "message": "DNS query timed out while resolving SPF record."
            },
            recommendation=f"DNS query timed out for {domain}. Verify authoritative nameserver health."
        )
    except Exception as e:
        return CheckResult(
            name="SPF",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": f"DNS resolution error: {str(e)}"
            },
            recommendation=f"Ensure your domain '{domain}' has accessible DNS nameservers and a valid SPF record."
        )

    # Collect SPF records
    spf_records: List[str] = []
    for rdata in answers:
        txt_strings = [part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings]
        combined_txt = "".join(txt_strings).strip()
        if combined_txt.startswith("v=spf1"):
            spf_records.append(combined_txt)

    if not spf_records:
        return CheckResult(
            name="SPF",
            status=CheckStatus.FAIL,
            details={
                "found": False,
                "record": None,
                "message": "No SPF (v=spf1) record found among domain TXT records."
            },
            recommendation=f"Add an SPF TXT record to {domain} with authorized mail servers and strict policy (e.g., 'v=spf1 include:_spf.example.com -all')."
        )

    if len(spf_records) > 1:
        return CheckResult(
            name="SPF",
            status=CheckStatus.WARN,
            details={
                "found": True,
                "record": spf_records[0],
                "all_records": spf_records,
                "multiple_records": True,
                "message": f"Multiple SPF records found ({len(spf_records)}). RFC 7208 states a domain must not have more than one SPF record."
            },
            recommendation=f"Consolidate multiple SPF records for {domain} into a single record to prevent SPF validation errors and email delivery failures."
        )

    record = spf_records[0]
    tokens = record.split()

    # Analyze mechanisms
    dns_lookup_mechanisms = 0
    all_mechanism = None
    has_redirect = False

    for token in tokens[1:]:
        token_lower = token.lower()
        if token_lower.startswith("include:") or token_lower.startswith("a:") or token_lower == "a" or \
           token_lower.startswith("mx:") or token_lower == "mx" or token_lower.startswith("exists:") or \
           token_lower.startswith("ptr:") or token_lower == "ptr":
            dns_lookup_mechanisms += 1
        elif token_lower.startswith("redirect="):
            dns_lookup_mechanisms += 1
            has_redirect = True
        elif token_lower in ["+all", "all", "-all", "~all", "?all"]:
            all_mechanism = token_lower

    details: Dict[str, Any] = {
        "found": True,
        "record": record,
        "lookup_count_approx": dns_lookup_mechanisms,
        "all_mechanism": all_mechanism,
        "tokens": tokens
    }

    # Evaluate issues
    # Check 1: Overly permissive "+all" or bare "all"
    if all_mechanism in ["+all", "all"]:
        details["permissive"] = True
        return CheckResult(
            name="SPF",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Change overly permissive '{all_mechanism}' in your SPF record to '~all' (SoftFail) or '-all' (HardFail) to prevent unauthorized senders from spoofing {domain}."
        )

    # Check 2: Too many lookups (>10)
    if dns_lookup_mechanisms > 10:
        details["lookup_limit_exceeded"] = True
        return CheckResult(
            name="SPF",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Reduce SPF lookup mechanisms (currently approx {dns_lookup_mechanisms}). RFC 7208 limits lookups to 10; exceeding this causes SPF PermError and rejected emails."
        )

    # Check 3: Missing 'all' mechanism (unless redirect is used)
    if not all_mechanism and not has_redirect:
        details["missing_all"] = True
        return CheckResult(
            name="SPF",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Add a terminating '-all' or '~all' mechanism to the end of your SPF record for {domain} to specify default handling for unlisted senders."
        )

    # Passed successfully
    details["valid"] = True
    return CheckResult(
        name="SPF",
        status=CheckStatus.PASS,
        details=details,
        recommendation=None
    )
