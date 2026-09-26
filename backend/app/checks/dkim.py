import dns.resolver
import dns.exception
import re
from typing import Dict, Any, List, Optional
from app.models import CheckResult, CheckStatus
from app.resolver import get_dns_resolver

COMMON_SELECTORS = [
    "google",
    "selector1",
    "selector2",
    "default",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2",
    "smtp"
]


def check_dkim(domain: str, timeout: float = 2.0) -> CheckResult:
    """
    DKIM check:
    - True DKIM requires knowing the selector (not discoverable via DNS alone).
    - Checks common selectors: google, selector1, selector2, default, k1, dkim, mail, s1, s2, smtp.
    - Query <selector>._domainkey.<domain> TXT record.
    - If found: parse and return PASS.
    - If none found: return WARN with best-effort explanation:
      'DKIM: not detected with common selectors (manual selector check recommended)'
    """
    resolver = get_dns_resolver(timeout=timeout)

    detected_selectors: List[Dict[str, Any]] = []

    for selector in COMMON_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                txt_parts = [part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings]
                record_str = "".join(txt_parts).strip()
                # DKIM records typically contain p= (public key) or v=DKIM1
                has_key = bool(re.search(r"p=[A-Za-z0-9+/]{20,}", record_str))
                if has_key or "v=dkim1" in record_str.lower():
                    detected_selectors.append({
                        "selector": selector,
                        "record": record_str,
                        "query": dkim_domain,
                        "has_public_key": has_key
                    })
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, Exception):
            continue

    # Filter to only those with valid public key
    valid_selectors = [s for s in detected_selectors if s["has_public_key"]]
    if valid_selectors:
        primary = valid_selectors[0]
        return CheckResult(
            name="DKIM",
            status=CheckStatus.PASS,
            details={
                "found": True,
                "tested_selectors": COMMON_SELECTORS,
                "detected_selectors": [s["selector"] for s in detected_selectors],
                "primary_selector": primary["selector"],
                "record": primary["record"],
                "has_public_key": primary["has_public_key"]
            },
            recommendation=None
        )

    # If none found, honest best-effort response
    return CheckResult(
        name="DKIM",
        status=CheckStatus.WARN,
        details={
            "found": False,
            "tested_selectors": COMMON_SELECTORS,
            "message": "DKIM: not detected with common selectors (manual selector check recommended)."
        },
        recommendation=f"Configure DKIM signing on your outbound email provider and publish the corresponding public key at '<selector>._domainkey.{domain}'."
    )
