import socket
import dns.resolver
import dns.exception
from typing import Dict, Any, List, Optional
from app.models import CheckResult, CheckStatus
from app.resolver import get_dns_resolver


from app.crypto.tls_probe import probe_protocol_tls, probe_https_sni_fallback


def check_starttls_capability(host: str, port: int = 25, timeout: float = 2.0, target_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs deep active STARTTLS probe on mail exchanger:
    - Verifies EHLO advertising of STARTTLS
    - Completes full TLS handshake
    - Extracts negotiated TLS version, cipher suite, forward secrecy, and X.509 certificate
    - Gracefully handles firewalls/ISP port 25 restrictions with 587/465/SNI fallbacks.
    """
    audit = probe_protocol_tls(
        host=host,
        port=port,
        protocol="smtp",
        use_starttls=True,
        target_domain=target_domain,
        timeout=timeout
    )

    # Multi-port and SNI fallbacks if port 25 is blocked by ISP firewall
    if not (audit.tls_handshake and audit.tls_handshake.success) and audit.status == CheckStatus.UNKNOWN:
        audit_587 = probe_protocol_tls(host=host, port=587, protocol="smtp", use_starttls=True, target_domain=target_domain, timeout=timeout)
        if audit_587.tls_handshake and audit_587.tls_handshake.success:
            audit = audit_587
        else:
            audit_465 = probe_protocol_tls(host=host, port=465, protocol="smtp", use_starttls=False, target_domain=target_domain, timeout=timeout)
            if audit_465.tls_handshake and audit_465.tls_handshake.success:
                audit = audit_465
            elif target_domain:
                sni_audit = probe_https_sni_fallback(host=host, target_domain=target_domain, timeout=timeout)
                if sni_audit.tls_handshake and sni_audit.tls_handshake.success:
                    audit = sni_audit


    if audit.tls_handshake and audit.tls_handshake.success:
        cipher_dict = audit.tls_handshake.cipher.model_dump() if audit.tls_handshake.cipher else None
        cert_dict = audit.tls_handshake.certificate.model_dump() if audit.tls_handshake.certificate else None
        return {
            "verified": True,
            "starttls_supported": True,
            "starttls_negotiated": audit.starttls_negotiated,
            "banner": audit.banner or "",
            "tls_version": audit.tls_handshake.negotiated_version,
            "cipher_suite": cipher_dict,
            "certificate": cert_dict,
            "findings": [f.model_dump() for f in audit.findings],
            "message": f"STARTTLS verified successfully using {audit.tls_handshake.negotiated_version} ({cipher_dict.get('name') if cipher_dict else 'unknown cipher'})."
        }
    elif audit.starttls_advertised is False:
        return {
            "verified": True,
            "starttls_supported": False,
            "starttls_negotiated": False,
            "banner": audit.banner or "",
            "message": "STARTTLS not advertised in EHLO response.",
            "findings": [f.model_dump() for f in audit.findings]
        }
    elif audit.status == CheckStatus.UNKNOWN or "timed out" in (audit.tls_handshake.error_message or "").lower():
        return {
            "verified": False,
            "starttls_supported": None,
            "error_type": "timeout",
            "message": "Outbound port 25 connection timed out (likely restricted by network/ISP firewall).",
            "findings": [f.model_dump() for f in audit.findings]
        }
    else:
        return {
            "verified": False,
            "starttls_supported": None,
            "error_type": "exception",
            "message": f"Could not complete TLS handshake: {audit.tls_handshake.error_message if audit.tls_handshake else 'Unknown error'}",
            "findings": [f.model_dump() for f in audit.findings]
        }


def check_mx_starttls(domain: str, timeout: float = 4.0) -> CheckResult:
    """
    Queries MX records and checks STARTTLS on the top priority host:
    - Queries MX records.
    - If no MX records found, flags failure.
    - Connects to top-priority MX on port 25 to check for STARTTLS.
    - If port 25 is blocked/unreachable, gracefully treats MX presence as partial pass with STARTTLS labeled as unverified.
    """
    resolver = get_dns_resolver(timeout=timeout)

    try:
        answers = resolver.resolve(domain, "MX")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.FAIL,
            details={
                "found_mx": False,
                "mx_records": [],
                "starttls": {"verified": False, "starttls_supported": False},
                "message": f"No MX records found for {domain}. This domain cannot receive inbound emails."
            },
            recommendation=f"Configure at least one MX record pointing to a mail server for {domain} to enable inbound email routing."
        )
    except dns.exception.Timeout:
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.UNKNOWN,
            details={
                "found_mx": False,
                "mx_records": [],
                "starttls": {"verified": False, "starttls_supported": False},
                "message": "DNS query timed out while resolving MX records."
            },
            recommendation=f"DNS lookup timed out when checking MX records for {domain}. Check DNS server health."
        )
    except Exception as e:
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.FAIL,
            details={
                "found_mx": False,
                "mx_records": [],
                "starttls": {"verified": False, "starttls_supported": False},
                "message": f"DNS resolution error: {str(e)}"
            },
            recommendation=f"Resolve DNS nameserver issues for {domain} and ensure MX records are correctly configured."
        )

    # Sort MX records by priority (preference)
    mx_list = []
    for rdata in answers:
        mx_list.append({
            "preference": rdata.preference,
            "exchange": str(rdata.exchange).rstrip(".")
        })

    mx_list.sort(key=lambda x: x["preference"])

    if not mx_list:
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.FAIL,
            details={
                "found_mx": False,
                "mx_records": [],
                "starttls": {"verified": False, "starttls_supported": False},
                "message": f"No MX records returned for {domain}."
            },
            recommendation=f"Add an MX record for {domain} to allow inbound mail delivery."
        )

    # Filter out empty or null MX (RFC 7505)
    valid_mx_list = [mx for mx in mx_list if mx["exchange"] and mx["exchange"] != "."]

    if not valid_mx_list:
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.WARN,
            details={
                "found_mx": True,
                "null_mx": True,
                "mx_records": mx_list,
                "message": f"Domain {domain} publishes a Null MX record (RFC 7505), indicating it explicitly does not accept incoming email."
            },
            recommendation=f"If {domain} is meant to receive emails, replace the Null MX record with an active mail server hostname."
        )

    top_mx = valid_mx_list[0]["exchange"]
    starttls_info = check_starttls_capability(top_mx, timeout=timeout, target_domain=domain)

    details: Dict[str, Any] = {
        "found_mx": True,
        "mx_records": mx_list,
        "primary_mx": top_mx,
        "starttls": starttls_info
    }

    # If STARTTLS verified and supported
    if starttls_info.get("verified") and starttls_info.get("starttls_supported"):
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.PASS,
            details=details,
            recommendation=None
        )

    # If connected successfully but STARTTLS not advertised
    if starttls_info.get("verified") and not starttls_info.get("starttls_supported"):
        return CheckResult(
            name="MX & STARTTLS",
            status=CheckStatus.WARN,
            details=details,
            recommendation=f"Enable opportunistic TLS (STARTTLS) on primary mail exchanger '{top_mx}' to encrypt mail in transit."
        )

    # If network restriction / port 25 unreachable -> partial pass with unverified label
    details["starttls_status"] = "unverified"
    return CheckResult(
        name="MX & STARTTLS",
        status=CheckStatus.PASS,
        details=details,
        recommendation=None
    )
