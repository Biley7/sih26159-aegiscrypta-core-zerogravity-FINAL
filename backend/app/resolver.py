import dns.resolver
import dns.exception
from typing import List, Optional

DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

def get_dns_resolver(timeout: float = 2.0, lifetime: float = 3.5) -> dns.resolver.Resolver:
    """
    Returns a configured dnspython Resolver with public upstream nameservers
    (8.8.8.8, 1.1.1.1, 9.9.9.9) for resilient, fast, consistent lookups across all environments.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(DEFAULT_DNS_SERVERS)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def clean_txt_rdata(rdata) -> str:
    """
    Combines multi-chunk DNS TXT record fragments and cleanly strips
    whitespace and wrapping quotes.
    """
    if hasattr(rdata, "strings") and rdata.strings:
        raw = "".join(
            s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
            for s in rdata.strings
        )
    else:
        raw = str(rdata)

    cleaned = raw.strip()
    # Strip wrapping quotes if present
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def resolve_txt_records(domain: str, timeout: float = 2.0, lifetime: float = 3.5) -> List[str]:
    """
    Resolves TXT records for a domain with public nameserver fallback.
    Returns cleaned strings. Returns empty list on NXDOMAIN / NoAnswer.
    """
    resolver = get_dns_resolver(timeout=timeout, lifetime=lifetime)
    try:
        answers = resolver.resolve(domain, "TXT")
        return [clean_txt_rdata(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        return []


def resolve_mx_hosts(domain: str, timeout: float = 2.0, lifetime: float = 3.5) -> List[str]:
    """
    Resolves MX records sorted by preference for a domain.
    Returns sorted list of MX hostnames without trailing dot.
    """
    resolver = get_dns_resolver(timeout=timeout, lifetime=lifetime)
    hosts: List[str] = []
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in sorted(answers, key=lambda x: x.preference):
            exchange = str(rdata.exchange).rstrip(".")
            if exchange and exchange != ".":
                hosts.append(exchange)
    except Exception:
        pass
    return hosts

