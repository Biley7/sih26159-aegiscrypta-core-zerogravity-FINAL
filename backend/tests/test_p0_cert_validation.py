"""
Regression tests for the certificate-validation fixes.

Background
----------
Two independent defects made every real scan report certificate problems on a
correctly configured domain:

1. ``_get_trust_store()`` only read the interpreter's own CA bundle. python.org
   framework builds and slim containers frequently ship *zero* root certificates,
   and the resulting exception was swallowed, so chain validation reported
   "System trust store is unavailable" (HIGH finding) for every host. The trust
   store must fall back to the CA bundle shipped with ``certifi``.

2. ``parse_x509_certificate`` was called with the *queried* domain rather than the
   *probed* host. A real MX such as ``gmail-smtp-in.l.google.com`` serves a
   certificate whose SANs cover that MX name but not the apex domain, so the
   scan raised a false "Certificate Domain Name Mismatch" (MEDIUM finding) on a
   perfectly valid certificate.

Both feed the ``certificate_health`` antecedent, so they compounded into a
substantially deflated *reported* certificate-health value (0.2 on a correctly
configured exchange) and injected two spurious HIGH/MEDIUM findings into every
report. Note that ``certificate_health`` is a display-only antecedent: the fused
posture score in ``compute_posture_risk`` is derived solely from the CDI, PED and
ELI composite indices, so these defects did not move the headline score.
"""

import inspect
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.crypto import cert_analyzer  # noqa: E402
from app.crypto import tls_probe  # noqa: E402

APEX_DOMAIN = "customer-domain.com"
MX_HOST = "mx.mail-provider.net"


def _make_certificate(sans, cn=None, days_valid=200):
    """Builds a self-signed DER certificate carrying the given SAN list."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or sans[0])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(autouse=True)
def _reset_trust_store_cache():
    """The trust store is cached per process; isolate every test in this module."""
    saved = (cert_analyzer._TRUST_STORE, cert_analyzer._TRUST_STORE_ERROR, cert_analyzer._TRUST_STORE_SOURCE)
    cert_analyzer._TRUST_STORE = None
    cert_analyzer._TRUST_STORE_ERROR = None
    cert_analyzer._TRUST_STORE_SOURCE = None
    yield
    cert_analyzer._TRUST_STORE, cert_analyzer._TRUST_STORE_ERROR, cert_analyzer._TRUST_STORE_SOURCE = saved


# ---------------------------------------------------------------------------
# P0.1 — trust store availability
# ---------------------------------------------------------------------------

def test_trust_store_falls_back_to_certifi_when_platform_store_is_empty(monkeypatch):
    """
    A runtime whose own trust store yields no roots (python.org framework builds,
    slim containers) must still be able to validate chains via the certifi bundle.
    """
    real_loader = cert_analyzer._load_root_certificates
    seen_cafiles = []

    def loader(cafile=None):
        seen_cafiles.append(cafile)
        if cafile is None:
            return []  # simulate an interpreter with no roots installed
        return real_loader(cafile)

    monkeypatch.setattr(cert_analyzer, "_load_root_certificates", loader)

    store = cert_analyzer._get_trust_store()

    assert store is not None, "chain validation must remain available via certifi"
    assert cert_analyzer.trust_store_source() == "certifi CA bundle"
    assert None in seen_cafiles, "the platform trust store should be tried first"
    assert any(c for c in seen_cafiles if c), "a fallback CA bundle path must be used"


def test_chain_validation_is_available_in_this_environment():
    """
    Guards the regression directly: certificate chain validation must be usable
    here, from either the platform trust store or certifi.
    """
    assert cert_analyzer.trust_store_source() in {"system trust store", "certifi CA bundle"}


def test_missing_root_cas_are_reported_not_raised(monkeypatch):
    """
    With no platform roots AND no importable certifi the analyzer must degrade to a
    clear, non-crashing diagnostic rather than an opaque failure.
    """
    monkeypatch.setattr(cert_analyzer, "_load_root_certificates", lambda cafile=None: [])

    def _unavailable_where():
        raise RuntimeError("no CA bundle installed")

    monkeypatch.setitem(sys.modules, "certifi", types.SimpleNamespace(where=_unavailable_where))

    der = _make_certificate([MX_HOST])
    valid, reason = cert_analyzer.verify_certificate_chain(
        x509.load_der_x509_certificate(der), MX_HOST, []
    )

    assert valid is False
    assert cert_analyzer._get_trust_store() is None
    assert "no trusted root CA bundle" in reason


# ---------------------------------------------------------------------------
# P0.2 — the probed host is the identity that must be covered
# ---------------------------------------------------------------------------

def test_certificate_sans_are_matched_against_the_probed_host_not_the_apex_domain():
    """
    A certificate covering the MX host is valid for that host even when it does not
    cover the domain whose mail it serves.
    """
    der = _make_certificate([MX_HOST, "smtp.mail-provider.net"])

    host_info, host_findings = cert_analyzer.parse_x509_certificate(der, target_domain=MX_HOST)
    assert host_info.matches_domain is True
    assert not [f for f in host_findings if f.title == "Certificate Domain Name Mismatch"]

    # The same certificate compared against the queried apex domain is a genuine
    # mismatch — which is exactly why the callers must pass the probed host.
    apex_info, apex_findings = cert_analyzer.parse_x509_certificate(der, target_domain=APEX_DOMAIN)
    assert apex_info.matches_domain is False
    assert [f for f in apex_findings if f.title == "Certificate Domain Name Mismatch"]


def test_wildcard_san_still_matches_a_probed_host():
    der = _make_certificate(["mail-provider.net", "*.mail-provider.net"])

    info, findings = cert_analyzer.parse_x509_certificate(der, target_domain="mx.mail-provider.net")

    assert info.matches_domain is True
    assert not [f for f in findings if f.title == "Certificate Domain Name Mismatch"]


def test_live_probe_validates_the_connected_host():
    """
    Static guard on the call sites: the direct probe connects to (and sends SNI for)
    ``host``, and the HTTPS SNI fallback asserts the SNI name it sent. Reverting
    either to the apex domain reintroduces the false mismatch finding.
    """
    direct_source = inspect.getsource(tls_probe.probe_protocol_tls)
    assert "target_domain=host" in direct_source

    fallback_source = inspect.getsource(tls_probe.probe_https_sni_fallback)
    assert "target_domain=target_domain or target_host" in fallback_source
