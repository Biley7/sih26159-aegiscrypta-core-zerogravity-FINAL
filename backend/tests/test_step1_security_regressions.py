import sys
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from fastapi import HTTPException

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from app import ai_engine
from app.main import verify_domain_resolvable


class FakeResolver:
    nameservers = []

    def __init__(self, outcome):
        self.outcome = outcome
        self.queries = []

    def resolve(self, domain, record_type):
        self.queries.append(record_type)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def test_domain_resolution_requires_a_dns_answer(monkeypatch):
    resolver = FakeResolver(dns.resolver.NoAnswer())
    monkeypatch.setattr("app.main.get_dns_resolver", lambda timeout: resolver)

    with pytest.raises(HTTPException) as error:
        verify_domain_resolvable("example.invalid")

    assert error.value.status_code == 400
    assert resolver.queries == ["A", "AAAA", "MX", "SOA"]


def test_domain_resolution_fails_when_dns_times_out(monkeypatch):
    resolver = FakeResolver(dns.exception.Timeout())
    monkeypatch.setattr("app.main.get_dns_resolver", lambda timeout: resolver)

    with pytest.raises(HTTPException) as error:
        verify_domain_resolvable("example.com")

    assert error.value.status_code == 503
    assert len(resolver.queries) == 4


def test_domain_resolution_accepts_first_answer(monkeypatch):
    resolver = FakeResolver(["192.0.2.1"])
    monkeypatch.setattr("app.main.get_dns_resolver", lambda timeout: resolver)

    assert verify_domain_resolvable("example.com") is True
    assert resolver.queries == ["A"]


def test_gemini_configuration_is_not_inserted_into_playbook(monkeypatch):
    response = SimpleNamespace(
        text=(
            '{"risk_factors": [], "mitigation_priority": [], '
            '"postfix_main_cf": "smtpd_banner = safe\\nmalicious_directive = yes", '
            '"bind_dns_zone": "example.com IN TXT \\"; injected\\""}'
        )
    )

    class FakeModel:
        def generate_content(self, prompt):
            return response

    fake_genai = SimpleNamespace(
        configure=lambda api_key: None,
        GenerativeModel=lambda model_name: FakeModel(),
    )
    monkeypatch.setitem(sys.modules, "google.generativeai", fake_genai)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        ai_engine,
        "calculate_posture_score",
        lambda **kwargs: (80, "A", [], []),
    )

    *_, playbook = ai_engine.evaluate_ai_remediation(
        domain="example.com",
        checks=[],
        crypto_posture=None,
        findings=[],
    )

    assert "malicious_directive" not in playbook.postfix_main_cf
    assert "injected" not in playbook.bind_dns_zone
    assert "smtpd_tls_security_level = encrypt" in playbook.postfix_main_cf