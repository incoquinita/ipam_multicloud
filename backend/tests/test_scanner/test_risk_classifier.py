"""Unit tests for the port-based risk classifier.

Exercises ``RiskClassifier.classify_port`` across:

- Every port in the ``SERVICE_RISK_BASELINE`` table, including the new
  SAP (3200/3300/3601/3901), Citrix (1494/2598), and GoGlobal (491)
  entries — all must classify as ``critical`` at default exposure.
- The risk-scoring formula: ``base × exposure_mult × vuln_mult ×
  enc_mult × ssl_mult``, capped at 10.
- Severity-level thresholds: critical ≥ 8, high ≥ 6, medium ≥ 4, low < 4.
- Edge cases: unknown port (no baseline), invalid encryption value.

.. note::
   Severity values are lowercase to match the ``PortResult.risk_level``
   column, the port-results filter allow-list, and analytics queries.

.. note::
   The default call ``classify_port(port)`` uses ``exposure="internet"``
   (1.5×) and ``encryption="none"`` (1.3×), so the default final score
   is ``min(base × 1.95, 10)``.  Tests that target a specific severity
   bucket pick an exposure/encryption combo that lands inside it.
"""

from __future__ import annotations

import pytest

from app.scanner.risk_classifier import RiskClassifier

# Pure unit tests — the shared ``tests/test_scanner/conftest.py`` already
# neutralises the root ``setup_database`` fixture, so no DB is touched.


# ── Critical-port coverage (SAP / Citrix / GoGlobal + admin) ──────


@pytest.mark.parametrize(
    "port",
    [
        # SAP family — all CRITICAL.
        3200, 3300, 3601, 3901,
        # Citrix family — all CRITICAL.
        1494, 2598,
        # GoGlobal — CRITICAL.
        491,
        # Other critical admin services.
        23,     # Telnet
        3389,   # RDP
        445,    # SMB
        5432,   # PostgreSQL
        6379,   # Redis
        27017,  # MongoDB
    ],
)
def test_classify_port_critical_services_are_critical(port: int) -> None:
    """High-baseline ports classify as critical at default (internet) exposure."""
    classifier = RiskClassifier()
    result = classifier.classify_port(port)

    assert result["severity"] == "critical", (
        f"port {port}: expected critical, got {result['severity']} "
        f"(score={result['final_score']})"
    )


@pytest.mark.parametrize(
    ("port", "expected_name"),
    [
        (3200, "SAP-Dispatcher"),
        (3300, "SAP-Dispatcher"),
        (3601, "SAP-Message-Server"),
        (3901, "SAP-Message-Server-HTTP"),
        (1494, "Citrix-ICA"),
        (2598, "Citrix-CGP"),
        (491, "GoGlobal"),
        (22, "SSH"),
        (3389, "RDP"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (80, "HTTP"),
        (443, "HTTPS"),
    ],
)
def test_classify_port_service_name_matches_baseline(port: int, expected_name: str) -> None:
    """The service name matches the baseline entry for each known port."""
    classifier = RiskClassifier()
    result = classifier.classify_port(port)

    assert result["service"] == expected_name


# ── Scoring formula ───────────────────────────────────────────────


def test_classify_port_score_formula_matches_baseline_times_multipliers() -> None:
    """``final_score == min(base × exp × vuln × enc × ssl, 10)``.

    Using port 22 (SSH, base 7.5) with internet exposure (1.5), CVEs
    (1.3), no encryption (1.3), no SSL (1.0):
    7.5 × 1.5 × 1.3 × 1.3 × 1.0 = 19.0125 → capped at 10.0.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(
        22, exposure="internet", has_cves=True, encryption="none", has_ssl=False,
    )

    assert result["base_score"] == 7.5
    assert result["exposure_multiplier"] == 1.5
    assert result["encryption_multiplier"] == 1.3
    assert result["ssl_multiplier"] == 1.0
    # 7.5 × 1.5 × 1.3 × 1.3 × 1.0 = 19.0125, capped at 10.
    assert result["final_score"] == 10.0
    assert result["severity"] == "critical"


def test_classify_port_score_capped_at_ten() -> None:
    """Even extreme multipliers cannot push the score above 10."""
    classifier = RiskClassifier()
    result = classifier.classify_port(
        23,  # Telnet, base 9.5
        exposure="internet",   # 1.5
        has_cves=True,         # 1.3
        encryption="none",     # 1.3
        has_ssl=False,         # 1.0
    )

    # 9.5 × 1.5 × 1.3 × 1.3 × 1.0 = 24.0675 → capped at 10.
    assert result["final_score"] == 10.0


def test_classify_port_ssl_reduces_score() -> None:
    """``has_ssl=True`` applies a 0.8× multiplier, lowering the final score."""
    classifier = RiskClassifier()
    without_ssl = classifier.classify_port(80, exposure="vpn", has_ssl=False)
    with_ssl = classifier.classify_port(80, exposure="vpn", has_ssl=True)

    assert with_ssl["final_score"] < without_ssl["final_score"]
    assert with_ssl["ssl_multiplier"] == 0.8
    assert without_ssl["ssl_multiplier"] == 1.0


def test_classify_port_tls_encryption_lowers_score_vs_none() -> None:
    """TLS encryption (0.8) reduces risk vs. no encryption (1.3)."""
    classifier = RiskClassifier()
    no_enc = classifier.classify_port(22, exposure="vpn", encryption="none")
    tls = classifier.classify_port(22, exposure="vpn", encryption="tls")

    assert tls["final_score"] < no_enc["final_score"]
    assert tls["encryption_multiplier"] == 0.8
    assert no_enc["encryption_multiplier"] == 1.3


def test_classify_port_cves_increase_score() -> None:
    """Known CVEs apply a 1.3× multiplier, raising the final score.

    Uses internal exposure so neither score hits the 10.0 cap and the
    difference is observable.
    """
    classifier = RiskClassifier()
    clean = classifier.classify_port(22, exposure="internal", has_cves=False)
    vulnerable = classifier.classify_port(22, exposure="internal", has_cves=True)

    assert vulnerable["final_score"] > clean["final_score"]


# ── Exposure multipliers ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("exposure", "expected_mult"),
    [
        ("internet", 1.5),
        ("vpn", 1.0),
        ("internal", 0.7),
        ("localhost", 0.3),
    ],
)
def test_classify_port_exposure_multipliers(exposure: str, expected_mult: float) -> None:
    """Each exposure context applies its documented multiplier."""
    classifier = RiskClassifier()
    result = classifier.classify_port(22, exposure=exposure)

    assert result["exposure_multiplier"] == expected_mult
    assert result["exposure"] == exposure


def test_classify_port_unknown_exposure_defaults_to_one() -> None:
    """An unrecognised exposure string falls back to a 1.0 multiplier."""
    classifier = RiskClassifier()
    result = classifier.classify_port(22, exposure="darkweb")

    assert result["exposure_multiplier"] == 1.0


# ── Severity thresholds ───────────────────────────────────────────


def test_classify_port_severity_critical_threshold() -> None:
    """A final score ≥ 8 maps to critical.

    Port 22 (7.5) at internet (1.5) with none-encryption (1.3):
    7.5 × 1.5 × 1.3 = 14.625 → capped 10.0.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(22, exposure="internet")
    assert result["final_score"] >= 8.0
    assert result["severity"] == "critical"


def test_classify_port_severity_high_threshold() -> None:
    """A final score in [6, 8) maps to high.

    Port 22 (7.5) at internal (0.7) with none-encryption (1.3):
    7.5 × 0.7 × 1.3 = 6.825 → 6.8.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(22, exposure="internal")
    assert 6.0 <= result["final_score"] < 8.0
    assert result["severity"] == "high"


def test_classify_port_severity_medium_threshold() -> None:
    """A final score in [4, 6) maps to medium.

    Port 80 (4.5) at vpn (1.0) with none-encryption (1.3):
    4.5 × 1.0 × 1.3 = 5.85 → 5.9.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(80, exposure="vpn")
    assert 4.0 <= result["final_score"] < 6.0
    assert result["severity"] == "medium"


def test_classify_port_severity_low_threshold() -> None:
    """A final score < 4 maps to low.

    Port 443 (2.0) at localhost (0.3) with none-encryption (1.3):
    2.0 × 0.3 × 1.3 = 0.78 → 0.8.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(443, exposure="localhost")
    assert result["final_score"] < 4.0
    assert result["severity"] == "low"


# ── Edge cases ────────────────────────────────────────────────────


def test_classify_port_unknown_port_uses_low_baseline() -> None:
    """A port with no baseline entry defaults to score 1.0, severity low."""
    classifier = RiskClassifier()
    result = classifier.classify_port(54321, exposure="vpn", encryption="tls")

    assert result["service"] == "Port-54321"
    assert result["base_score"] == 1.0
    assert result["severity"] == "low"


def test_classify_port_unknown_port_with_internet_exposure_stays_low() -> None:
    """An unknown port on internet exposure (1.5×, 1.3× enc) stays low.

    1.0 × 1.5 × 1.3 = 1.95 → 2.0, which is < 4 → low.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(54321, exposure="internet")

    assert result["final_score"] == 2.0
    assert result["severity"] == "low"


def test_classify_port_invalid_encryption_raises_value_error() -> None:
    """An unrecognised encryption value fails fast with a descriptive error."""
    classifier = RiskClassifier()
    with pytest.raises(ValueError, match="Unknown encryption 'wpa3'"):
        classifier.classify_port(22, encryption="wpa3")


def test_classify_port_result_contains_all_documented_keys() -> None:
    """The result dict exposes every key promised by the docstring."""
    classifier = RiskClassifier()
    result = classifier.classify_port(22)

    expected_keys = {
        "port", "service", "base_score", "exposure", "exposure_multiplier",
        "has_cves", "encryption", "encryption_multiplier",
        "has_ssl", "ssl_multiplier", "final_score", "severity",
    }
    assert expected_keys == set(result)


def test_classify_port_final_score_rounded_to_one_decimal() -> None:
    """``final_score`` is rounded to one decimal place for readability.

    Port 5900 (VNC, 9.0) at internal (0.7) with none-encryption (1.3):
    9.0 × 0.7 × 1.3 = 8.19 → 8.2.
    """
    classifier = RiskClassifier()
    result = classifier.classify_port(5900, exposure="internal")
    assert result["final_score"] == 8.2
    # Verify the rounding: the value has at most one decimal place.
    assert round(result["final_score"], 1) == result["final_score"]
