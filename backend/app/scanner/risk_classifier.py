"""Port-based risk classification engine.

Assigns a risk level and score to a port based on its number, the
exposure context, encryption status, SSL usage, and whether known
CVEs exist for that service.
"""

from typing import Any


class RiskClassifier:
    """Classifies the risk of exposed ports.

    Uses a baseline score for known services, adjusted by an exposure
    multiplier, encryption multiplier, SSL multiplier, and a CVE penalty.
    """

    # Base risk scores (0–10) for well-known services.
    # Severity values are lowercase to match the ``PortResult.risk_level``
    # column, the port-results filter allow-list, and the analytics
    # distribution queries — keeping the whole pipeline consistent so
    # risk-level filtering actually matches stored rows.
    SERVICE_RISK_BASELINE: dict[int, dict[str, Any]] = {
        23: {"name": "Telnet", "severity": "critical", "score": 9.5},
        3389: {"name": "RDP", "severity": "critical", "score": 9.5},
        3200: {"name": "SAP-Dispatcher", "severity": "critical", "score": 9.5},
        3300: {"name": "SAP-Dispatcher", "severity": "critical", "score": 9.5},
        3601: {"name": "SAP-Message-Server", "severity": "critical", "score": 9.5},
        445: {"name": "SMB", "severity": "critical", "score": 9.0},
        139: {"name": "NetBIOS", "severity": "critical", "score": 9.0},
        27017: {"name": "MongoDB", "severity": "critical", "score": 9.0},
        2049: {"name": "NFS", "severity": "critical", "score": 9.0},
        5900: {"name": "VNC", "severity": "critical", "score": 9.0},
        5901: {"name": "VNC", "severity": "critical", "score": 9.0},
        491: {"name": "GoGlobal", "severity": "critical", "score": 9.0},
        1494: {"name": "Citrix-ICA", "severity": "critical", "score": 9.0},
        2598: {"name": "Citrix-CGP", "severity": "critical", "score": 9.0},
        3901: {"name": "SAP-Message-Server-HTTP", "severity": "critical", "score": 9.0},
        5432: {"name": "PostgreSQL", "severity": "critical", "score": 8.5},
        6379: {"name": "Redis", "severity": "critical", "score": 8.5},
        3306: {"name": "MySQL", "severity": "high", "score": 8.0},
        1433: {"name": "MSSQL", "severity": "high", "score": 8.0},
        1521: {"name": "OracleDB", "severity": "high", "score": 8.0},
        111: {"name": "RPC", "severity": "high", "score": 7.5},
        135: {"name": "MSRPC", "severity": "high", "score": 7.5},
        5985: {"name": "WinRM", "severity": "high", "score": 7.5},
        22: {"name": "SSH", "severity": "high", "score": 7.5},
        21: {"name": "FTP", "severity": "high", "score": 7.0},
        389: {"name": "LDAP", "severity": "high", "score": 7.0},
        5986: {"name": "WinRM-TLS", "severity": "high", "score": 7.0},
        25: {"name": "SMTP", "severity": "medium", "score": 5.5},
        161: {"name": "SNMP", "severity": "medium", "score": 5.0},
        9090: {"name": "Prometheus", "severity": "medium", "score": 5.0},
        53: {"name": "DNS", "severity": "medium", "score": 5.0},
        80: {"name": "HTTP", "severity": "medium", "score": 4.5},
        8080: {"name": "HTTP-Alt", "severity": "medium", "score": 4.5},
        443: {"name": "HTTPS", "severity": "low", "score": 2.0},
        993: {"name": "IMAPS", "severity": "low", "score": 2.0},
        995: {"name": "POP3S", "severity": "low", "score": 1.5},
    }

    EXPOSURE_MULTIPLIERS: dict[str, float] = {
        "internet": 1.5,
        "vpn": 1.0,
        "internal": 0.7,
        "localhost": 0.3,
    }

    ENCRYPTION_MULTIPLIERS: dict[str, float] = {
        "none": 1.3,
        "starttls": 1.1,
        "tls": 0.8,
        "auth": 0.6,
    }

    def classify_port(
        self,
        port: int,
        exposure: str = "internet",
        has_cves: bool = False,
        encryption: str = "none",
        has_ssl: bool = False,
    ) -> dict[str, Any]:
        """Classify the risk of an exposed port.

        Parameters
        ----------
        port : int
            Port number.
        exposure : str
            Exposure context — one of ``"internet"``, ``"vpn"``,
            ``"internal"``, or ``"localhost"`` (default ``"internet"``).
        has_cves : bool
            Whether known CVEs exist for this service (default ``False``).
        encryption : str
            Encryption status — one of ``"none"``, ``"starttls"``,
            ``"tls"``, or ``"auth"`` (default ``"none"``).
        has_ssl : bool
            Whether SSL/TLS is enabled (default ``False``). If ``True``,
            reduces the score by an 0.8× multiplier.

        Returns
        -------
        dict
            Risk assessment with keys ``port``, ``service``,
            ``base_score``, ``exposure``, ``exposure_multiplier``,
            ``has_cves``, ``encryption``, ``encryption_multiplier``,
            ``has_ssl``, ``ssl_multiplier``, ``final_score``, and
            ``severity``.
        """
        # Guard: validate encryption value.
        if encryption not in self.ENCRYPTION_MULTIPLIERS:
            raise ValueError(
                f"Unknown encryption '{encryption}'. "
                f"Options: {', '.join(self.ENCRYPTION_MULTIPLIERS)}",
            )

        baseline = self.SERVICE_RISK_BASELINE.get(port, {
            "name": f"Port-{port}",
            "severity": "low",
            "score": 1.0,
        })

        exp_mult = self.EXPOSURE_MULTIPLIERS.get(exposure, 1.0)
        enc_mult = self.ENCRYPTION_MULTIPLIERS[encryption]
        ssl_mult = 0.8 if has_ssl else 1.0
        vuln_mult = 1.3 if has_cves else 1.0

        final_score = min(
            baseline["score"] * exp_mult * vuln_mult * enc_mult * ssl_mult,
            10.0,
        )

        # Map score to severity (lowercase to match PortResult.risk_level,
        # the port-results filter allow-list, and analytics queries).
        if final_score >= 8.0:
            severity = "critical"
        elif final_score >= 6.0:
            severity = "high"
        elif final_score >= 4.0:
            severity = "medium"
        else:
            severity = "low"

        return {
            "port": port,
            "service": baseline["name"],
            "base_score": baseline["score"],
            "exposure": exposure,
            "exposure_multiplier": exp_mult,
            "has_cves": has_cves,
            "encryption": encryption,
            "encryption_multiplier": enc_mult,
            "has_ssl": has_ssl,
            "ssl_multiplier": ssl_mult,
            "final_score": round(final_score, 1),
            "severity": severity,
        }
