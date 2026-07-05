"""Scan profile definitions.

Scan profiles encapsulate named port lists and scanning behaviour
(timeout, concurrency, banner grabbing, HTTP analysis) so that
callers can select a profile rather than specifying raw config.
"""

from dataclasses import dataclass, field


@dataclass
class ScanProfile:
    """Named scan configuration profile.

    Attributes
    ----------
    name : str
        Machine-readable profile name (``"quick"``, ``"standard"``,
        ``"thorough"``, ``"custom"``).
    description : str
        Human-readable description of what this profile does.
    ports : list[int]
        Port numbers to scan.
    timeout : float
        Connection timeout in seconds.
    concurrency : int
        Maximum concurrent connection attempts.
    banner_grab : bool
        Whether to grab service banners for open ports.
    http_analysis : bool
        Whether to perform HTTP/HTTPS analysis on web ports.
    """

    name: str
    description: str
    ports: list[int] = field(default_factory=list)
    timeout: float = 2.0
    concurrency: int = 200
    banner_grab: bool = False
    http_analysis: bool = False


SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan — top 10 admin ports",
        ports=[22, 23, 80, 443, 3389, 8080, 8443, 21, 445, 3306],
        timeout=1.0,
        concurrency=500,
        banner_grab=False,
        http_analysis=False,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Standard scan — top 31 admin ports + banners",
        ports=[
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
            491, 993, 995, 1433, 1494, 1521, 2049, 2598, 3200, 3300, 3306,
            3389, 3601, 3901, 5432, 5900, 5901, 5985, 5986, 6379, 8080, 8443,
            9090, 27017,
        ],
        timeout=2.0,
        concurrency=200,
        banner_grab=True,
        http_analysis=True,
    ),
    "thorough": ScanProfile(
        name="thorough",
        description="Deep scan — top 100 ports + banners + HTTP analysis",
        # Ports 1-1024 plus key administrative ports above 1024.
        ports=list(range(1, 1025)) + [1494, 2598, 3200, 3300, 3601, 3901],
        timeout=3.0,
        concurrency=100,
        banner_grab=True,
        http_analysis=True,
    ),
    "custom": ScanProfile(
        name="custom",
        description="Custom port list",
        ports=[],
        timeout=2.0,
        concurrency=200,
        banner_grab=True,
        http_analysis=True,
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Return a scan profile by name.

    Parameters
    ----------
    name : str
        Profile name — one of ``"quick"``, ``"standard"``,
        ``"thorough"``, or ``"custom"``.

    Returns
    -------
    ScanProfile
        The matching profile.

    Raises
    ------
    ValueError
        If the profile name is unknown.
    """
    if name not in SCAN_PROFILES:
        raise ValueError(
            f"Unknown profile '{name}'. "
            f"Options: {', '.join(SCAN_PROFILES)}",
        )
    return SCAN_PROFILES[name]
