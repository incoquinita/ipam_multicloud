"""Asynchronous TCP connect port scanner.

Uses ``asyncio`` for non-blocking TCP connections with configurable
timeouts and concurrency limits.  Scans a list of ports on a single
host and returns the subset of ports that are open.
"""

import asyncio


class PortScanner:
    """Async TCP connect port scanner with semaphore-gated concurrency.

    Parameters
    ----------
    concurrency : int
        Maximum number of concurrent connection attempts (default 200).
    timeout : float
        Connection timeout in seconds (default 2.0).
    """

    # Commonly exposed administrative / well-known service ports.
    ADMIN_PORTS: dict[int, str] = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        491: "GoGlobal",
        993: "IMAPS",
        995: "POP3S",
        1433: "MS-SQL",
        1494: "Citrix-ICA",
        1521: "Oracle DB",
        2049: "NFS",
        2598: "Citrix-CGP",
        3200: "SAP-Dispatcher",
        3300: "SAP-Dispatcher",
        3306: "MySQL",
        3389: "RDP",
        3601: "SAP-Message-Server",
        3901: "SAP-Message-Server-HTTP",
        5432: "PostgreSQL",
        5900: "VNC",
        5901: "VNC",
        5985: "WinRM",
        5986: "WinRM TLS",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9090: "Prometheus",
        27017: "MongoDB",
    }

    def __init__(self, concurrency: int = 200, timeout: float = 2.0) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)

    async def _scan_port(self, host: str, port: int) -> int | None:
        """Attempt a TCP connection to ``host:port``.

        Returns the port number if the connection succeeds, or ``None``
        if the port is closed or filtered.
        """
        async with self._semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan_host(self, host: str, ports: list[int]) -> list[int]:
        """Scan a list of ports on *host* concurrently.

        Parameters
        ----------
        host : str
            IP address or hostname.
        ports : list[int]
            Port numbers to scan.

        Returns
        -------
        list[int]
            Sorted list of open port numbers.
        """
        # Guard: empty port list.
        if not ports:
            return []

        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)

        open_ports = [port for port in results if port is not None]
        open_ports.sort()
        return open_ports

    def get_service_name(self, port: int) -> str:
        """Return the common service name for *port*.

        Returns ``"unknown"`` if the port is not in the well-known map.
        """
        return self.ADMIN_PORTS.get(port, "unknown")

    def get_admin_ports(self) -> dict[int, str]:
        """Return a copy of the internal admin-ports mapping."""
        return dict(self.ADMIN_PORTS)
