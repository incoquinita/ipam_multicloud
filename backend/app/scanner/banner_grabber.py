"""Service banner grabber for identified open ports.

Attempts to read a service banner from an open TCP port by sending a
protocol-appropriate probe and reading the initial response.
"""

import asyncio


class BannerGrabber:
    """Grabs service banners from open TCP ports.

    Parameters
    ----------
    timeout : float
        Connection and read timeout in seconds (default 2.0).
    """

    HTTP_PORTS: set[int] = {80, 443, 8080, 8443}

    def __init__(self, timeout: float = 2.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout

    async def grab_banner(self, host: str, port: int) -> str | None:
        """Attempt to grab a banner from ``host:port``.

        For HTTP/HTTPS ports, sends a ``HEAD`` request.  For all other
        ports, sends a generic probe (two CR-LF pairs).

        Parameters
        ----------
        host : str
            IP address or hostname.
        port : int
            Target port.

        Returns
        -------
        str or None
            The banner text decoded as UTF-8 (with error replacement),
            or ``None`` if the connection or read failed.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )

            if port in self.HTTP_PORTS:
                writer.write(
                    b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode(),
                )
            else:
                writer.write(b"\r\n\r\n")

            await writer.drain()

            banner = await asyncio.wait_for(
                reader.read(2048),
                timeout=self.timeout,
            )

            writer.close()
            await writer.wait_closed()

            if banner:
                return banner.decode("utf-8", errors="ignore").strip()
            return None

        except (TimeoutError, ConnectionRefusedError, OSError):
            return None
