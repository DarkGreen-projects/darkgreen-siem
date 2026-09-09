from __future__ import annotations

import asyncio
import logging
from typing import Callable

logger = logging.getLogger("syslog")


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_message: Callable[[str, str], None]):
        self.on_message = on_message

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        try:
            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return
            host = addr[0] if addr else "unknown"
            self.on_message(text, host)
        except Exception:
            logger.exception("Failed to handle syslog datagram")


async def start_syslog_server(host: str, port: int, on_message: Callable[[str, str], None]):
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(on_message),
        local_addr=(host, port),
    )
    logger.info("Syslog UDP listening on %s:%s", host, port)
    return transport
