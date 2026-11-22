import asyncio
import unittest
from dns_transport import AuthoritativeBridge, ResolverBridge, query


class EchoDNS(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(data[:2] + b"\x81" + data[3:], address)


class Transport(unittest.IsolatedAsyncioTestCase):
    async def test_udp_tcp_and_fallback(self):
        loop = asyncio.get_running_loop()
        udp, _ = await loop.create_datagram_endpoint(EchoDNS, local_addr=("127.0.0.1", 0))
        self.addCleanup(udp.close)
        udp_port = udp.get_extra_info("sockname")[1]
        bridge = AuthoritativeBridge("127.0.0.1", udp_port)
        tcp = await asyncio.start_server(bridge.handle, "127.0.0.1", 0)
        async with tcp:
            port = tcp.sockets[0].getsockname()[1]
            packet = bytes.fromhex("12340100000100000000000001610000010001")
            for mode, target in (("udp", udp_port), ("tcp", port), ("auto", port)):
                adapter, handler = await loop.create_datagram_endpoint(
                    lambda: ResolverBridge("127.0.0.1", target, mode, 0.3),
                    local_addr=("127.0.0.1", 0))
                try:
                    result = await asyncio.wait_for(query(packet, "127.0.0.1",
                        adapter.get_extra_info("sockname")[1], "udp"), 2)
                    self.assertEqual(result, packet[:2] + b"\x81" + packet[3:])
                    if mode == "auto":
                        self.assertEqual(handler.preferred, "tcp")
                finally:
                    adapter.close()
