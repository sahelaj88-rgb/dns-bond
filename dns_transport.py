"""DNS transport adapters for MasterDnsVPN. Python 3.11+, no dependencies."""
import argparse
import asyncio
import contextlib
import ipaddress
import socket
import struct
from pathlib import Path
from health import respond


async def read_dns(reader):
    size, = struct.unpack("!H", await reader.readexactly(2))
    if size < 12:
        raise ValueError("invalid DNS frame")
    return await reader.readexactly(size)


def frame(data):
    return struct.pack("!H", len(data)) + data


async def query(data, host, port, mode):
    if mode == "tcp":
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(frame(data))
            await writer.drain()
            response = await read_dns(reader)
        finally:
            writer.close()
    else:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            loop = asyncio.get_running_loop()
            await loop.sock_connect(sock, (host, port))
            await loop.sock_sendall(sock, data)
            response = await loop.sock_recv(sock, 65535)
    if len(response) < 12 or response[:2] != data[:2] or not response[2] & 128:
        raise ValueError("mismatched DNS response")
    return response


class ResolverBridge(asyncio.DatagramProtocol):
    def __init__(self, host, port, mode, timeout, limit=128, health=None):
        self.health = health
        self.host, self.port, self.mode = host, port, mode
        self.timeout, self.limit = timeout, limit
        self.jobs = set()
        self.preferred = "udp"

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        for job in self.jobs:
            job.cancel()

    def datagram_received(self, data, address):
        if len(data) < 12 or len(self.jobs) >= self.limit:
            return
        if self.health:
            answer = respond(data, *self.health)
            if answer:
                self.transport.sendto(answer, address)
                return
        job = asyncio.create_task(self.answer(data, address))
        self.jobs.add(job)
        job.add_done_callback(self.jobs.discard)

    async def answer(self, data, address):
        modes = [self.mode]
        if self.mode == "auto":
            modes = [self.preferred, "tcp" if self.preferred == "udp" else "udp"]
        for mode in modes:
            try:
                async with asyncio.timeout(self.timeout):
                    reply = await query(data, self.host, self.port, mode)
                if self.mode == "auto" and mode == "udp" and reply[2] & 2:
                    continue
                self.transport.sendto(reply, address)
                self.preferred = mode
                return
            except (OSError, ValueError, EOFError):
                continue


class AuthoritativeBridge:
    def __init__(self, host, port, limit=256, health=None):
        self.host, self.port, self.limit = host, port, limit
        self.health = health
        self.active = 0

    async def handle(self, reader, writer):
        if self.active >= self.limit:
            writer.close()
            return
        self.active += 1
        try:
            while True:
                async with asyncio.timeout(30):
                    data = await read_dns(reader)
                async with asyncio.timeout(5):
                    answer = respond(data, *self.health) if self.health else None
                    writer.write(frame(answer or await query(data, self.host, self.port, "udp")))
                    await writer.drain()
        except (OSError, ValueError, EOFError):
            pass
        finally:
            self.active -= 1
            writer.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["resolver", "authority"])
    parser.add_argument("--listen")
    parser.add_argument("--port", type=int)
    parser.add_argument("--target", required=True, type=ipaddress.ip_address)
    parser.add_argument("--target-port", type=int, default=53)
    parser.add_argument("--mode", choices=["auto", "udp", "tcp"], default="auto")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--domain")
    parser.add_argument("--key-file", type=Path)
    args = parser.parse_args()
    if args.role == "resolver":
        host = args.listen or "127.0.0.1"
        if not ipaddress.ip_address(host).is_loopback:
            parser.error("resolver adapter requires a loopback listener")
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: ResolverBridge(str(args.target), args.target_port, args.mode, args.timeout),
            local_addr=(host, args.port or 5300))
        with contextlib.closing(transport):
            await asyncio.Future()
    else:
        health = (args.domain, args.key_file.read_bytes().strip()) if args.key_file and args.domain else None
        server = AuthoritativeBridge(str(args.target), args.target_port, health=health)
        addr = (args.listen or "0.0.0.0", args.port or 53)
        udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: ResolverBridge(str(args.target), args.target_port, "udp", 5, 512, health),
            local_addr=addr)
        with contextlib.closing(udp):
            async with await asyncio.start_server(server.handle, *addr) as tcp:
                await tcp.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
