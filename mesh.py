"""Bond TCP streams over independent forwarders. Each path uses mutual TLS."""
import argparse
import asyncio
import contextlib
import ipaddress
import json
import secrets
import ssl
import struct
import time
from pathlib import Path

BLOCK = 16384
WINDOW = 32
NONE = 2**64 - 1
HEADER = struct.Struct("!QQH")
HANDSHAKE = struct.Struct("!16sH")
GRACE = 120


class Stream:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.pending, self.buffer = {}, {}
        self.instance = secrets.token_bytes(16)
        self.sent = self.expected = self.acked = 0
        self.eof_out = self.eof_in = False
        self.wakeup = asyncio.Event()
        self.lock = asyncio.Lock()
        self.last_seen = time.monotonic()
        self.producer = asyncio.create_task(self.produce())

    async def produce(self):
        while not self.eof_out:
            if len(self.pending) >= WINDOW:
                self.wakeup.clear()
                await self.wakeup.wait()
                continue
            data = await self.reader.read(BLOCK)
            self.eof_out = not data
            self.pending[self.sent] = (data, 0.0)
            self.sent += 1

    def packet(self):
        if self.producer.done():
            self.producer.result()
        now = time.monotonic()
        for seq, (data, last) in self.pending.items():
            if not last or now - last >= 2:
                self.pending[seq] = data, now
                return HEADER.pack(self.expected, seq, len(data)) + data
        return HEADER.pack(self.expected, NONE, 0)

    async def accept(self, ack, seq, data):
        async with self.lock:
            if ack > self.sent:
                raise ValueError("invalid ACK")
            for key in range(self.acked, ack):
                self.pending.pop(key, None)
            self.acked = max(ack, self.acked)
            self.wakeup.set()
            if seq == NONE or seq < self.expected:
                return
            if self.eof_in or seq >= self.expected + WINDOW:
                raise ValueError("invalid receive window")
            self.buffer[seq] = data
            while self.expected in self.buffer:
                part = self.buffer.pop(self.expected)
                self.expected += 1
                if part:
                    self.writer.write(part)
                else:
                    self.eof_in = True
                    self.writer.write_eof()
                    break
            await self.writer.drain()

    @property
    def finished(self):
        return self.eof_in and self.eof_out and not self.pending

    async def close(self):
        self.producer.cancel()
        await asyncio.gather(self.producer, return_exceptions=True)
        self.writer.close()


async def receive(reader, stream):
    ack, seq, size = HEADER.unpack(await reader.readexactly(HEADER.size))
    if size > BLOCK or (seq == NONE and size):
        raise ValueError("invalid frame")
    await stream.accept(ack, seq, await reader.readexactly(size))
    return size


def tls(config, server):
    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    ctx = ssl.create_default_context(purpose, cafile=config["ca"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(config["cert"], config["key"])
    return ctx


async def exit_server(config):
    sessions = {}
    opening = {}

    async def create(sid, host, port):
        try:
            dest = await asyncio.wait_for(asyncio.open_connection(host, port), 8)
            sessions[sid] = host, port, Stream(*dest)
        finally:
            opening.pop(sid, None)
    async def handle(reader, writer):
        try:
            async with asyncio.timeout(20):
                sid, size = HANDSHAKE.unpack(await reader.readexactly(HANDSHAKE.size))
                if not 1 <= size <= 253:
                    raise ValueError("invalid host")
                host = (await reader.readexactly(size)).decode("ascii")
                port, = struct.unpack("!H", await reader.readexactly(2))
                if sid not in sessions:
                    if sid not in opening:
                        if len(sessions) + len(opening) >= 512:
                            return
                        opening[sid] = asyncio.create_task(create(sid, host, port))
                    await asyncio.shield(opening[sid])
                h, p, stream = sessions[sid]
                if (h, p) != (host, port):
                    return
                writer.write(b"Y" + stream.instance)
                await writer.drain()
            while True:
                async with asyncio.timeout(30):
                    size = await receive(reader, stream)
                    stream.last_seen = time.monotonic()
                    pkt = stream.packet()
                    writer.write(pkt)
                    await writer.drain()
                if not size and len(pkt) == HEADER.size:
                    await asyncio.sleep(0.015)
        except (OSError, EOFError, ValueError, RuntimeError):
            pass
        finally:
            writer.close()

    async def reap():
        while True:
            await asyncio.sleep(5)
            expired = [sid for sid, (_, _, s) in sessions.items()
                       if time.monotonic()-s.last_seen > (5 if s.finished else GRACE)]
            for sid in expired:
                await sessions.pop(sid)[2].close()
    async with await asyncio.start_server(handle, *config["listen"], ssl=tls(config, True)) as server:
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(reap())
            tasks.create_task(server.serve_forever())


async def socks_target(r, w):
    version, count = await r.readexactly(2)
    methods = await r.readexactly(count)
    if version != 5 or 0 not in methods:
        w.write(b"\x05\xff")
        raise ValueError("unsupported SOCKS authentication")
    w.write(b"\x05\x00")
    await w.drain()
    version, cmd, reserved, kind = await r.readexactly(4)
    if (version, cmd, reserved) != (5, 1, 0):
        raise ValueError("CONNECT required")
    if kind == 3:
        n = (await r.readexactly(1))[0]
        host = await r.readexactly(n)
    elif kind in (1, 4):
        host = str(ipaddress.ip_address(await r.readexactly(4 if kind == 1 else 16))).encode()
    else:
        raise ValueError("address type")
    return HANDSHAKE.pack(secrets.token_bytes(16), len(host)) + host + await r.readexactly(2)


async def entry_server(config):
    context = tls(config, False)
    if not ipaddress.ip_address(config["listen"][0]).is_loopback or not config["paths"]:
        raise ValueError("entry requires loopback and at least one path")

    async def handle(r, w):
        tasks = []
        stream = None
        ready = asyncio.Event()
        started = asyncio.Event()
        instance = None
        async def lane(path, hello):
            nonlocal instance
            while True:
                remote = None
                try:
                    async with asyncio.timeout(15):
                        rr, remote = await asyncio.open_connection(*path, ssl=context,
                            server_hostname="dns-bond-exit")
                        remote.write(hello)
                        await remote.drain()
                        if await rr.readexactly(1) != b"Y":
                            raise ValueError("exit refused")
                        token = await rr.readexactly(16)
                        if instance is not None and token != instance:
                            w.close()
                            return
                        instance = token
                    ready.set()
                    await started.wait()
                    burst = 1
                    while True:
                        # Multiple outstanding exchanges fill the path during a
                        # long RTT. Idle sessions use a single poll per round.
                        async with asyncio.timeout(25):
                            sent_payload = False
                            for _ in range(burst):
                                pkt = stream.packet()
                                remote.write(pkt)
                                sent_payload |= len(pkt) > HEADER.size
                            await remote.drain()
                            received = 0
                            for _ in range(burst):
                                received += await receive(rr, stream)
                            stream.last_seen = time.monotonic()
                        burst = 8 if sent_payload or received else 1
                        if burst == 1:
                            await asyncio.sleep(0.015)
                except (OSError, EOFError, ValueError):
                    await asyncio.sleep(0.5)
                finally:
                    if remote:
                        remote.close()

        try:
            async with asyncio.timeout(20):
                hello = await socks_target(r, w)
                tasks = [asyncio.create_task(lane(p, hello)) for p in config["paths"]]
                await ready.wait()
                w.write(b"\x05\x00\x00\x01" + bytes(6))
                await w.drain()
            stream = Stream(r, w)
            started.set()
            while not w.is_closing() and not stream.finished and time.monotonic()-stream.last_seen < GRACE-20:
                await asyncio.sleep(0.1)
        except (OSError, EOFError, ValueError):
            if not started.is_set():
                with contextlib.suppress(OSError):
                    w.write(b"\x05\x01\x00\x01" + bytes(6))
                    await w.drain()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if stream:
                await stream.close()
            else:
                w.close()
    async with await asyncio.start_server(handle, *config["listen"]) as server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["entry", "exit"])
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    asyncio.run((entry_server if args.role == "entry" else exit_server)(cfg))
