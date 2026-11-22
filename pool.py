"""Bounded DNS health checks for a supplied resolver inventory on an Iran node."""
import argparse
import asyncio
import ipaddress
import itertools
import logging
from health import make_probe, verified
import time
from pathlib import Path
from dns_transport import query

SLOTS = 8


def read_inventory(path):
    limit = 8 * 1024 * 1024
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("resolver file exceeds 8 MiB")
    entries = {}
    for line in data.decode("utf-8-sig").splitlines():
        text = line.partition("#")[0].strip()
        if not text:
            continue
        host = ipaddress.ip_address(text)
        if host.is_multicast or host.is_unspecified:
            raise ValueError("invalid resolver address")
        entries[str(host)] = None
        if len(entries) > 30000:
            raise ValueError("limit is 30000 unique resolver IPs")
    if not entries:
        raise ValueError("empty resolver list")
    return data, entries


def inventory(path):
    return read_inventory(path)[1]


class Pool:
    def __init__(self, args):
        self.args = args
        self.key = args.key_file.read_bytes().strip()
        self.healthy = {}
        self.members = set()
        self.slots = [None] * SLOTS
        self.errors = {}
        self.running = set()
        self.user_load = 0

    async def exchange(self, packet, host, preferred, verify_health=False):
        mode = self.args.mode
        routes = [mode] if mode != "auto" else [preferred, "tcp" if preferred == "udp" else "udp"]
        for route in routes:
            try:
                async with asyncio.timeout(self.args.timeout):
                    reply = await query(packet, host, self.args.resolver_port, route)
                if mode == "auto" and route == "udp" and reply[2] & 2:
                    continue
                if verify_health and not verified(packet, reply, self.key):
                    continue
                return reply, route
            except (OSError, EOFError, ValueError):
                pass
        raise TimeoutError

    def refresh(self):
        # Keep healthy routes stable while the upstream engine measures each slot.
        taken = {h for h in self.slots if h in self.healthy}
        candidates = iter(sorted(self.healthy.keys() - taken, key=lambda h:self.healthy[h][1]))
        for i, host in enumerate(self.slots):
            if host not in self.healthy:
                self.slots[i] = next(candidates, None)

    def rebalance(self):
        self.refresh()
        spare = self.healthy.keys() - set(self.slots)
        if not spare or None in self.slots:
            return
        # Change one slot per sweep so the engine retains measured alternatives.
        best = min(spare, key=lambda h: self.healthy[h][1])
        worst = max(range(SLOTS), key=lambda i: self.healthy[self.slots[i]][1])
        if self.healthy[best][1] < 0.7 * self.healthy[self.slots[worst]][1]:
            self.slots[worst] = best

    def failed(self, host):
        if host not in self.healthy:
            return
        self.errors[host] = self.errors.get(host, 0) + 1
        if self.errors[host] >= 3:
            self.healthy.pop(host, None)
            self.errors.pop(host, None)
            self.refresh()

    async def check(self, host):
        start = time.monotonic()
        try:
            data = make_probe(self.args.domain)
            response, mode = await self.exchange(data, host, self.healthy.get(host, ("udp", 0))[0], verify_health=True)
            if host in self.members:
                self.healthy[host] = mode, time.monotonic() - start
                self.errors.pop(host, None)
                if None in self.slots:
                    self.refresh()
        except (OSError, ValueError):
            self.failed(host)

    async def monitor(self):
        while True:
            try:
                listed = await asyncio.to_thread(inventory, self.args.file)
            except (OSError, ValueError) as e:
                logging.warning("Resolver file: %s", e)
                await asyncio.sleep(5)
                continue
            self.members = set(listed)
            for host in self.healthy.keys() - self.members:
                self.healthy.pop(host)
                self.errors.pop(host, None)
            self.refresh()
            for host in itertools.chain((h for h in self.slots if h), listed):
                while len(self.running) >= 64:
                    await asyncio.wait(self.running.copy(), return_when=asyncio.FIRST_COMPLETED)
                task = asyncio.create_task(self.check(host))
                self.running.add(task)
                task.add_done_callback(self.running.discard)
                await asyncio.sleep((4 if self.user_load >= 32 else 1) / self.args.rate)
            if self.running:
                await asyncio.gather(*self.running.copy())
            self.rebalance()
            logging.info("resolver list=%d responding=%d active=%d", len(listed),
                         len(self.healthy), sum(h is not None for h in self.slots))
            await asyncio.sleep(5)


class Slot(asyncio.DatagramProtocol):
    def __init__(self, pool, index):
        self.pool, self.index = pool, index
        self.jobs = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        host = self.pool.slots[self.index]
        if not host or len(data) < 12 or len(self.jobs) >= 64:
            return
        job = asyncio.create_task(self.answer(host, data, addr))
        self.jobs.add(job)
        job.add_done_callback(self.jobs.discard)

    async def answer(self, host, data, addr):
        self.pool.user_load += 1
        try:
            preferred = self.pool.healthy.get(host, ("udp", 0))[0]
            reply, mode = await self.pool.exchange(data, host, preferred)
            self.transport.sendto(reply, addr)
            if host in self.pool.healthy:
                self.pool.healthy[host] = mode, self.pool.healthy[host][1]
        except OSError:
            self.pool.failed(host)
        finally:
            self.pool.user_load -= 1


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--mode", choices=["udp", "tcp", "auto"], default="auto")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--rate", type=int, choices=range(1, 151), default=100, metavar="1..150")
    parser.add_argument("--resolver-port", type=int, default=53)
    parser.add_argument("--slot-port", type=int, default=15300)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()
    pool = Pool(args)
    listeners = []
    try:
        for i in range(SLOTS):
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda i=i: Slot(pool, i), local_addr=(f"127.70.0.{i+1}", args.slot_port))
            listeners.append(transport)
        await pool.monitor()
    finally:
        for listener in listeners:
            listener.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
