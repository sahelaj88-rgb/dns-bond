"""Bounded framing and reassembly for a single directional byte stream."""
import struct

CHUNK = 8192
WINDOW = 64
HEADER = struct.Struct("!QH")


class Receiver:
    def __init__(self):
        self.expected = 0
        self.pending = {}
        self.finished = False

    def accept(self, index, payload):
        if index < self.expected:
            return b""
        if self.finished or not self.expected <= index < self.expected + WINDOW:
            raise ValueError("frame beyond receive window")
        if len(payload) > CHUNK:
            raise ValueError("oversized frame")
        if index in self.pending and self.pending[index] != payload:
            raise ValueError("conflicting duplicate")
        self.pending[index] = payload
        ready = bytearray()
        while self.expected in self.pending:
            part = self.pending.pop(self.expected)
            self.expected += 1
            if not part:
                if self.pending:
                    raise ValueError("data after end of stream")
                self.finished = True
                break
            ready.extend(part)
        return bytes(ready)


async def read_frame(reader):
    index, size = HEADER.unpack(await reader.readexactly(HEADER.size))
    if size > CHUNK:
        raise ValueError("oversized frame")
    return index, await reader.readexactly(size)


async def send_stream(reader, paths):
    """Send one bounded window and wait for cumulative delivery on path zero."""
    index = 0
    while True:
        data = await reader.read(CHUNK)
        _, writer = paths[index % len(paths)]
        writer.write(HEADER.pack(index, len(data)) + data)
        await writer.drain()
        index += 1
        if index % WINDOW == 0 or not data:
            ack = await paths[0][0].readexactly(8)
            if int.from_bytes(ack, "big") != index:
                raise ValueError("invalid delivery acknowledgement")
        if not data:
            return


async def receive_stream(paths, output):
    import asyncio
    receiver = Receiver()
    # Only one waiter per lane; carry buffered frames across window boundaries.
    reads = {asyncio.create_task(read_frame(reader)): reader for reader, _ in paths}
    acknowledged = 0
    try:
        while not receiver.finished:
            done, _ = await asyncio.wait(reads, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                reader = reads.pop(task)
                index, data = task.result()
                output.write(receiver.accept(index, data))
                await output.drain()
                reads[asyncio.create_task(read_frame(reader))] = reader
            if receiver.finished or receiver.expected - acknowledged >= WINDOW:
                acknowledged = receiver.expected
                paths[0][1].write(acknowledged.to_bytes(8, "big"))
                await paths[0][1].drain()
        if output.can_write_eof():
            output.write_eof()
    finally:
        for task in reads:
            task.cancel()
        await asyncio.gather(*reads, return_exceptions=True)
