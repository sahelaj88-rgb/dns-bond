"""Loopback-only SOCKS5 demonstration with three local paths in each direction."""
import asyncio
import socket
import struct
from contextlib import AsyncExitStack

from bond import receive_stream, send_stream


async def serve_http(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
        body = b"dns-bond local transfer OK\n"
        writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                     str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
    finally:
        writer.close()


async def proxy(client, reply, target_port):
    async with AsyncExitStack() as resources:
        resources.callback(reply.close)
        async def paths():
            left, right = [], []
            for _ in range(3):
                a, b = socket.socketpair()
                resources.callback(a.close)
                resources.callback(b.close)
                for sock, group in ((a, left), (b, right)):
                    pair = await asyncio.open_connection(sock=sock)
                    resources.callback(pair[1].close)
                    group.append(pair)
            return left, right

        version, count = await client.readexactly(2)
        methods = await client.readexactly(count)
        if version != 5 or 0 not in methods:
            reply.write(b"\x05\xff")
            await reply.drain()
            return
        reply.write(b"\x05\x00")
        await reply.drain()
        header = await client.readexactly(4)
        status = 7
        if header == b"\x05\x01\x00\x01":
            address, port = struct.unpack("!4sH", await client.readexactly(6))
            status = 0 if (address, port) == (socket.inet_aton("127.0.0.1"), target_port) else 2
        if status == 0:
            remote, destination = await asyncio.open_connection("127.0.0.1", target_port)
            resources.callback(destination.close)
        reply.write(bytes((5, status, 0, 1)) + bytes(6))
        await reply.drain()
        if status:
            return
        up_local, up_remote = await paths()
        down_remote, down_local = await paths()
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(send_stream(client, up_local))
            tasks.create_task(receive_stream(up_remote, destination))
            tasks.create_task(send_stream(remote, down_remote))
            tasks.create_task(receive_stream(down_local, reply))


async def main():
    async with await asyncio.start_server(serve_http, "127.0.0.1", 18080) as http:
        async def handle(client, reply):
            try:
                async with asyncio.timeout(60):
                    await proxy(client, reply, 18080)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                pass
        async with await asyncio.start_server(handle, "127.0.0.1", 1080) as server:
            print("SOCKS5 127.0.0.1:1080 -> local HTTP 127.0.0.1:18080", flush=True)
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
