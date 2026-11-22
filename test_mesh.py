import asyncio
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from mesh import entry_server, exit_server


class MeshIntegration(unittest.IsolatedAsyncioTestCase):
    async def server(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        return server

    async def unused_port(self):
        server = await self.server(lambda *args: None)
        port = server.sockets[0].getsockname()[1]
        server.close()
        return port

    async def launch(self, fn, config):
        task = asyncio.create_task(fn(config))
        async def cleanup():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.addAsyncCleanup(cleanup)
        await asyncio.sleep(0.08)
        if task.done():
            task.result()

    async def test_survives_one_path_loss(self):
        with tempfile.TemporaryDirectory() as temp:
            keys = Path(temp, "keys")
            await asyncio.to_thread(subprocess.run, ["sh", str(Path(__file__).with_name("certificates.sh")), str(keys)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            external = await self.unused_port()
            local = await self.unused_port()
            def config(side, port):
                return dict(ca=str(keys / "ca.crt"), cert=str(keys / f"{side}.crt"),
                            key=str(keys / f"{side}.key"), listen=["127.0.0.1", port])
            await self.launch(exit_server, config("exit", external))
            dropped = asyncio.Event()
            async def fragile(r, w):
                upstream, pipe = await asyncio.open_connection("127.0.0.1", external)
                async def copy(src, dst, count=False):
                    while data := await src.read(32768):
                        dst.write(data)
                        await dst.drain()
                        if count and len(data) > 8192:
                            w.close()
                            pipe.close()
                            dropped.set()
                            break
                try:
                    await asyncio.gather(copy(r, pipe, True), copy(upstream, w))
                except OSError:
                    pass
                finally:
                    w.close()
                    pipe.close()
            relay = await self.server(fragile)
            entry = config("entry", local)
            entry["paths"] = [["127.0.0.1", relay.sockets[0].getsockname()[1]], ["127.0.0.1", external]]
            await self.launch(entry_server, entry)
            payload = os.urandom(2 * 1024 * 1024 + 257)
            async def echo(reader, writer):
                data = await reader.read()
                writer.write(data)
                await writer.drain()
                writer.close()
            target = await self.server(echo)
            port = target.sockets[0].getsockname()[1]
            async with asyncio.timeout(30):
                r, w = await asyncio.open_connection("127.0.0.1", local)
                w.write(bytes.fromhex("050100"))
                self.assertEqual(await r.readexactly(2), bytes.fromhex("0500"))
                w.write(bytes.fromhex("050100017f000001") + port.to_bytes(2, "big"))
                self.assertEqual((await r.readexactly(10))[1], 0)
                w.write(payload)
                await w.drain()
                w.write_eof()
                await dropped.wait()
                relay.close()
                self.assertEqual(await r.read(), payload)
                w.close()
                await w.wait_closed()
