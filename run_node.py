"""Run all services in a node profile, fail as a group on unexpected exit."""
import asyncio
import json
import signal
import sys
from pathlib import Path


async def run(directory):
    services = json.loads((directory / "services.json").read_text())
    children = []
    waits = []
    stopping = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, stopping.set)
    try:
        for argv in services:
            children.append(await asyncio.create_subprocess_exec(*argv, cwd=directory))
        waits = [asyncio.create_task(p.wait()) for p in children]
        waits.append(asyncio.create_task(stopping.wait()))
        await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
        return 0 if stopping.is_set() else 1
    finally:
        for child in children:
            if child.returncode is None:
                child.terminate()
        try:
            async with asyncio.timeout(5):
                await asyncio.gather(*(child.wait() for child in children))
        except TimeoutError:
            for child in children:
                if child.returncode is None:
                    child.kill()
            await asyncio.gather(*(child.wait() for child in children))
        for task in waits:
            task.cancel()


if __name__ == "__main__":
    sys.exit(asyncio.run(run(Path(sys.argv[1]).resolve())))
