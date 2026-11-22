"""Run four real node processes locally using installed official MasterDnsVPN binaries."""
import contextlib
import functools
import http.server
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def provision(path, answers):
    subprocess.run([PYTHON, ROOT / "setup_node.py", path], input="\n".join(answers)+"\n",
                   text=True, check=True, stdout=subprocess.DEVNULL)


def patch(profile, index, extra):
    f = profile / "services.json"
    jobs = json.loads(f.read_text())
    jobs[index].extend(map(str, extra))
    f.write_text(json.dumps(jobs))


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run(work):
    for name in ("masterdnsvpn-client", "masterdnsvpn-server", "curl", "openssl"):
        if not shutil.which(name):
            raise SystemExit(f"{name} required on PATH")
    # Each node normally owns its machine and standard ports. The fixture only
    # remaps its UDP/TCP listener and local engine port to share one host.
    keys = work / "keys"
    subprocess.run(["sh", ROOT / "certificates.sh", keys], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    inventory = work / "list"
    inventory.write_text("127.0.0.1\n")
    nodes = []
    for i, role in enumerate(("master", "helper")):
        domain = f"pair{i}.example.test"
        outside, inside = work / f"outside{i}", work / f"inside{i}"
        answers = ["outside", role, domain]
        answers += ["127.0.0.1", "27443"] if i else ["27443", "127.0.0.1"]
        provision(outside, answers)
        engine_port, authority_port = 25453+i, 25553+i
        f = outside / "server.toml"
        f.write_text(f.read_text().replace("UDP_PORT = 15453", f"UDP_PORT = {engine_port}"))
        patch(outside, 1, ["--port", authority_port, "--target-port", engine_port])
        inputs = ["iran", role, domain, str(outside / "pair.json")]
        if i:
            inputs += ["127.0.0.1"]
        inputs += [str(27001+i), "tcp" if i else "udp", str(inventory)]
        if not i:
            inputs += ["127.0.0.1:27002", "-", "21080"]
        provision(inside, inputs)
        slot = 25300 + i
        patch(inside, 0, ["--slot-port", slot, "--resolver-port", authority_port])
        f = inside / "active.txt"
        f.write_text(f.read_text().replace(":15300", f":{slot}"))
        if not i:
            for target, label in ((inside,"entry"), (outside,"exit")):
                for filename in ["ca.crt", label+".key", label+".crt"]:
                    shutil.copy(keys / filename, target)
        nodes.extend([outside, inside])
    www = work / "www"
    www.mkdir()
    payload = os.urandom(65537)
    (www / "sample.bin").write_bytes(payload)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=www)
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with contextlib.ExitStack() as cleanup:
        cleanup.callback(origin.server_close)
        cleanup.callback(origin.shutdown)
        children = {}
        for node in nodes:
            log = cleanup.enter_context((work / (node.name+".log")).open("w"))
            child = subprocess.Popen([PYTHON, ROOT / "run_node.py", node], stdout=log, stderr=log)
            cleanup.callback(stop, child)
            children[node.name] = child
        def fetch(label):
            deadline = time.monotonic()+90
            while time.monotonic() < deadline:
                result = subprocess.run(["curl", "-fsS", "--noproxy", "", "--max-time", "14",
                    "--socks5-hostname", "127.0.0.1:21080",
                    f"http://127.0.0.1:{origin.server_port}/sample.bin"], capture_output=True)
                if result.returncode == 0 and result.stdout == payload:
                    print(label, "OK", flush=True)
                    return
                time.sleep(1)
            raise RuntimeError(label + " timed out")
        fetch("Four roles, two domains")
        # Disable the direct forwarder without stopping its SOCKS entry.
        stop(children["outside0"])
        # Keep the exit master itself alive, but leave its first DNS authority down.
        exit_process = subprocess.Popen([PYTHON, ROOT/"mesh.py", "exit", "mesh.json"],
                                        cwd=nodes[0])
        cleanup.callback(stop, exit_process)
        fetch("Helper-only TCP DNS path")
    return True


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        run(Path(d))
