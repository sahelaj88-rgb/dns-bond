"""Distribute one inventory atomically via an existing authenticated SSH account."""
import argparse
import hashlib
import logging
import time
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from pool import read_inventory


def push(peer, data):
    dest, path = peer.split(":", 1)
    if not re.fullmatch(r"[\w][\w.@-]*", dest) or not path.startswith("/"):
        raise ValueError("use ssh-host:/absolute/profile")
    # mktemp on the same filesystem keeps the final rename atomic.
    cmd = ("set -eu; umask 077; cd " + shlex.quote(path) +
           "; test -f client.toml; f=$(mktemp .resolvers.XXXXXXXX); "
           "trap 'rm -f \"$f\"' EXIT; cat > \"$f\"; mv \"$f\" resolvers.txt")
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "--", dest, cmd], input=data, check=True, timeout=60)


def publish(file, profile, peers):
    data, _ = read_inventory(file)
    if not profile.is_dir() or not (profile / "client.toml").is_file():
        raise ValueError("expected an Iran node profile directory")
    for peer in peers:
        push(peer, data)
    with tempfile.NamedTemporaryFile(dir=profile, delete=False) as target:
        target.write(data)
        tmp = target.name
    os.replace(tmp, profile / "resolvers.txt")


def watch(file, peers):
    delivered = {}
    while True:
        try:
            data, _ = read_inventory(file)
            digest = hashlib.sha256(data).digest()
            for peer in peers:
                if delivered.get(peer) == digest:
                    continue
                try:
                    push(peer, data)
                    delivered[peer] = digest
                    logging.info("inventory delivered to %s", peer)
                except (OSError, subprocess.SubprocessError) as e:
                    logging.warning("sync to %s failed: %s", peer, e)
        except (OSError, ValueError) as e:
            logging.warning("waiting for valid inventory: %s", e)
        time.sleep(10)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("file", type=Path)
    p.add_argument("profile", type=Path)
    p.add_argument("peers", nargs="*")
    p.add_argument("--watch", action="store_true")
    args = p.parse_args()
    if args.watch:
        logging.basicConfig(level=logging.INFO)
        watch(args.file, args.peers)
    else:
        publish(args.file, args.profile, args.peers)
