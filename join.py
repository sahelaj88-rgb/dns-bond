"""Exchange a short-lived, single-use pair invitation over authenticated SSH."""
import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path


def token_path(directory, token):
    if not re.fullmatch("[A-Za-z0-9_-]{32}", token):
        raise ValueError("invalid invite")
    return directory / ("invite-" + hashlib.sha256(token.encode()).hexdigest())


def issue(directory):
    if not (directory / "pair.json").is_file():
        raise ValueError("outside profile required")
    token = secrets.token_urlsafe(24)
    with token_path(directory, token).open("x") as f:
        f.write(str(int(time.time()) + 900))
    print(token)


def consume(directory, token):
    path = token_path(directory, token)
    # Rename claims the invitation exactly once across concurrent SSH sessions.
    claimed = path.with_name(path.name + "-" + secrets.token_hex(8))
    path.rename(claimed)
    try:
        if time.time() > int(claimed.read_text()):
            raise ValueError("invite expired")
        return (directory / "pair.json").read_bytes()
    finally:
        claimed.unlink()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    for cmd in ["invite", "consume"]:
        sub.add_parser(cmd).add_argument("profile", type=Path)
    j = sub.add_parser("redeem")
    j.add_argument("ssh_host")
    j.add_argument("remote_profile")
    j.add_argument("output", type=Path)
    args = p.parse_args()
    os.umask(0o077)
    if args.action == "invite":
        issue(args.profile)
    elif args.action == "consume":
        sys.stdout.buffer.write(consume(args.profile, sys.stdin.readline().strip()))
    else:
        if args.output.exists():
            p.error("choose a new output filename")
        if not re.fullmatch(r"[\w][\w.@-]*", args.ssh_host):
            p.error("invalid SSH host")
        token = getpass.getpass("کد عضویت: ")
        cmd = shlex.join(["python3", "/opt/dns-bond/join.py", "consume", args.remote_profile])
        proc = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                               "--", args.ssh_host, cmd], input=(token+"\n").encode(),
                              stdout=subprocess.PIPE, check=True, timeout=30)
        pair = json.loads(proc.stdout)
        if not isinstance(pair.get("domain"), str) or not re.fullmatch("[a-f0-9]{32}", pair["key"]):
            raise ValueError("invalid remote pair profile")
        with args.output.open("x") as f:
            json.dump(pair, f)
