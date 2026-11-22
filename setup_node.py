"""Interactive per-node provisioning. Runtime files stay outside the checkout."""
import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def ask(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    answer = input(label + suffix + ": ").strip() or default
    if answer is None:
        raise ValueError("مقدار لازم است")
    return str(answer)


def choice(label, choices):
    answer = ask(label + " (" + "/".join(choices) + ")", choices[0])
    if answer not in choices:
        raise ValueError("انتخاب نامعتبر")
    return answer


def ip(label, default):
    return str(ipaddress.ip_address(ask(label, default)))


def port(label, default):
    n = int(ask(label, default))
    if not 1 <= n <= 65535:
        raise ValueError("پورت نامعتبر")
    return n


def domain():
    name = ask("دامنهٔ اختصاصی این جفت، مثل tun.example.com").rstrip(".").lower()
    if len(name) > 215 or "." not in name or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in name.split(".")
    ):
        raise ValueError("دامنه نامعتبر")
    return name


def save(directory, name, data):
    (directory / name).write_text(data, encoding="utf8")


def make_profile(out):
    side = choice("محل سرور", ["iran", "outside"])
    role = choice("نقش سرور", ["master", "helper"])
    name = domain()
    q = json.dumps
    jobs = []
    def job(*args):
        jobs.append(list(map(str, args)))

    pair = {"domain": name}
    if side == "outside":
        key = secrets.token_hex(16)
        pair["key"] = key
        exit_host = "127.0.0.1" if role == "master" else ip("IP خصوصی یا عمومی مستر خارج", None)
        exit_port = port("پورت اتصال به مستر خارج", 7443)
        save(out, "server.toml", f'DOMAIN = [{q(name)}]\nPROTOCOL_TYPE = "TCP"\n'
             f'UDP_HOST = "127.0.0.1"\nUDP_PORT = 15453\nFORWARD_IP = {q(exit_host)}\nFORWARD_PORT = {exit_port}\n'
             'DATA_ENCRYPTION_METHOD = 5\nENCRYPTION_KEY_FILE = "encrypt_key.txt"\n')
        save(out, "encrypt_key.txt", key + "\n")
        save(out, "pair.json", q(pair))
        job("masterdnsvpn-server", "-config", "server.toml")
        job(sys.executable, ROOT / "dns_transport.py", "authority", "--target", "127.0.0.1",
            "--target-port", 15453, "--domain", name, "--key-file", "encrypt_key.txt")
        if role == "master":
            mesh = {"listen": [ip("IP سرویس تجمیع خارج", "0.0.0.0"), exit_port],
                    "ca": "ca.crt", "cert": "exit.crt", "key": "exit.key"}
            save(out, "mesh.json", q(mesh, indent=2))
            job(sys.executable, ROOT / "mesh.py", "exit", "mesh.json")
    else:
        pair = json.loads(Path(ask("مسیر pair.json همین جفت")).read_text())
        if pair["domain"] != name or not re.fullmatch("[0-9a-f]{32}", pair["key"]):
            raise ValueError("دامنه یا کلید جفت تطابق ندارد")
        listen = "127.0.0.1" if role == "master" else ip("IP داخلی این سرور برای مستر ایران", None)
        tunnel_port = port("پورت محلی ارسال به تونل", 17001)
        mode = choice("انتقال DNS", ["auto", "udp", "tcp"])
        source = Path(ask("مسیر فایل resolverهای این جفت"))
        # The monitor produces a small active pool out of the complete list.
        shutil.copyfile(source, out / "resolvers.txt")
        save(out, "encrypt_key.txt", pair["key"] + "\n")
        job(sys.executable, ROOT / "pool.py", "--file", "resolvers.txt", "--mode", mode,
            "--domain", name, "--key-file", "encrypt_key.txt")
        save(out, "active.txt", "".join(f"127.70.0.{p}:15300\n" for p in range(1, 9)))
        save(out, "client.toml", f'DOMAINS = [{q(name)}]\nPROTOCOL_TYPE = "TCP"\n'
             f'LISTEN_IP = {q(listen)}\nLISTEN_PORT = {tunnel_port}\n'
             f'DATA_ENCRYPTION_METHOD = 5\nENCRYPTION_KEY = {q(pair["key"])}\n'
             'LOCAL_DNS_ENABLED = false\nRECHECK_INACTIVE_SERVERS_ENABLED = true\n'
             'AUTO_SAVE_RANKED_RESOLVERS = false\n')
        job("masterdnsvpn-client", "-config", "client.toml", "-resolvers", "active.txt")
        if role == "master":
            paths = [[listen, tunnel_port]]
            for address in ask("آدرس کمکی‌های ایران به شکل IP:PORT با کاما، یا -", "-").split(","):
                if address != "-":
                    h, p = address.strip().rsplit(":", 1)
                    if not 1 <= int(p) <= 65535:
                        raise ValueError("پورت نامعتبر")
                    paths.append([str(ipaddress.ip_address(h.strip("[]"))), int(p)])
            peers = ask("مقصدهای همگام‌سازی به شکل ssh-host:/absolute/profile با کاما، یا -", "-")
            if peers != "-":
                job(sys.executable, ROOT / "sync_resolvers.py", "--watch", "resolvers.txt", ".",
                    *[peer.strip() for peer in peers.split(",")])
            mesh = {"listen": ["127.0.0.1", port("پورت SOCKS5 برای outbound شما", 1080)],
                    "paths": paths, "ca": "ca.crt", "cert": "entry.crt", "key": "entry.key"}
            save(out, "mesh.json", q(mesh, indent=2))
            job(sys.executable, ROOT / "mesh.py", "entry", "mesh.json")
    save(out, "services.json", q(jobs, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    dst = args.directory.absolute()
    if dst.exists():
        parser.error("پوشهٔ جدید انتخاب کنید")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir=dst.parent) as stage:
        path = Path(stage) / "profile"
        path.mkdir()
        make_profile(path)
        path.rename(dst)
    print("پروفایل ساخته شد:", dst)
