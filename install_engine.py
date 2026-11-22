"""Install a checksum-pinned official Linux MasterDnsVPN binary."""
import argparse
import hashlib
import os
import platform
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "v2026.11.18.210322-7198b45"
DIGESTS = {
    ("Client", "AMD64"): "af45909481dad215eb670e2d3119599c39908b38555004b5f9ef47a2acce64d3",
    ("Client", "ARM64"): "60a6a93249c6bef916d498238ecb73f202a614df4b7256401187e7401e01e09c",
    ("Server", "AMD64"): "d0f455ac87afb31010dbc9203d74c3ca24eed52b728873694d10d04b4fd24b06",
    ("Server", "ARM64"): "5f284644af2b2b3a747473a1a9df694fced10592ced0e5847fb77226fbb73895",
}


def install(role, directory):
    machine = {"x86_64": "AMD64", "aarch64": "ARM64"}.get(platform.machine())
    if platform.system() != "Linux" or not machine:
        raise SystemExit("Linux x86_64 or aarch64 required")
    role = role.capitalize()
    prefix = f"MasterDnsVPN_{role}_Linux_{machine}"
    url = f"https://github.com/masterking32/MasterDnsVPN/releases/download/{VERSION}/{prefix}.zip"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        archive = Path(tmp, "release.zip")
        with urllib.request.urlopen(url, timeout=60) as src, archive.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        with archive.open("rb") as src:
            if hashlib.file_digest(src, "sha256").hexdigest() != DIGESTS[role, machine]:
                raise ValueError("release checksum mismatch")
        staged = Path(tmp, "binary")
        with zipfile.ZipFile(archive) as z, z.open(prefix + "_" + VERSION) as src, staged.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        staged.chmod(0o755)
        target = directory / ("masterdnsvpn-" + role.lower())
        os.replace(staged, target)
        print(target)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["client", "server"])
    p.add_argument("--directory", type=Path, default=Path("/usr/local/bin"))
    args = p.parse_args()
    install(args.role, args.directory)
