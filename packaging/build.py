"""Build a self-contained application archive from pinned upstream ZIP files."""
import argparse
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from install_engine import DIGESTS, VERSION


def digest(file):
    with file.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def build(arch, upstream, out):
    name = f"dns-bond-offline-linux-{arch.lower()}"
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / name
        app = pkg / "app"
        binaries = pkg / "bin"
        binaries.mkdir(parents=True)
        app.mkdir()
        files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for rel in filter(None, files):
            if rel.startswith((".github/", "packaging/")) or rel == ".gitignore":
                continue
            dest = app / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, dest)
        for role in ("Client", "Server"):
            prefix = f"MasterDnsVPN_{role}_Linux_{arch}"
            archive = upstream / (prefix + ".zip")
            if digest(archive) != DIGESTS[role, arch]:
                raise ValueError(f"Invalid checksum: {archive.name}")
            with zipfile.ZipFile(archive) as z:
                exe = binaries / ("masterdnsvpn-" + role.lower())
                exe.write_bytes(z.read(prefix + "_" + VERSION))
                exe.chmod(0o755)
        for file in ("install.sh", "OFFLINE-FA.md", "MasterDnsVPN-LICENSE"):
            shutil.copyfile(ROOT / "packaging" / file, pkg / file)
        (pkg / "ARCH").write_text(arch.lower()+"\n")
        (pkg / "SHA256SUMS").write_text("".join(
            f"{digest(p)}  {p.relative_to(pkg)}\n" for p in sorted(pkg.rglob("*")) if p.is_file()))
        out.mkdir(parents=True, exist_ok=True)
        output = out / (name + ".tar.gz")
        with tarfile.open(output, "w:gz") as tar:
            tar.add(pkg, arcname=name)
        print(digest(output), output)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("arch", choices=["AMD64", "ARM64"])
    p.add_argument("upstream", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    build(args.arch, args.upstream, args.output)
