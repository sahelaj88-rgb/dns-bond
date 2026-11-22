#!/bin/sh
set -eu
cd "$(dirname "$0")"
side=${1:-}
case "$side" in
  iran) engine=masterdnsvpn-client ;;
  outside) engine=masterdnsvpn-server ;;
  *) echo 'usage: sudo sh install.sh iran|outside' >&2; exit 2 ;;
esac
test "$(uname -s)" = Linux
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'Unsupported Linux CPU' >&2; exit 2 ;;
esac
test "$(cat ARCH)" = "$arch" || { echo 'CPU does not match this archive' >&2; exit 2; }
sha256sum -c SHA256SUMS >/dev/null
root=${DESTDIR:-}
if [ -z "$root" ]; then
  test "$(id -u)" -eq 0 || { echo 'Use sudo' >&2; exit 1; }
  /usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3,11))' || { echo 'Python 3.11+ required at /usr/bin/python3' >&2; exit 1; }
  command -v openssl >/dev/null
  command -v systemctl >/dev/null
fi
install -d "$root/opt/dns-bond" "$root/usr/local/bin" "$root/etc/systemd/system"
cp -R app/. "$root/opt/dns-bond/"
install -m 755 "bin/$engine" "$root/usr/local/bin/$engine"
install -m 644 app/dns-bond.service "$root/etc/systemd/system/dns-bond.service"
if [ -z "$root" ]; then
  if ! id dnsbond >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/dns-bond --shell /bin/sh dnsbond
  fi
  install -d -o dnsbond -g dnsbond -m 700 /var/lib/dns-bond
  systemctl daemon-reload
fi
echo 'Installed. Next: follow OFFLINE-FA.md to configure this node.'
