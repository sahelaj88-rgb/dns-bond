#!/bin/sh
set -eu
umask 077
mkdir "${1:?usage: sh certificates.sh NEW_DIRECTORY}"
cd "$1"
openssl req -x509 -newkey rsa:3072 -nodes -days 730 -subj '/CN=DNS Bond local CA' -keyout ca.key -out ca.crt
for role in entry exit; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=dns-bond-$role" -keyout "$role.key" -out "$role.csr"
  case "$role" in
    entry) usage=clientAuth ;;
    exit) usage=serverAuth ;;
  esac
  printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=%s\nsubjectAltName=DNS:dns-bond-%s\n' "$usage" "$role" > "$role.ext"
  openssl x509 -req -in "$role.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -extfile "$role.ext" -out "$role.crt"
done
