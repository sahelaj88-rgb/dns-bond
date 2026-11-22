"""Fresh DNS TXT challenge authenticated with an independent per-pair subkey."""
import hashlib
import hmac
import secrets
import struct

QUESTION = b"\x00\x10\x00\x01"
ANSWER = bytes.fromhex("c00c0010000100000000004140")


def make_probe(domain):
    nonce = secrets.token_hex(12)
    labels = ("health-" + nonce + "." + domain).encode("ascii").split(b".")
    name = b"".join(bytes([len(s)]) + s for s in labels) + b"\0"
    if len(name) > 255:
        raise ValueError("domain too long for DNS health checks")
    return secrets.token_bytes(2) + bytes.fromhex("01000001000000000000") + name + QUESTION


def marker(key, name):
    return hmac.digest(key, b"dns-bond-health-v1\0" + name.lower(), hashlib.sha256).hex().encode("ascii")


def respond(data, domain, key):
    if len(data) < 49 or data[2] & 128 or data[4:6] != b"\0\1" or data[12] != 31:
        return None
    if data[13:20].lower() != b"health-":
        return None
    suffix = b"".join(bytes([len(s)]) + s for s in domain.encode().lower().split(b".")) + b"\0"
    end = 44 + len(suffix)
    if data[44:end].lower() != suffix or data[end:end+4] != QUESTION:
        return None
    return (data[:2] + b"\x85\x00" + bytes.fromhex("0001000100000000") +
            data[12:end+4] + ANSWER + marker(key, data[12:end]))


def verified(data, response, key):
    # Resolvers may change case, TTL or add EDNS records. Validate a complete
    # TXT RDATA field in the answer section, and bind it to this query nonce.
    if (len(response) < 12 or response[:2] != data[:2] or response[3] & 15
            or response[4:6] != b"\0\1" or not response[2] & 128):
        return False
    n = int.from_bytes(response[6:8], "big")
    end = len(data)
    if response[12:end].lower() != data[12:].lower():
        return False
    expected = b"\x40" + marker(key, data[12:-4])
    i = end
    for _ in range(n):
        while i < len(response):
            size = response[i]
            i += 1
            if size == 0:
                break
            if size & 0xc0 == 0xc0:
                i += 1
                break
            if size > 63:
                return False
            i += size
        if i + 10 > len(response):
            return False
        typ, cls, _, length = struct.unpack_from("!HHIH", response, i)
        i += 10
        if i + length > len(response):
            return False
        if typ == 16 and cls == 1 and hmac.compare_digest(response[i:i+length], expected):
            return True
        i += length
    return False
