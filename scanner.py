"""
Quantum-Readiness Scanner
=========================
Checks whether a website protects its connections with post-quantum
cryptography, or whether its traffic could be recorded today and decrypted
later by a large quantum computer running Shor's algorithm
("harvest now, decrypt later").

How it works, in one paragraph:
Every HTTPS connection starts with a TLS "handshake". The browser (client)
sends a ClientHello listing the key-exchange methods ("groups") it supports.
The server replies with a ServerHello saying which one it picked. We send a
ClientHello that offers BOTH a post-quantum hybrid group (X25519MLKEM768) and
a classical one (X25519), then read which one the server chooses. That single
choice tells us whether the site is quantum-ready for key exchange.

We build the ClientHello by hand (raw bytes) instead of using Python's ssl
library, because most installed OpenSSL versions can't speak ML-KEM yet.
We only need the server's FIRST reply, so we never finish the handshake.

Usage:
    python scanner.py google.com cloudflare.com
    python scanner.py --file sites.txt
    python scanner.py --file sites.txt --csv results.csv
"""

import argparse
import csv
import os
import secrets
import socket
import ssl
import struct
import sys

# -----------------------------------------------------------------------------
# 1. The key-exchange "groups" we care about.
#    Every group has an official 2-byte ID registered with IANA.
# -----------------------------------------------------------------------------
X25519MLKEM768 = 0x11EC  # Hybrid: classical X25519 + post-quantum ML-KEM-768
X25519 = 0x001D          # Classical elliptic curve (broken by Shor's algorithm)
SECP256R1 = 0x0017       # Classical elliptic curve P-256 (also broken by Shor)

GROUP_NAMES = {
    X25519MLKEM768: "X25519MLKEM768 (post-quantum hybrid)",
    X25519: "X25519 (classical)",
    SECP256R1: "secp256r1 / P-256 (classical)",
}

# A HelloRetryRequest looks like a ServerHello but uses this fixed "random"
# value (defined in RFC 8446). It means: "I want a different key share."
HELLO_RETRY_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)


# -----------------------------------------------------------------------------
# 2. Building the ClientHello
# -----------------------------------------------------------------------------
def fake_mlkem768_public_key():
    """
    Make a structurally valid ML-KEM-768 public key (1184 bytes).

    We never decrypt anything, so we don't need a REAL key pair, but the
    server checks the key is well-formed: it is 768 numbers, each smaller
    than q = 3329, packed into 12 bits each, followed by a 32-byte seed.
    Random bytes would fail that check, so we generate valid numbers.
    """
    q = 3329
    coeffs = [secrets.randbelow(q) for _ in range(768)]
    packed = bytearray()
    for i in range(0, 768, 2):          # pack two 12-bit numbers into 3 bytes
        a, b = coeffs[i], coeffs[i + 1]
        packed += bytes([a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4])
    return bytes(packed) + os.urandom(32)  # 1152 + 32 = 1184 bytes


def ext(ext_type, data):
    """A TLS extension = 2-byte type + 2-byte length + data."""
    return struct.pack("!HH", ext_type, len(data)) + data


def vec(data, length_bytes):
    """A TLS 'vector' = length prefix (1, 2 or 3 bytes) followed by the data."""
    return len(data).to_bytes(length_bytes, "big") + data


def build_client_hello(hostname):
    # Key shares we offer: post-quantum hybrid first (our preference), then
    # classical X25519. A hybrid share is ML-KEM key (1184) + X25519 key (32).
    hybrid_share = fake_mlkem768_public_key() + os.urandom(32)
    classical_share = os.urandom(32)
    key_shares = (
        struct.pack("!H", X25519MLKEM768) + vec(hybrid_share, 2)
        + struct.pack("!H", X25519) + vec(classical_share, 2)
    )

    groups = [X25519MLKEM768, X25519, SECP256R1]
    sig_algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    host = hostname.encode()

    extensions = b"".join([
        # server_name (SNI): which website on this server we want
        ext(0x0000, vec(b"\x00" + vec(host, 2), 2)),
        # supported_groups: key exchanges we can do
        ext(0x000A, vec(b"".join(struct.pack("!H", g) for g in groups), 2)),
        # signature_algorithms: how the certificate may be signed
        ext(0x000D, vec(b"".join(struct.pack("!H", s) for s in sig_algs), 2)),
        # supported_versions: we only speak TLS 1.3 (0x0304) and 1.2 (0x0303)
        ext(0x002B, vec(b"\x03\x04\x03\x03", 1)),
        # psk_key_exchange_modes (required by some servers for TLS 1.3)
        ext(0x002D, vec(b"\x01", 1)),
        # key_share: our actual public keys
        ext(0x0033, vec(key_shares, 2)),
    ])

    cipher_suites = [0x1301, 0x1302, 0x1303,          # TLS 1.3
                     0xC02B, 0xC02F, 0xC02C, 0xC030]  # TLS 1.2 fallbacks

    body = (
        b"\x03\x03"                                   # legacy version: TLS 1.2
        + os.urandom(32)                              # client random
        + vec(os.urandom(32), 1)                      # legacy session id
        + vec(b"".join(struct.pack("!H", c) for c in cipher_suites), 2)
        + vec(b"\x00", 1)                             # compression: none
        + vec(extensions, 2)
    )
    handshake = b"\x01" + vec(body, 3)               # type 1 = ClientHello
    # Wrap in a TLS record: type 22 (handshake), version, length
    return struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake


# -----------------------------------------------------------------------------
# 3. Reading the ServerHello
# -----------------------------------------------------------------------------
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("server closed the connection")
        data += chunk
    return data


def read_server_hello(sock):
    """Return the body of the server's first handshake message."""
    record_type, _version, length = struct.unpack("!BHH", recv_exact(sock, 5))
    payload = recv_exact(sock, length)
    if record_type == 21:  # 21 = Alert: the server refused our hello
        raise ConnectionError(f"server sent TLS alert {payload[-1]}")
    if record_type != 22 or payload[0] != 2:  # 2 = ServerHello
        raise ConnectionError("unexpected reply (not a ServerHello)")
    return payload[4:]


def parse_server_hello(body):
    """Pull out the TLS version and the key-exchange group the server chose."""
    pos = 2                                   # skip legacy version
    random = body[pos:pos + 32]; pos += 32
    sid_len = body[pos]; pos += 1 + sid_len
    pos += 3                                  # cipher suite (2) + compression (1)

    result = {"tls_version": "TLS 1.2", "group": None,
              "retry": random == HELLO_RETRY_RANDOM}
    if pos >= len(body):
        return result
    ext_total = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
    end = pos + ext_total
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", body[pos:pos + 4]); pos += 4
        data = body[pos:pos + ext_len]; pos += ext_len
        if ext_type == 0x002B and data == b"\x03\x04":
            result["tls_version"] = "TLS 1.3"
        elif ext_type == 0x0033:
            # In both a ServerHello and a HelloRetryRequest, the first two
            # bytes of key_share are the group the server selected.
            result["group"] = struct.unpack("!H", data[:2])[0]
    return result


# -----------------------------------------------------------------------------
# 4. Bonus: what kind of certificate does the site use?
#    Certificates are signed with RSA or ECDSA, which Shor's algorithm also
#    breaks. This is less urgent (a forged signature can't be "harvested"
#    and used years later), and post-quantum certificates aren't widely
#    deployed yet, but it's worth reporting.
# -----------------------------------------------------------------------------
def certificate_type(hostname, port, timeout):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    except ImportError:
        return "unknown (pip install cryptography)"
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    key = x509.load_der_x509_certificate(der).public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA ({key.curve.name})"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(key).__name__


# -----------------------------------------------------------------------------
# 5. Putting it together
# -----------------------------------------------------------------------------
def verdict(info):
    if info["group"] == X25519MLKEM768:
        return "QUANTUM-SAFE"
    if info["tls_version"] == "TLS 1.2":
        return "AT RISK (old TLS 1.2)"
    return "AT RISK"


def scan(hostname, port=443, timeout=6):
    row = {"site": hostname, "verdict": "ERROR", "tls_version": "",
           "key_exchange": "", "certificate": "", "note": ""}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            s.sendall(build_client_hello(hostname))
            info = parse_server_hello(read_server_hello(s))
        row["tls_version"] = info["tls_version"]
        row["key_exchange"] = GROUP_NAMES.get(
            info["group"],
            "classical (TLS 1.2 ECDHE/RSA)" if info["group"] is None
            else f"unknown group 0x{info['group']:04X}")
        row["verdict"] = verdict(info)
        if info["retry"]:
            row["note"] = "server asked for a different key share"
    except Exception as e:  # noqa: BLE001 - report any failure per site
        row["note"] = str(e) or type(e).__name__
        return row
    try:
        row["certificate"] = certificate_type(hostname, port, timeout)
    except Exception as e:  # noqa: BLE001
        row["certificate"] = f"could not read ({type(e).__name__})"
    return row


def clean(site):
    """Accept 'https://www.example.com/path' as well as 'example.com'."""
    site = site.strip()
    site = site.split("://", 1)[-1]
    return site.split("/", 1)[0].split(":", 1)[0]


def main():
    parser = argparse.ArgumentParser(description="Check websites for post-quantum TLS.")
    parser.add_argument("sites", nargs="*", help="websites to scan, e.g. google.com")
    parser.add_argument("--file", help="text file with one website per line")
    parser.add_argument("--csv", help="also save results to this CSV file")
    args = parser.parse_args()

    sites = list(args.sites)
    if args.file:
        with open(args.file) as f:
            sites += [line for line in f if line.strip() and not line.startswith("#")]
    sites = [clean(s) for s in sites]
    if not sites:
        parser.error("give at least one website, or --file sites.txt")

    results = []
    for site in sites:
        row = scan(site)
        results.append(row)
        print(f"{row['site']:<28} {row['verdict']:<24} "
              f"{row['key_exchange'] or row['note']}")

    safe = sum(r["verdict"] == "QUANTUM-SAFE" for r in results)
    print(f"\n{safe} of {len(results)} sites use post-quantum key exchange.")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0]))
            writer.writeheader()
            writer.writerows(results)
        print(f"Saved full results to {args.csv}")


if __name__ == "__main__":
    sys.exit(main())
