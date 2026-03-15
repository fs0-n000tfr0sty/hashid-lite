#!/usr/bin/env python3
"""hashid-lite: guess a hash type from its shape."""
import re
import sys

PATTERNS = [
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM", "MD4"]),
    (r"^[a-f0-9]{40}$", ["SHA-1", "RIPEMD-160"]),
    (r"^[a-f0-9]{56}$", ["SHA-224", "SHA3-224"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256", "BLAKE2s"]),
    (r"^[a-f0-9]{96}$", ["SHA-384", "SHA3-384"]),
    (r"^[a-f0-9]{128}$", ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]),
    (r"^\$2[abxy]?\$\d{2}\$[./a-z0-9]{53}$", ["bcrypt"]),
]


def identify(h):
    h = h.strip().lower()
    for pattern, names in PATTERNS:
        if re.match(pattern, h):
            return names
    return []


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: hashid.py <hash>")
        sys.exit(1)
    found = identify(sys.argv[1])
    print("\n".join(found) if found else "unknown")
