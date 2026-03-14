#!/usr/bin/env python3
"""hashid-lite: guess a hash type from its shape."""
import re
import sys

PATTERNS = [
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM", "MD4"]),
    (r"^[a-f0-9]{40}$", ["SHA-1", "RIPEMD-160"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256"]),
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
