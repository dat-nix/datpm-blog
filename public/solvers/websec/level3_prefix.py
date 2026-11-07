#!/usr/bin/env python3
"""Find a short input whose SHA-1 begins with the leaked 0x7c00 prefix."""

import hashlib
import itertools
import string


def main() -> None:
    alphabet = string.ascii_letters + string.digits
    for length in range(1, 8):
        for chars in itertools.product(alphabet, repeat=length):
            candidate = "".join(chars)
            if hashlib.sha1(candidate.encode()).hexdigest().startswith("7c00"):
                print(candidate)
                return
    raise SystemExit("no candidate found")


if __name__ == "__main__":
    main()
