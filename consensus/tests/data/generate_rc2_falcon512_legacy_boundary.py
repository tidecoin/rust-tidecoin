#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""Reproduce synthetic Falcon fixtures; validate them against the pinned node.

This constructs test vectors, not keys or signatures for funds. The chosen
public key makes s1 zero for the selected message and constant s2 polynomial.
"""

import hashlib
import json
from pathlib import Path


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash512(data):
    return hashlib.sha512(data).digest()


def packed(fields):
    bits = "".join(fields)
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def vector(message, coefficient=260, logn=9):
    n = 1 << logn
    nonce = bytes(40)
    stream = hashlib.shake_256(nonce + message).digest(4096)
    words = [int.from_bytes(stream[i:i + 2], "big") for i in range(0, len(stream), 2)]
    point = [word % 12289 for word in words if word < 61445][:n]
    assert len(point) == n
    # s2 = a * (1 + x + ... + x^(n-1)). Its inverse is (1-x)/(2a)
    # modulo x^n+1, so h*s2 = H and s1 = H-h*s2 = 0.
    inverse = pow(2 * coefficient, -1, 12289)
    h = [((point[0] + point[-1]) * inverse) % 12289]
    h += [((point[i] - point[i - 1]) * inverse) % 12289 for i in range(1, n)]
    public_key = bytes([logn]) + packed([f"{value:014b}" for value in h])
    encoded_coefficient = "0" + f"{coefficient % 128:07b}" + "0" * (coefficient // 128) + "1"
    signature = bytes([0x30 + logn]) + nonce + packed([encoded_coefficient] * n)
    return {
        "message": message.hex(),
        "public_key": public_key.hex(),
        "signature": signature.hex(),
        "signature_bytes": len(signature),
        "squared_norm": n * coefficient ** 2,
        "coefficient": coefficient,
        "logn": logn,
    }


def main():
    # Same transaction as tidecoin_rc2_rules.rs::tx(), spent amount 1000 sat,
    # OP_CHECKSIG scriptCode, and SIGHASH_ALL. Serialize independently of Rust.
    version = (2).to_bytes(4, "little")
    outpoint = bytes([7]) * 32 + bytes(4)
    sequence = b"\xff" * 4
    output = (1).to_bytes(8, "little") + b"\x01\x51"
    amount = (1000).to_bytes(8, "little")
    end = bytes(4) + (1).to_bytes(4, "little")
    script_code = b"\x01\xac"
    v0 = hash256(version + hash256(outpoint) + hash256(sequence) + outpoint
                 + script_code + amount + sequence + hash256(output) + end)
    locking = b"\x51\x40" + hash512(b"\xac")
    tag = hash512(b"TidecoinSighashV1_512")
    v1 = hash512(tag + tag + version + hash512(outpoint) + hash512(amount)
                 + hash512(bytes([len(locking)]) + locking) + hash512(sequence)
                 + outpoint + script_code + amount + sequence + hash512(output) + end)
    data = {
        "node_revision": "7d653be5d24e73b49d101578afb33d8d7a889c1d",
        "construction": "All s2 coefficients equal a; s1 = 0; h = H(message) / s2 in "
                        "Z_12289[x]/(x^n+1). Each vector records a and log2(n). "
                        "The synthetic public key is supplied in the witness of "
                        "OP_CHECKSIG, so scriptCode does not depend on it.",
        "v0": vector(v0),
        "v1": vector(v1),
        "v0_excess_norm": vector(v0, 292),
        "v1_excess_norm": vector(v1, 292),
        "v0_strict": vector(v0, 1),
        "v1_strict": vector(v1, 1),
        "v0_falcon1024": vector(v0, 1, 10),
        "v1_falcon1024": vector(v1, 1, 10),
    }
    Path(__file__).with_name("rc2_falcon512_legacy_boundary.json").write_text(
        json.dumps(data, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
