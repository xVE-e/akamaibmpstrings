#!/usr/bin/env python3
"""
Akamai BMP SDK 4.1.3 — Sensor Data Decryptor
Decrypts the X-acf-sensor-data header using session keys from Frida.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SESSION_KEY = "46516d8ed136d3b2a7030e797eff02b4"
HMAC_KEY = "430bdd53f51392d33ecbeb844ae02098720cc3ccd797f6307ca228a56305fc51"

# Full X-acf-sensor-data header OR just the base64 payload ($[1])
HEADER = "6,a,bjfK3r1r81wjoRQMJT2eFVs4OMUM7lQbaLNf+nHI957+yuFN73FRkmFZfyIkn0XCN0q1cSZoHxflq3Cmby9fDEXmGNIF397AGpWIvtaS81FxumQoGd6irIYLRw5L7clRFWqgFgQsh2zvGG13PEC8jl/FOf2fdAbg5aA8oWahUhM=,LaeB/PmDZO3nOHxxukrd11FID5V1yjvOndOWSRE0HhIiAJe5rm/w7mIyXCSnW4ZGcvthMuY42SIoC7PZdwkJWys8pS0Qj+hlzNQyChuWFwHPID8cNANfob7h9r5Qz31E8VhopvYfBNqRM76P0ztswpz9CezlcOyp3Cs3SVQyKyc=$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$395,407,4121"

B64_PAYLOAD = ""

SEPARATOR = "-1,2,-94,"


def decrypt_payload(session_key: bytes, hmac_key: bytes, payload_b64: str) -> dict:
    raw = base64.b64decode(payload_b64)
    iv = raw[:16]
    ciphertext = raw[16:-32]
    hmac_tag = raw[-32:]
    computed_hmac = hmac_mod.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    hmac_valid = computed_hmac == hmac_tag
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    plaintext_padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    pad_len = plaintext_padded[-1]
    if 1 <= pad_len <= 16 and all(b == pad_len for b in plaintext_padded[-pad_len:]):
        plaintext = plaintext_padded[:-pad_len]
    else:
        plaintext = plaintext_padded
    text = plaintext.decode("utf-8", errors="replace")
    pairs = {}
    parts = text.split(SEPARATOR)
    sdk_version = parts[0] if parts else ""
    for part in parts[1:]:
        comma_idx = part.find(",")
        if comma_idx > 0:
            key = part[:comma_idx]
            value = part[comma_idx + 1 :]
            pairs[key] = value
        elif part.strip():
            pairs[part.strip()] = ""
    return {
        "hmac_valid": hmac_valid,
        "iv": iv.hex(),
        "plaintext_length": len(plaintext),
        "sdk_version": sdk_version,
        "pairs": pairs,
        "raw_plaintext": text,
    }


def parse_header(header: str) -> dict:
    parts = header.split("$")
    p0 = parts[0].split(",") if parts else []

    return {
        "version": p0[0] if len(p0) > 0 else "",
        "platform": p0[1] if len(p0) > 1 else "",
        "rsa_key_1": p0[2] if len(p0) > 2 else "",
        "rsa_key_2": p0[3] if len(p0) > 3 else "",
        "encrypted_payload_b64": parts[1] if len(parts) > 1 else "",
        "timing": parts[2] if len(parts) > 2 else "",
        "pow_response": parts[3] if len(parts) > 3 else "",
        "cca_token": parts[4] if len(parts) > 4 else "",
        "server_signal": parts[5] if len(parts) > 5 else "",
        "metadata": parts[6] if len(parts) > 6 else "",
    }


KEY_NAMES = {
    "-90": "JS Signals", "-91": "CPR Signal", "-70": "Marker 1", "-80": "Marker 2",
    "-121": "Background", "-100": "Device FP", "-101": "Sensor Flags", "-102": "DCI Status",
    "-103": "Lifecycle", "-104": "Device Info", "-108": "Touch/Key", "-112": "Performance",
    "-115": "Sys Counters", "-117": "Touch Stream", "-120": "Platform", "-142": "Orient Data",
    "-143": "Motion Data", "-144": "Orient Summary", "-145": "Motion Summary",
    "-150": "Thread Info", "-160": "BG Counts", "-161": "BG Timing", "-163": "App Identity",
    "-165": "OS/Network", "-166": "Android Dev", "-171": "Server URL", "-240": "Callback",
    "-164": "Sec Patch", "-170": "MT Verify",
}


def main():
    session_key = bytes.fromhex(SESSION_KEY)
    hmac_key = bytes.fromhex(HMAC_KEY)

    if HEADER:
        parsed = parse_header(HEADER)
        payload_b64 = parsed["encrypted_payload_b64"]
    elif B64_PAYLOAD:
        payload_b64 = B64_PAYLOAD
    else:
        print("Set HEADER or B64_PAYLOAD")
        return

    result = decrypt_payload(session_key, hmac_key, payload_b64)

    hmac_str = "\033[92mOK\033[0m" if result["hmac_valid"] else "\033[91mFAIL\033[0m"
    print(f"\n  HMAC: {hmac_str}  |  SDK: {result['sdk_version']}  |  {len(result['pairs'])} pairs  |  {result['plaintext_length']} bytes\n")

    for key, value in result["pairs"].items():
        name = KEY_NAMES.get(key, "???")
        if not value:
            print(f"  \033[90m{key:>5s}  {name:<16s}  (empty)\033[0m")
        else:
            print(f"  {key:>5s}  \033[96m{name:<16s}\033[0m  {value}")

    print(f"\n\033[90m--- Raw plaintext ---\033[0m")
    print(result["raw_plaintext"])
    print()


if __name__ == "__main__":
    main()
