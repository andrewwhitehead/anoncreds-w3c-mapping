"""Convert an AnonCreds credential into (draft) W3C format."""

import json
import sys

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from hashlib import sha256
from math import ceil, log2

CONTEXTS = [
    "https://www.w3.org/2018/credentials/v1",
    "https://andrewwhitehead.github.io/anoncreds-w3c-mapping/schema.json",
    {"@vocab": "urn:anoncreds:attributes#"},
]

SIGNATURE_PARTS = ["m_2", "a", "e", "v", "se", "c"]


def base64_encode(val: bytes) -> str:
    return urlsafe_b64encode(val).rstrip(b"=").decode("utf-8")


def base64_decode(val: str) -> bytes:
    padlen = 4 - len(val) % 4
    return urlsafe_b64decode(val if padlen > 2 else (val + "=" * padlen))


def encode_identifier(ident: str) -> str:
    return ident.replace(" ", "%20")


def decode_identifier(ident: str) -> str:
    return ident.replace("%20", " ")


def encode_w3c_signature(cred_json: dict) -> str:
    """Combine the credential signature (p_credential) and correctness proof."""
    parts: dict = cred_json["signature"]["p_credential"].copy()
    parts.update(cred_json["signature_correctness_proof"])

    entries = []
    for idx, key in enumerate(SIGNATURE_PARTS):
        if key not in parts:
            continue
        raw = int(parts[key])
        raw_len = ceil(log2(raw) / 8)
        raw_bytes = raw.to_bytes(raw_len, "big")
        entries.append(bytes((idx,)) + raw_len.to_bytes(2, "big") + raw_bytes)

    return base64_encode(b"".join(entries))


def decode_w3c_signature(signature: str) -> dict:
    sig_bytes = base64_decode(signature)

    ret = {"p_credential": {}, "signature_correctness_proof": {}}
    while sig_bytes:
        if len(sig_bytes) < 3:
            raise Exception("invalid signature")
        idx = int(sig_bytes[0])
        if idx >= len(SIGNATURE_PARTS):
            raise Exception("invalid signature")
        raw_len = int.from_bytes(sig_bytes[1:3], "big")
        sig_bytes = sig_bytes[3:]
        if len(sig_bytes) < raw_len:
            raise Exception("invalid signature")
        raw = str(int.from_bytes(sig_bytes[:raw_len], "big"))
        sig_bytes = sig_bytes[raw_len:]

        key = SIGNATURE_PARTS[idx]
        if key in ("se", "c"):
            ret["signature_correctness_proof"][key] = raw
        else:
            ret["p_credential"][key] = raw

    return ret


def encode_indy_attrib(orig) -> str:
    """
    Encode a credential value as an int.

    Encode credential attribute value, purely stringifying any int32
    and leaving numeric int32 strings alone, but mapping any other
    input to a stringified 256-bit (but not 32-bit) integer.
    Predicates in indy-sdk operate on int32 values properly only when
    their encoded values match their raw values.

    Args:
        orig: original value to encode
    Returns:
        encoded value
    """
    I32_BOUND = 2**31

    if isinstance(orig, int) and -I32_BOUND <= orig < I32_BOUND:
        return str(int(orig))  # python bools are ints

    try:
        i32orig = int(str(orig))  # don't encode floats as ints
        if -I32_BOUND <= i32orig < I32_BOUND:
            return str(i32orig)
    except (ValueError, TypeError):
        pass

    rv = int.from_bytes(sha256(str(orig).encode()).digest(), "big")

    return str(rv)


def to_w3c(cred_json: dict) -> dict:
    """Convert a classic AnonCreds credential to W3C-compatible format."""
    cred_def_id = cred_json["cred_def_id"]
    schema_id = cred_json["schema_id"]
    issuer = "did:sov:" + cred_def_id.split(":")[0]
    signature = encode_w3c_signature(cred_json)
    attrs = {name: entry["raw"] for name, entry in cred_json["values"].items()}

    # - limitations on attrib names, like `id` or `@type`?

    return {
        "@context": CONTEXTS.copy(),
        "type": ["VerifiableCredential", "AnonCredsCredential"],
        "issuer": issuer,
        "issuanceDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSchema": {
            "type": "AnonCredsDefinition",
            "schema": schema_id,
            "definition": cred_def_id,
        },
        "credentialSubject": attrs,
        "proof": {
            "type": "CLSignature2022",
            "encoding": "auto",
            "signature": signature,
        },
    }


def from_w3c(cred_json: dict) -> dict:
    """Convert a W3C-compatible credential to AnonCreds classic format."""
    # FIXME validate context, add error handling

    schema_id = cred_json["credentialSchema"]["schema"]
    cred_def_id = cred_json["credentialSchema"]["definition"]
    attrs = cred_json["credentialSubject"]
    signature_parts = decode_w3c_signature(cred_json["proof"]["signature"])

    values = {}
    for attr_name, attr_value in attrs.items():
        values[attr_name] = {
            "raw": attr_value,
            "encoded": encode_indy_attrib(attr_value),
        }

    return {
        "schema_id": schema_id,
        "cred_def_id": cred_def_id,
        "rev_reg_id": None,
        "values": values,
        "signature": {
            "p_credential": signature_parts["p_credential"],
            "r_credential": None,
        },
        "signature_correctness_proof": signature_parts["signature_correctness_proof"],
        "rev_reg": None,
        "witness": None,
    }


if __name__ == "__main__":
    if len(sys.argv) < 1:
        raise SystemExit(
            "Expected input filename, for example: credentials/Credential_1.json"
        )
    input = json.load(open(sys.argv[1], "r"))

    if not isinstance(input, dict):
        raise SystemExit("Expected a JSON object")

    w3c_cred = to_w3c(input)
    print(json.dumps(w3c_cred, indent=2))

    cmp_pres = from_w3c(w3c_cred)
    if cmp_pres != input:
        raise SystemExit("Credential did not round-trip successfully")
