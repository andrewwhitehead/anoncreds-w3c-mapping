"""Convert an AnonCreds presentation into (draft) W3C Presentation format."""

import json
import sys

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from hashlib import sha256
from math import ceil
from typing import Tuple


CONTEXTS = [
    "https://www.w3.org/2018/credentials/v1",
    (
        "https://raw.githubusercontent.com/andrewwhitehead/"
        "anoncreds-w3c-mapping/main/schema.json"
    ),
]

EQ_PROOF_PARTS = ["a_prime", "e", "v", "m", "m2"]
GE_PROOF_PARTS = ["u", "r", "mj", "alpha", "t"]
GE_NUMBER_PARTS = ["0", "1", "2", "3", "DELTA"]


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


def encode_credentials(req_json: dict, pres_json: dict, proofs: list) -> list:
    """Re-encode the credentials contained in the presentation."""
    if (
        "proof" not in pres_json
        or "proofs" not in pres_json["proof"]
        or "requested_proof" not in pres_json
    ):
        raise Exception("invalid presentation")

    creds = []
    req_proof = pres_json["requested_proof"]
    req_attr_map = {}
    req_pred_map = req_json.get("requested_predicates", {})

    for reft, attr in req_json.get("requested_attributes", {}).items():
        if not isinstance(attr, dict):
            raise Exception("Invalid proof request")
        if "name" in attr and isinstance(attr["name"], str):
            req_attr_map[reft] = attr["name"]
        elif "names" in attr and isinstance(attr["names"], list):
            req_attr_map[reft] = attr["names"]
        else:
            raise Exception("Invalid proof request")

    def _check_index(idx):
        if not isinstance(idx, int):
            raise Exception("Expected integer sub_proof_index")
        if idx < 0 or idx >= len(creds):
            raise Exception("Invalid sub_proof_index")
        return idx

    for idx in range(len(proofs)):
        idents = pres_json["identifiers"][idx]
        issuer = "did:sov:" + idents["cred_def_id"].split(":")[0]
        cred = {
            "@context": CONTEXTS.copy(),
            "type": ["VerifiableCredential", "AnonCredsPresentation"],
            "issuer": issuer,
            "issuanceDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSchema": {
                "type": "AnonCredsDefinition",
                "schema": encode_identifier(idents["schema_id"]),
                "definition": encode_identifier(idents["cred_def_id"]),
            },
            "credentialSubject": {"attribute": {}},
            "proof": {
                "type": "AnonCredsPresentationProof2022",
                "credential": {
                    "encoding": "auto",
                    "index": idx,
                    "mapping": {},
                },
            },
        }
        cred["proof"]["credential"].update(proofs[idx])
        creds.append(cred)

    for reft, attr in req_proof.get("revealed_attrs", {}).items():
        idx = _check_index(attr["sub_proof_index"])
        if reft not in req_attr_map:
            raise Exception(f"Unknown attribute referent: {reft}")
        if not isinstance(req_attr_map[reft], str):
            raise Exception(f"Expected single name for attribute referent: {reft}")
        creds[idx]["credentialSubject"]["attribute"][req_attr_map[reft]] = {
            "value": attr["raw"]
        }
        creds[idx]["proof"]["credential"]["mapping"].setdefault(
            "revealedAttributes", {}
        )[reft] = req_attr_map[reft]

    for reft, group in req_proof.get("revealed_attr_groups", {}).items():
        idx = _check_index(group["sub_proof_index"])
        if reft not in req_attr_map:
            raise Exception(f"Unknown attribute group referent: {reft}")
        if not isinstance(req_attr_map[reft], list):
            raise Exception(f"Expected array of names for attribute referent: {reft}")
        req_names = set(req_attr_map[reft])
        mapping = []
        for name, attr in group["values"].items():
            if name not in req_names:
                raise Exception(f"Unexpected attribute name: {name}")
            creds[idx]["credentialSubject"]["attribute"][name] = {"value": attr["raw"]}
            mapping.append(name)
        creds[idx]["proof"]["credential"]["mapping"].setdefault(
            "revealedAttributes", {}
        )[reft] = mapping

    for reft, group in req_proof.get("unrevealed_attrs", {}).items():
        idx = _check_index(group["sub_proof_index"])
        if reft not in req_attr_map:
            raise Exception(f"Unknown attribute referent: {reft}")
        if not isinstance(req_attr_map[reft], str):
            raise Exception(f"Expected single name for attribute referent: {reft}")
        creds[idx]["proof"]["credential"]["mapping"].setdefault(
            "unrevealedAttributes", {}
        )[reft] = req_attr_map[reft]

    pred_idx = 0
    for reft, group in req_proof.get("predicates", {}).items():
        idx = _check_index(group["sub_proof_index"])
        if reft not in req_pred_map:
            raise Exception(f"Unknown predicate referent: {reft}")
        req_pred = req_pred_map[reft]
        creds[idx]["proof"]["credential"]["mapping"].setdefault(
            "requestedPredicates", {}
        )[reft] = {
            "index": pred_idx,
            "attr_name": req_pred["name"],
            "p_type": req_pred["p_type"],
            "value": req_pred["p_value"],
        }

    self_attest = req_proof.get("self_attested_attrs")
    if self_attest:
        creds[idx]["proof"]["credential"]["selfAttestedAttributes"] = self_attest

    return creds


def base64_encode(val: bytes) -> str:
    return urlsafe_b64encode(val).rstrip(b"=").decode("utf-8")


def base64_decode(val: str) -> bytes:
    padlen = 4 - len(val) % 4
    return urlsafe_b64decode(val if padlen > 2 else (val + "=" * padlen))


def encode_bytes(val: bytes) -> bytes:
    return len(val).to_bytes(2, "big") + val


def decode_bytes(val: bytes) -> Tuple[bytes, bytes]:
    lv = len(val)
    if lv < 2:
        raise Exception("Expected field length")
    int_len = int.from_bytes(val[:2], "big")
    end = 2 + int_len
    if lv < end:
        print(lv, end)
        raise Exception("Invalid encoded integer value")
    return val[2:end], val[end:]


def encode_int(val: int) -> bytes:
    if isinstance(val, str):
        val = int(val)
    assert val >= 0
    int_len = ceil(val.bit_length() / 8)
    int_bytes = val.to_bytes(int_len, "big")
    return int_len.to_bytes(2, "big") + int_bytes


def decode_int(val: bytes) -> Tuple[int, bytes]:
    (ibytes, remain) = decode_bytes(val)
    return int.from_bytes(ibytes, "big"), remain


def encode_identifier(ident: str) -> str:
    return ident.replace(" ", "%20")


def decode_identifier(ident: str) -> str:
    return ident.replace("%20", " ")


def encode_eq_proof(eq_proof: dict) -> str:
    """Combine the credential signature (p_credential) and correctness proof."""

    entries = []
    for idx, key in enumerate(EQ_PROOF_PARTS):
        if key not in eq_proof:
            continue
        if key == "m":
            blinded = []
            for attr, value in eq_proof["m"].items():
                attr = attr.encode("utf-8")
                blinded.append(encode_bytes(attr) + encode_int(value))
            enc = encode_bytes(b"".join(blinded))
        else:
            enc = encode_int(eq_proof[key])
        entries.append(bytes((idx,)) + enc)

    return base64_encode(b"".join(entries))


def decode_eq_proof(eq_proof: str, subject: dict) -> dict:
    entries = {
        "revealed_attrs": {
            attr: encode_indy_attrib(val["value"])
            for (attr, val) in subject.get("credentialSubject", {})
            .get("attribute")
            .items()
        }
    }

    eq_proof = base64_decode(eq_proof)
    while eq_proof:
        pfx = eq_proof[0]
        if pfx > len(EQ_PROOF_PARTS):
            raise Exception("Invalid eq_proof")
        prop = EQ_PROOF_PARTS[pfx]
        if prop == "m":
            (blinded, eq_proof) = decode_bytes(eq_proof[1:])
            msgs = {}
            while blinded:
                (attr, blinded) = decode_bytes(blinded)
                (val, blinded) = decode_int(blinded)
                msgs[attr.decode("utf-8")] = str(val)
            entries[prop] = msgs
        else:
            (val, eq_proof) = decode_int(eq_proof[1:])
            entries[prop] = str(val)

    return entries


def encode_ge_proof(ge_proof: dict) -> str:
    entries = []
    for idx, prop in enumerate(GE_PROOF_PARTS):
        if prop not in ge_proof:
            continue
        if prop in ("u", "r", "t"):
            nums = [
                encode_int(ge_proof[prop][a])
                for a in GE_NUMBER_PARTS
                if a in ge_proof[prop]
            ]
            nums = b"".join(nums)
            enc = encode_bytes(nums)
        else:
            enc = encode_int(ge_proof[prop])
        entries.append(bytes((idx,)) + enc)

    return base64_encode(b"".join(entries))


def decode_ge_proof(ge_proof: str) -> dict:
    entries = {}
    ge_proof = base64_decode(ge_proof)
    while ge_proof:
        pfx = ge_proof[0]
        if pfx > len(GE_PROOF_PARTS):
            raise Exception("Invalid ge_proofs")
        prop = GE_PROOF_PARTS[pfx]
        if prop in ("u", "r", "t"):
            parts = {}
            part = iter(GE_NUMBER_PARTS)
            (nums, ge_proof) = decode_bytes(ge_proof[1:])
            while nums:
                (val, nums) = decode_int(nums)
                parts[next(part)] = str(val)
            entries[prop] = parts
        else:
            (val, ge_proof) = decode_int(ge_proof[1:])
            entries[prop] = str(val)

    return entries


def encode_credential_proofs(pres_json: dict) -> str:
    proofs = []
    for pres_proof in pres_json["proof"]["proofs"]:
        proof = {}

        pres_primary = pres_proof["primary_proof"]
        proof["eqProof"] = encode_eq_proof(pres_primary["eq_proof"])
        ge_proofs = pres_primary.get("ge_proofs")
        if ge_proofs:
            proof["geProof"] = list(map(encode_ge_proof, ge_proofs))

        proofs.append(proof)

    return proofs


def encode_aggregated_proof(pres_json: dict) -> str:
    pres_proof = pres_json["proof"]["aggregated_proof"]
    c_hash = encode_int(pres_proof["c_hash"])
    c_list = b"".join(encode_bytes(bytes(b)) for b in pres_proof["c_list"])
    return base64_encode(bytes((0,)) + c_hash + bytes((1,)) + encode_bytes(c_list))


def decode_aggregated_proof(pres_json: dict) -> str:
    c_hash = None
    c_list = None

    pres_proof = base64_decode(pres_json["proof"]["aggregated"])
    while pres_proof:
        pfx = pres_proof[0]
        if pfx == 0:
            c_hash, pres_proof = decode_int(pres_proof[1:])
        elif pfx == 1:
            (ints, pres_proof) = decode_bytes(pres_proof[1:])
            c_list = []
            while ints:
                (c_int, ints) = decode_bytes(ints)
                c_list.append(list(c_int))

    return {"c_hash": str(c_hash), "c_list": c_list}


def map_predicate_operator(op: str) -> str:
    if op == "<=":
        return "LE"
    elif op == ">=":
        return "GE"
    return op


def decode_credential_proof(pres_json: dict) -> dict:
    subjects = {}
    cred_list = pres_json["verifiableCredential"]
    if isinstance(cred_list, dict):
        cred_list = [cred_list]
    for entry in cred_list:
        subjects[entry["proof"]["credential"]["index"]] = entry
    cred_count = max(subjects.keys()) + 1

    proofs = []
    identifiers = []
    requested = {
        "revealed_attrs": {},
        "revealed_attr_groups": {},
        "self_attested_attrs": {},
        "unrevealed_attrs": {},
        "predicates": {},
    }

    for idx in range(cred_count):
        subj = subjects[idx]
        pres_proof = subj["proof"]["credential"]
        mapping = pres_proof["mapping"]
        eq = decode_eq_proof(pres_proof["eqProof"], subj)
        proof = {"primary_proof": {"eq_proof": eq, "ge_proofs": []}}

        ge_proofs = pres_proof.get("geProof")
        if ge_proofs:
            predicates = {}
            for reft, pred in mapping["requestedPredicates"].items():
                predicates[pred["index"]] = pred
            for idx, ge_proof in enumerate(ge_proofs):
                ge_proof = decode_ge_proof(ge_proof)
                pred = predicates[idx]
                ge_proof["predicate"] = {
                    "attr_name": pred["attr_name"],
                    "p_type": map_predicate_operator(pred["p_type"]),
                    "value": pred["value"],
                }
                proof["primary_proof"]["ge_proofs"].append(ge_proof)

        proofs.append(proof)

        identifiers.append(
            {
                "schema_id": decode_identifier(subj["credentialSchema"]["schema"]),
                "cred_def_id": decode_identifier(
                    subj["credentialSchema"]["definition"]
                ),
            }
        )

        for reft, attr_names in mapping.get("revealedAttributes", {}).items():
            if isinstance(attr_names, list):
                values = {}
                for attr in attr_names:
                    values[attr] = {
                        "raw": subj["credentialSubject"]["attribute"][attr]["value"],
                        "encoded": encode_indy_attrib(
                            subj["credentialSubject"]["attribute"][attr]["value"]
                        ),
                    }
                requested["revealed_attr_groups"][reft] = {
                    "sub_proof_index": idx,
                    "values": values,
                }
            elif isinstance(attr_names, str):
                requested["revealed_attrs"][reft] = {
                    "sub_proof_index": idx,
                    "raw": subj["credentialSubject"]["attribute"][attr_names]["value"],
                    "encoded": encode_indy_attrib(
                        subj["credentialSubject"]["attribute"][attr_names]["value"]
                    ),
                }
            else:
                raise Exception("Invalid mapping")

        for reft, attr_names in mapping.get("unrevealedAttributes", {}).items():
            requested["unrevealed_attrs"][reft] = {"sub_proof_index": idx}

        for reft, attr_names in mapping.get("requestedPredicates", {}).items():
            requested["predicates"][reft] = {"sub_proof_index": idx}

        self_attest = mapping.get("selfAttestedAttributes", {})
        if self_attest:
            requested["self_attested_attrs"][reft] = self_attest

    if not requested["revealed_attr_groups"]:
        # not always defined in current standard output
        del requested["revealed_attr_groups"]

    return {
        "proof": {
            "proofs": proofs,
            "aggregated_proof": decode_aggregated_proof(pres_json),
        },
        "requested_proof": requested,
        "identifiers": identifiers,
    }


def to_w3c(req_json: dict, pres_json: dict) -> dict:
    """Convert a classic AnonCreds presentation to W3C-compatible format."""
    proofs = encode_credential_proofs(pres_json)
    creds = encode_credentials(req_json, pres_json, proofs)
    agg = encode_aggregated_proof(pres_json)

    return {
        "@context": CONTEXTS.copy(),
        "type": ["VerifiablePresentation", "AnonCredsPresentation"],
        # "holder": { .. },
        "verifiableCredential": creds,
        "proof": {
            "type": "AnonCredsPresentationProof2022",
            "nonce": req_json["nonce"],
            "aggregated": agg,
        },
    }


def from_w3c(pres_json: dict) -> dict:
    """Convert a W3C-compatible presentation to AnonCreds classic format."""
    return decode_credential_proof(pres_json)


if __name__ == "__main__":
    if len(sys.argv) < 1:
        raise SystemExit(
            "Expected input filename, for example: presentations/ComplexProof.json"
        )
    input = json.load(open(sys.argv[1], "r"))

    if (
        not isinstance(input, dict)
        or "presentation" not in input
        or "presentation_request" not in input
    ):
        raise SystemExit(
            "Expected a JSON object with 'presentation' and 'presentation_request' keys"
        )

    w3c_pres = to_w3c(input["presentation_request"], input["presentation"])
    print(json.dumps(w3c_pres, indent=2))

    cmp_pres = from_w3c(w3c_pres)
    if cmp_pres != input["presentation"]:
        raise SystemExit("Presentation did not round-trip successfully")
