import json

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
from math import ceil, log2

I32_BOUND = 2**31

TEST_CRED = {
    "schema_id": "3avoBCqDMFHFaKUHug9s8W:2:fabername:0.1.0",
    "cred_def_id": "3avoBCqDMFHFaKUHug9s8W:3:CL:13:default",
    "rev_reg_id": None,
    "values": {
        "name": {
            "raw": "Alice Jones",
            "encoded": "72896232743708443677449555551687504476536417389324439453514323796296385992918",
        }
    },
    "signature": {
        "p_credential": {
            "m_2": "57832835556928742723946725004638238236382427793876617639158517726445069815397",
            "a": "20335594316731334597758816443885619716281946894071547670112874227353349613733788033617671091848119624077343554670947282810485774124636153228333825818186760397527729892806528284243491342499262911619541896964620427749043381625203893661466943880747122017539322865930800203806065857795584699623987557173946111100450130555197585324032975907705976283592876161733661021481170756352943172201881541765527633833412431874555779986196454199886878078859992928382512010526711165717317294021035408585595567390933051546616905350933492259317172537982279278238456869493798937355032304448696707549688520575565393297998400926856935054785",
            "e": "259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930114221280625468933785621106476195767",
            "v": "6264315754962089362691677910875768714719628097173834826942639456162861264780209679632476338104728648674666095282910717315628966174111516324733617604883927936031834134944562245348356595475949760140820205017843765225176947252534891385340037654527825604373031641665762232119470199172203915071879260274922482308419475927587898260844045340005759709509719230224917577081434498505999519246994431019808643717455525020238858900077950802493426663298211783820016830018445034267920428147219321200498121844471986156393710041532347890155773933440967485292509669092990420513062430659637641764166558511575862600071368439136343180394499313466692464923385392375334511727761876368691568580574716011747008456027092663180661749027223129454567715456876258225945998241007751462618767907499044716919115655029979467845162863204339002632523083819",
        },
        "r_credential": None,
    },
    "signature_correctness_proof": {
        "se": "16380378819766384687299800964395104347426132415600670073499502988403571039552426989440730562439872799389359320216622430122149635890650280073919616970308875713611769602805907315796100888051513191790990723115153015179238215201014858697020476301190889292739142646098613335687696678474499610035829049097552703970387216872374849734708764603376911608392816067509505173513379900549958002287975424637744258982508227210821445545063280589183914569333870632968595659796744088289167771635644102920825749994200219186110532662348311959247565066406030309945998501282244986323336410628720691577720308242032279888024250179409222261839",
        "c": "54687071895183924055442269144489786903186459631877792294627879136747836413523",
    },
    "rev_reg": None,
    "witness": None,
}

SIGNATURE_PARTS = ["m_2", "a", "e", "v", "se", "c"]

# r_credential:
# sigma: PointG1,
# c: GroupOrderElement,
# vr_prime_prime: GroupOrderElement,
# witness_signature: WitnessSignature,
# g_i: PointG1,
# i: u32,
# m2: GroupOrderElement


def base64_pad(val: str) -> str:
    """Pad base64 values if need be: JWT calls to omit trailing padding."""
    padlen = 4 - len(val) % 4
    return val if padlen > 2 else (val + "=" * padlen)


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

    return urlsafe_b64encode(b"".join(entries)).rstrip(b"=").decode("utf-8")


def decode_w3c_signature(signature: str) -> dict:
    sig_bytes = urlsafe_b64decode(base64_pad(signature))

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
    Predicates in indy-sdk operate
    on int32 values properly only when their encoded values match their raw values.
    Args:
        orig: original value to encode
    Returns:
        encoded value
    """

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
    cred_def_id = cred_json["cred_def_id"]
    schema_id = cred_json["schema_id"]
    issuer = "did:sov:" + cred_def_id.split(":")[0]
    signature = encode_w3c_signature(cred_json)
    attrs = {name: entry["raw"] for name, entry in cred_json["values"].items()}

    # issues
    # - need @vocab or an additional @context entry & type
    # - limitations on attrib names, like `id` or `@type`?

    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
        ],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "credentialSchema": cred_def_id,
        "credentialSubject": attrs,
        "proof": {
            "type": "AnonCredsProof2022",
            "encoding": "auto",
            "schema_id": schema_id,
            "signature": signature,
        },
    }


def from_w3c(cred_json: dict) -> dict:
    # FIXME validate context, add error handling

    cred_def_id = cred_json["credentialSchema"]
    schema_id = cred_json["proof"]["schema_id"]
    attrs = cred_json["credentialSubject"]
    signature_parts = decode_w3c_signature(cred_json["proof"]["signature"])

    values = {}
    for name, val in attrs.items():
        values[name] = {"raw": val, "encoded": encode_indy_attrib(val)}

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
    w3c_cred = to_w3c(TEST_CRED)
    print(json.dumps(w3c_cred, indent=2))

    indy_cred = from_w3c(w3c_cred)
    assert indy_cred == TEST_CRED
