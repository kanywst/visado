#!/usr/bin/env python3
"""asor-03 interop between attenu-guard and visado.

  attenu_guard_interop.py mint
      Mints Delegation Chains with attenu-guard and prints them as input for
      `visado-interop asor-verify`, each case with attenu-guard's own verdict.

  attenu_guard_interop.py compare MINTED.json VISADO_RESULTS.json
      Joins attenu-guard's verdicts with visado's.

  attenu_guard_interop.py verify VISADO_MINTED.json
      Verifies chains minted by visado with attenu-guard's `wire.load`.

attenu-guard's built-in Ed25519 signer writes `"alg": "EdDSA"`, which the -03
does not allow (Section 3; its Section 11 says so). The chains here are signed
through a wrapper that writes the fully-specified `"Ed25519"` (RFC 9864) and
signs with the same key; case A.9 keeps the built-in signer.
"""

import base64
import hashlib
import json
import sys

from attenu_guard import Authority, Guard, draft02, wire
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NOW = 1_800_000_000
AUDIENCE = "https://tools.example.com"
ISSUER = "https://td.attenu-guard.example"
URI = "https://tools.example.com/mcp"
PRINCIPAL = "user:alice"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FullySpecified:
    """An attenu-guard Signer with the RFC 9864 name for Ed25519."""

    alg = "Ed25519"

    def __init__(self, inner):
        self.inner = inner
        self.kid = inner.kid

    def sign(self, signing_input: bytes) -> bytes:
        return self.inner.sign(signing_input)

    def verify(self, signing_input: bytes, sig: bytes, key_id=None) -> bool:
        return self.inner.verify(signing_input, sig, key_id)


def seed_key(n: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def jwk(key: Ed25519PrivateKey) -> dict:
    return {"crv": "Ed25519", "kty": "OKP", "x": b64u(raw_public(key))}


def jkt(key: Ed25519PrivateKey) -> str:
    """RFC 7638 thumbprint."""
    j = jwk(key)
    canon = json.dumps({"crv": j["crv"], "kty": j["kty"], "x": j["x"]}, separators=(",", ":"))
    return b64u(hashlib.sha256(canon.encode()).digest())


def compact(header: dict, claims: dict, key: Ed25519PrivateKey) -> str:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64u(key.sign(f'{h}.{p}'.encode()))}"


def dpop(holder: Ed25519PrivateKey, leaf: str, jti: str) -> str:
    """An RFC 9449 proof by `holder` for POST on URI, presenting `leaf`."""
    ath = b64u(hashlib.sha256(leaf.encode()).digest())
    return compact({"typ": "dpop+jwt", "alg": "Ed25519", "jwk": jwk(holder)},
                   {"jti": jti, "htm": "POST", "htu": URI, "iat": NOW, "ath": ath}, holder)


ANCHOR = seed_key(0x41)
HOLDERS = {"orchestrator": seed_key(0x42), "reader": seed_key(0x43), "summarizer": seed_key(0x44)}


def authority(scopes, rows, ttl):
    return Authority(scopes=frozenset(scopes), ceilings=(draft02.Max("rows", rows),), ttl=ttl,
                     profile=draft02.PROFILE_02)


def chain(depth: int, *, signer, aud=AUDIENCE, max_depth=4):
    """Root (orchestrator, crm.*, rows<=1000), then reader (crm.read, rows<=100),
    then summarizer (crm.read, rows<=10), cut at `depth` hops below the root."""
    g = Guard.issue("orchestrator", authority({"crm.*"}, 1000, 600), max_depth=max_depth)
    if depth >= 1:
        g = g.delegate("reader", authority({"crm.read"}, 100, 300), "read")
    if depth >= 2:
        g = g.delegate("summarizer", authority({"crm.read"}, 10, 120), "summarize")
    return wire.serialize_chain(g, signer, iss=ISSUER, principal=PRINCIPAL, aud=aud, iat=NOW,
                                draft=draft02.PROFILE_02,
                                cnf=lambda node: {"jkt": jkt(HOLDERS[node.agent_id])})


def guard_verdict(tokens, signer, now, request=None):
    """attenu-guard's verdict: `wire.load` (steps 1 to 5 and the audience), then,
    with a request, `VerifiedChain.permits` (step 8). It does not check DPoP."""
    try:
        verified = wire.load(tokens, signer, now=now, draft=draft02.PROFILE_02, audience=AUDIENCE)
    except wire.WireError as e:
        return {"verdict": "reject", "reason": e.reason}
    if request:
        decision = verified.permits(request["scope"], request["params"])
        if not decision.allowed:
            reasons = getattr(decision, "reasons", None) or [getattr(decision, "reason", None)]
            code = getattr(reasons[0], "code", None) if reasons and reasons[0] is not None else None
            return {"verdict": "reject", "reason": code or str(decision)}
    return {"verdict": "accept"}


def mint() -> dict:
    builtin = wire.Ed25519Signer.from_private_bytes(bytes([0x41]) * 32, kid="ag-1")
    signer = FullySpecified(builtin)
    two, three = chain(1, signer=signer), chain(2, signer=signer)
    forged = two[:-1] + [two[1][:-4] + ("AAAA" if not two[1].endswith("AAAA") else "BBBB")]
    other_aud = chain(1, signer=signer, aud="https://elsewhere.example.com")
    eddsa = chain(1, signer=builtin)

    def request(tokens, rows, jti):
        return {"dpop": dpop(HOLDERS["reader"], tokens[-1], jti), "method": "POST", "uri": URI,
                "scope": "crm.read", "params": {"rows": rows}}

    cases = [
        ("A.1", "two hops, no request", two, NOW, None, signer),
        ("A.2", "three hops, no request", three, NOW, None, signer),
        ("A.3", "two hops, DPoP-bound request within the ceiling", two, NOW, request(two, 50, "d3"), signer),
        ("A.4", "two hops, request over the child's ceiling", two, NOW, request(two, 500, "d4"), signer),
        ("A.5", "two hops, scope the leaf does not hold", two, NOW,
         dict(request(two, 5, "d5"), scope="crm.write"), signer),
        ("A.6", "child signature altered", forged, NOW, None, signer),
        ("A.7", "checked after the child's exp", two, NOW + 301, None, signer),
        ("A.8", "leaf audience names another enforcement point", other_aud, NOW, None, signer),
        ("A.9", "signed by attenu-guard's built-in signer (alg EdDSA)", eddsa, NOW, None, builtin),
    ]
    out = []
    for cid, note, tokens, at, req, verify_with in cases:
        case = {"id": cid, "note": note, "tokens": tokens, "now": at,
                "attenu_guard": guard_verdict(tokens, verify_with, at, req)}
        if req:
            case["request"] = req
        if verify_with is builtin:
            case["known_divergence"] = ("attenu-guard signs Ed25519 as \"EdDSA\"; Section 3 of the -03 "
                                        "requires the fully-specified \"Ed25519\" (RFC 9864). The "
                                        "draft's Section 11 records this.")
        out.append(case)
    return {"minted_by": "attenu-guard " + package_version(),
            "anchor": {"iss": ISSUER, "kid": "ag-1", "x": b64u(raw_public(ANCHOR))},
            "audience": AUDIENCE, "cases": out}


def package_version() -> str:
    from importlib.metadata import version
    return version("attenu-guard")


def compare(minted: dict, visado: dict) -> dict:
    by_id = {r["id"]: r for r in visado["results"]}
    rows, differ, unexpected = [], 0, 0
    for case in minted["cases"]:
        v = {k: by_id[case["id"]][k] for k in ("verdict", "reason") if k in by_id[case["id"]]}
        same = v["verdict"] == case["attenu_guard"]["verdict"]
        known = case.get("known_divergence")
        differ += not same
        unexpected += not same and not known
        row = {"id": case["id"], "note": case["note"], "attenu_guard": case["attenu_guard"],
               "visado": v, "agree": same}
        if known:
            row["known_divergence"] = known
        rows.append(row)
    return {"minted_by": minted["minted_by"], "verified_by": "visado-chain-asor",
            "cases": len(rows), "differ": differ, "unexpected": unexpected, "results": rows}


def verify(minted: dict) -> dict:
    anchor = minted["anchor"]
    verifier = FullySpecified(wire.Ed25519Verifier(b64u_dec(anchor["x"]), kid="ed25519-1"))
    rows, differ = [], 0
    for case in minted["cases"]:
        got = guard_verdict(case["tokens"], verifier, case["now"])
        same = got["verdict"] == case["visado"]["verdict"]
        differ += not same
        rows.append({"id": case["id"], "note": case["note"], "visado": case["visado"],
                     "attenu_guard": got, "agree": same})
    return {"minted_by": minted["minted_by"], "verified_by": "attenu-guard " + package_version(),
            "cases": len(rows), "differ": differ, "unexpected": differ, "results": rows}


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "mint":
        result = mint()
    elif cmd == "compare":
        result = compare(json.load(open(sys.argv[2])), json.load(open(sys.argv[3])))
    elif cmd == "verify":
        result = verify(json.load(open(sys.argv[2])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result.get("unexpected") else 0


if __name__ == "__main__":
    sys.exit(main())
