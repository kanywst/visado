"""Join a minted case set with verifier outputs into one results file.

Usage: python3 -I summarize.py MINTED NAME=VERDICTS [NAME=VERDICTS ...]

Prints JSON: per case the expectation from the minting side and each
verifier's verdict, whether an accepted token's tctx/rctx came through
unchanged, and per verifier a count of verdicts that match the expectation.
Tokens are left out (most are minted at the wall clock); loopback URLs and
local paths are scrubbed from error strings.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys

LOOPBACK = re.compile(r"http://127\.0\.0\.1:\d+")


def scrub(text: str) -> str:
    text = LOOPBACK.sub("<jwks-url>", text)
    for var in ("HOME", "TMPDIR"):
        value = os.environ.get(var)
        if value:
            text = text.replace(value.rstrip("/"), f"<{var}>")
    return text


def part(token: str, index: int) -> dict:
    try:
        raw = token.split(".")[index]
        return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (IndexError, ValueError):
        return {}


def main() -> int:
    minted = json.load(open(sys.argv[1]))
    verifiers = {}
    for arg in sys.argv[2:]:
        name, path = arg.split("=", 1)
        verifiers[name] = json.load(open(path))
    by_id = {name: {c["id"]: c for c in v["cases"]} for name, v in verifiers.items()}

    cases, summary = [], {}
    for name in verifiers:
        summary[name] = {"cases": 0, "as_expected": 0, "unexpected": [], "unspecified": {}}
    for case in minted["cases"]:
        header, claims = part(case["token"], 0), part(case["token"], 1)
        row = {
            "id": case["id"],
            "expect": case["expect"],
            "why": case["why"],
            "alg": header.get("alg"),
        }
        for name in verifiers:
            got = by_id[name].get(case["id"], {"verdict": "missing"})
            cell = {"verdict": got["verdict"]}
            if "error" in got:
                cell["error"] = scrub(got["error"])
            if got["verdict"] == "accept":
                cell["tctx_rctx_carried"] = (
                    got.get("tctx") == claims.get("tctx") and got.get("rctx") == claims.get("rctx")
                )
            row[name] = cell
            s = summary[name]
            s["cases"] += 1
            if case["expect"] == "unspecified":
                s["unspecified"][case["id"]] = got["verdict"]
            elif got["verdict"] == case["expect"]:
                s["as_expected"] += 1
            else:
                s["unexpected"].append(case["id"])
        cases.append(row)

    out = {
        "minter": minted.get("minter"),
        "trust_domain": minted.get("trust_domain"),
        "keys": [{k: key.get(k) for k in ("kid", "kty", "crv", "alg", "use") if k in key}
                 for key in minted.get("keys", [])],
        "summary": summary,
        "cases": cases,
    }
    for name, v in verifiers.items():
        if v.get("key_errors"):
            out.setdefault("key_errors", {})[name] = [
                {k: (scrub(x) if isinstance(x, str) else x) for k, x in e.items()} for e in v["key_errors"]
            ]
        if v.get("clock"):
            out.setdefault("clock", {})[name] = v["clock"]
    if minted.get("not_minted"):
        out["not_minted"] = minted["not_minted"]
    if minted.get("claim_names"):
        out["claim_names"] = minted["claim_names"]
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
