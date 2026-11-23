#!/usr/bin/env python3
"""Verify visado-minted AAT chains with the Section 8 verifier in tenuo's
ietf/vectors/gen_vectors.py.

Usage: tenuo_verify.py TENUO_CHECKOUT MINTED.json

Prints one result per case, with visado's verdict next to tenuo's, and exits 1
if any verdict differs.
"""

import json
import sys
from pathlib import Path


def main() -> int:
    checkout, minted_path = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(checkout / "ietf" / "vectors"))
    sys.argv = sys.argv[:1]  # gen_vectors parses argv only when run as a script
    import gen_vectors as g  # noqa: E402

    minted = json.loads(minted_path.read_text())
    anchors = [(a["iss"], a["jwk"]) for a in minted["trust_anchors"]]
    results, differ = [], 0
    for case in minted["cases"]:
        args, dup = g._loads(case["args_json"])
        try:
            verdict = {"verdict": g.verify_chain(
                case["chain"], anchors, case["tool"], args, case["pop"],
                now=minted["now"], audience=minted["audience"], args_dup=dup)}
        except g.Deny as e:
            verdict = {"verdict": "DENY", "step": e.step}
        same = verdict["verdict"] == case["visado"]["verdict"]
        differ += not same
        results.append({"id": case["id"], "note": case["note"], "visado": case["visado"],
                        "tenuo": verdict, "agree": same})
    print(json.dumps({"verifier": "tenuo ietf/vectors/gen_vectors.py verify_chain",
                      "cases": len(results), "differ": differ, "results": results}, indent=2))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
