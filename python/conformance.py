"""Run the SPEC.md §12 conformance vectors against the Python implementation.

Prints one line per vector and exits non-zero on any mismatch.
"""

import base64
import json
import sys
from pathlib import Path

import agentmail


def main(path: str) -> int:
    vec = json.loads(Path(path).read_text())
    assert vec["domain"].encode() == agentmail.DOMAIN, "domain string mismatch"
    seeds = {k["name"]: bytes.fromhex(k["seed"]) for k in vec["keys"]}
    for k in vec["keys"]:
        tok = agentmail.sign(seeds[k["name"]], b"{}")
        if "k_" + tok.split(".")[1] != k["key"]:
            print(f"FAIL key {k['name']}")
            return 1
    fails = passes = 0
    for v in vec["valid"]:
        payload = base64.urlsafe_b64decode(v["payload_b64"] + "=" * (-len(v["payload_b64"]) % 4))
        problems = []
        if agentmail.sign(seeds[v["signer"]], payload) != v["token"]:
            problems.append("re-signed token differs")
        try:
            got = agentmail.verify(v["token"])
            if got["id"] != v["id"] or got["t"] != v["t"]:
                problems.append(f"id/t mismatch {got['id']} {got['t']}")
        except Exception as e:  # an uncaught crash is a failure of THIS vector
            problems.append(f"rejected with {type(e).__name__}: {e}")
        fails, passes = report("valid", v["name"], problems, fails, passes)
    for v in vec["invalid"]:
        problems = []
        try:
            agentmail.verify(v["token"])
            problems.append("accepted")
        except agentmail.AgentMailError as e:
            if e.code != v["error"]:
                problems.append(f"want {v['error']}, got {e}")
        except Exception as e:
            problems.append(f"want {v['error']}, crashed with {type(e).__name__}: {e}")
        fails, passes = report("invalid", v["name"], problems, fails, passes)
    print(f"python: {passes} passed, {fails} failed, {passes + fails} vectors")
    return 1 if fails or passes == 0 else 0


def report(kind, name, problems, fails, passes):
    if problems:
        print(f"FAIL {kind} {name}: {'; '.join(problems)}")
        return fails + 1, passes
    print(f"ok   {kind} {name}")
    return fails, passes + 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
