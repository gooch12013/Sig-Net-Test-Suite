#!/usr/bin/env python3
"""Checks the rules fixture.schema.json can't express.

Usage: check_fixture.py FILE.json [...]   (run --self-test to test this script)
Validate against the schema first; this assumes the file's shape is valid.
"""
import json
import sys


def problems(fixture):
    out = []
    for p in fixture["personalities"]:
        where = f"personality {p['personality']} ({p['name']})"
        chans = p["channels"]
        if p["footprint"] != len(chans):
            out.append(f"{where}: footprint {p['footprint']} but {len(chans)} channels")
        nums = [c["ch"] for c in chans]
        if nums != list(range(1, len(chans) + 1)):
            out.append(f"{where}: ch numbers {nums}, expected 1..{len(chans)}")
        for c in chans:
            r = c["ranges"]
            cw = f"{where} ch {c['ch']}"
            if r[0]["from"] != 0:
                out.append(f"{cw}: first range starts at {r[0]['from']}, not 0")
            if r[-1]["to"] != 255:
                out.append(f"{cw}: last range ends at {r[-1]['to']}, not 255")
            for x in r:
                if x["from"] > x["to"]:
                    out.append(f"{cw}: range {x['name']!r} has from {x['from']} > to {x['to']}")
            for a, b in zip(r, r[1:]):
                if b["from"] != a["to"] + 1:
                    out.append(f"{cw}: {a['name']!r} ends at {a['to']}, {b['name']!r} starts at {b['from']}")
    return out


def self_test():
    rng = lambda f, t: {"from": f, "to": t, "name": f"{f}-{t}"}
    good = {"personalities": [{"personality": 1, "name": "2CH", "footprint": 2, "channels": [
        {"ch": 1, "name": "A", "ranges": [rng(0, 255)]},
        {"ch": 2, "name": "B", "ranges": [rng(0, 9), rng(10, 255)]},
    ]}]}
    assert problems(good) == []
    bad = json.loads(json.dumps(good))
    p = bad["personalities"][0]
    p["footprint"] = 3
    p["channels"][1]["ch"] = 3
    p["channels"][1]["ranges"] = [rng(1, 9), rng(11, 254)]
    assert len(problems(bad)) == 5, problems(bad)
    print("self-test ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    if not sys.argv[1:]:
        sys.exit(__doc__)
    failed = False
    for path in sys.argv[1:]:
        with open(path) as f:
            found = problems(json.load(f))
        for msg in found:
            print(f"{path}: {msg}")
        failed |= bool(found)
        if not found:
            print(f"{path}: ok")
    sys.exit(1 if failed else 0)
