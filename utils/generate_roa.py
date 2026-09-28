"""generates the 'roa.json' file to be consumed by StayRTR"""

import argparse
import datetime
import ipaddress
import json
import os
import sys
from pathlib import Path

from rpsl import DATA_DIR, Registry


def roas(registry: Registry) -> list[dict]:
    vrps = set()
    for obj in registry.valid("route").values():
        network = ipaddress.IPv4Network(obj.get("route"))
        max_length = int(obj.get("max-length") or network.prefixlen)
        for origin in obj.get_all("origin"):
            vrps.add((network, max_length, int(origin.removeprefix("AS"))))
    return [
        {"prefix": str(network), "maxLength": max_length, "asn": asn}
        for network, max_length, asn in sorted(vrps)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit non-zero on any warning")
    parser.add_argument("--data", type=Path, default=DATA_DIR, help="registry data directory")
    parser.add_argument("-o", "--output", type=Path, default=Path("roa.json"), help="output file")
    args = parser.parse_args()

    registry = Registry(args.data)
    if "route" not in registry.schemas:
        print("error: no valid schema for route, refusing to write ROAs", file=sys.stderr)
        return 1

    problems = [
        f"route/{problem.path.name}: {problem.message}"
        for problem in registry.validate()
        if problem.error and problem.path.parent.name == "route"
    ]
    for problem in problems:
        print(f"warning: {problem}, skipping", file=sys.stderr)

    vrps = roas(registry)
    # StayRTR refuses a file whose build time is older than 24 hours, so it is always rewritten
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    output = {
        "metadata": {
            "generated": int(now.timestamp()),
            "buildtime": now.isoformat().replace("+00:00", "Z"),
            "vrps": len(vrps),
        },
        "roas": vrps,
    }

    tmp = args.output.with_name(f"{args.output.name}.tmp")
    tmp.write_text(json.dumps(output, indent=2) + "\n")
    os.replace(tmp, args.output)
    print(f"{args.output}: {len(vrps)} ROA(s)")
    return 1 if args.check and problems else 0


if __name__ == "__main__":
    sys.exit(main())
