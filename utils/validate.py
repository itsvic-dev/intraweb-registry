#!/usr/bin/env python3
"""check every registry object against its schema"""

import argparse
import os
import sys
from pathlib import Path

from rpsl import DATA_DIR, Registry

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DATA_DIR, help="registry data directory")
    args = parser.parse_args()

    problems = Registry(args.data).validate()
    for problem in problems:
        kind = "error" if problem.error else "warning"
        path = os.path.relpath(problem.path, args.data.parent)
        if IN_ACTIONS:
            print(f"::{kind} file={path}::{problem.message}")
        else:
            print(f"{kind}: {path}: {problem.message}")

    errors = sum(problem.error for problem in problems)
    print(f"{errors} error(s), {len(problems) - errors} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
