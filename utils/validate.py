#!/usr/bin/env python3
"""check every registry object against its schema"""

import os
import sys

from rpsl import Registry

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def main() -> int:
    problems = Registry().validate()
    for problem in problems:
        kind = "error" if problem.error else "warning"
        path = os.path.relpath(problem.path)
        if IN_ACTIONS:
            print(f"::{kind} file={path}::{problem.message}")
        else:
            print(f"{kind}: {path}: {problem.message}")

    errors = sum(problem.error for problem in problems)
    print(f"{errors} error(s), {len(problems) - errors} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
