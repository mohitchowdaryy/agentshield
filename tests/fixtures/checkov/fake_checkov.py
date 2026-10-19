"""Stand-in for the checkov CLI in tests: replays real captured JSON outputs.

Modes (FAKE_CHECKOV_MODE): "ok" (default), "fail" (exit 2), "badjson", "sleep", "noversion".
It records its argv to FAKE_CHECKOV_ARGS_FILE when set, so tests can check argument handling.
"""

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent


def main() -> int:
    args = sys.argv[1:]
    record = os.environ.get("FAKE_CHECKOV_ARGS_FILE")
    if record:
        with open(record, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(args) + "\n")
    mode = os.environ.get("FAKE_CHECKOV_MODE", "ok")
    if "--version" in args:
        if mode == "noversion":
            return 1
        print("3.3.29")
        return 0
    if mode == "fail":
        print("boom: simulated scanner crash", file=sys.stderr)
        return 2
    if mode == "badjson":
        print("this is not json")
        return 0
    if mode == "sleep":
        time.sleep(30)
        return 0
    target = Path(args[args.index("--directory") + 1])
    name = "secure" if target.name == "secure" else "insecure"
    sys.stdout.write((HERE / f"{name}.json").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
