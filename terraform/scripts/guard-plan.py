import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Reject destructive actions in a normal Terraform apply plan.")
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()

    plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
    destructive = []
    for resource in plan.get("resource_changes", []):
        actions = resource.get("change", {}).get("actions", [])
        if "delete" in actions:
            destructive.append(f"{resource.get('address', '<unknown>')}: {','.join(actions)}")

    if destructive:
        print("Normal apply blocked because the plan contains delete or replacement actions:", file=sys.stderr)
        for item in destructive:
            print(f"  {item}", file=sys.stderr)
        print("Review and resolve the change, or use the separately protected destroy workflow.", file=sys.stderr)
        return 1

    print("Plan guard passed: no resource delete or replacement actions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
