import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "guard-plan.py"


class PlanGuardTests(unittest.TestCase):
    def run_guard(self, resource_changes):
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "plan.json"
            plan_path.write_text(json.dumps({"resource_changes": resource_changes}), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(plan_path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_allows_create_and_update(self):
        result = self.run_guard([
            {"address": "aws_instance.decoy", "change": {"actions": ["create"]}},
            {"address": "aws_cloudwatch_log_group.logs", "change": {"actions": ["update"]}},
        ])

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_delete_and_replacement(self):
        result = self.run_guard([
            {"address": "aws_instance.old", "change": {"actions": ["delete"]}},
            {"address": "aws_s3_bucket.audit", "change": {"actions": ["delete", "create"]}},
        ])

        self.assertEqual(result.returncode, 1)
        self.assertIn("aws_instance.old", result.stderr)
        self.assertIn("aws_s3_bucket.audit", result.stderr)


if __name__ == "__main__":
    unittest.main()
