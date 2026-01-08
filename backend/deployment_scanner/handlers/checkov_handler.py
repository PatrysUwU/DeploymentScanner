import json
import sys
from pathlib import Path

from .base_handler import BaseHandler


class CheckovHandler(BaseHandler):
    def scan_repo(self):
        checkov_bin = Path(sys.executable).parent / "checkov.cmd"

        cmd = [str(checkov_bin), "-d", str(self.proj_path), "-o", "json", "--quiet"]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        with open("checkov_output.json", "w") as f:
            json.dump(data, f, indent=4)

        return {
            "tool": "checkov",
            "type": "iac",
            "results": self._normalize(data),
            "errors": err,
        }

    def _normalize(self, data: dict) -> list[dict]:
        if not data:
            return []

        target = {"Target": str(self.proj_path), "Type": "iac", "Vulnerabilities": []}

        for check_type in data:
            for check in check_type.get("results", {}).get("failed_checks", []):
                target["Vulnerabilities"].append(
                    {
                        "VulnerabilityID": check.get("check_id"),
                        "Severity": check.get("severity"),
                        "Title": check.get("check_name"),
                        "Description": check.get("guideline"),
                        "File": check.get("file_path"),
                        "Line": check.get("file_line_range", [None])[0],
                        "CVSS": {},
                        "References": check.get("guideline", "").split(),
                    }
                )

        return [target]
