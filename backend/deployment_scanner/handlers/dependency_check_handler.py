from .base_handler import BaseHandler
import logging
import json
from pathlib import Path
import os

logging.basicConfig(level=logging.DEBUG)


class DependencyCheckHandler(BaseHandler):

    EXCLUDE_DIRS = [
        ".venv",
        "node_modules",
        "tests",
    ]
    NVD_DATA_DIR = os.path.expanduser("~/dependency-check-data")

    def scan(self):
        output = Path(self.proj_path) / "dp_result.json"

        exclude_abs_paths = [
            str((Path(self.proj_path) / d).resolve())
            for d in self.EXCLUDE_DIRS
        ]
        exclude_arg = ",".join(exclude_abs_paths)

        cmd = [
            "dependency-check",
            "--project",
            "scan",
            "--format",
            "JSON",
            "--out",
            str(output),
            "--scan",
            str(self.proj_path),
            "--data",
            str(self.NVD_DATA_DIR),
            "--noupdate",
            "--exclude",
            exclude_arg,
        ]
        logging.info("RUNNING DP CHECK")
        code, out, err = self.run_cmd(cmd)

        data = None
        if output.exists():
            try:
                with open(output, "r") as f:
                    data = json.load(f)
            except Exception as e:
                logging.error(f"Failed to parse dependency-check JSON: {e}")

        filtered = self._filter_data(data)

        return {
            "tool": "dependency-check",
            "type": "dependency",
            "path": str(self.proj_path),
            "success": code == 0,
            "output_raw": data,
            "errors": err,
            "results": filtered,
        }

    def _filter_data(self, data: dict):
        if not data:
            return []

        result = []

        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            return []

        for dep in dependencies:

            dep_path = Path(dep.get("filePath", ""))
            if any(
                dep_path.is_relative_to(Path(self.proj_path) / d)
                for d in self.EXCLUDE_DIRS
            ):
                continue
            entry = {
                "Target": dep.get("fileName", ""),
                "Type": "dependency",
                "Vulnerabilities": [],
            }

            vulns = dep.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                continue

            for vuln in vulns:
                cvss_score = vuln.get("cvssScore") or (
                    vuln.get("cvss") or {}
                ).get("baseScore")

                temp_vul = {
                    "VulnerabilityID": vuln.get("name", ""),
                    "Severity": vuln.get("severity", "UNKNOWN"),
                    "Description": vuln.get("description", ""),
                    "File": dep.get("fileName", ""),
                    "Line": None,
                    "CVSS": {"score": cvss_score},
                    "DataSource": vuln.get("source", "NVD"),
                    "PublishedDate": vuln.get("publishedDate", ""),
                    "LastModifiedDate": vuln.get("lastModifiedDate", ""),
                }

                entry["Vulnerabilities"].append(temp_vul)

            result.append(entry)

        return result
