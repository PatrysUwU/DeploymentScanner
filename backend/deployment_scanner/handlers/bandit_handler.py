from .base_handler import BaseHandler
import logging

logging.basicConfig(level="DEBUG")


class BanditHandler(BaseHandler):

    def scan_repo(self):
        cmd = [
            "bandit",
            "-r",
            str(self.proj_path),
            "-f",
            "json",
            "-x",
            "./.venv",
            "-q",
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        filtered = self._filter_data(data)

        return {
            "tool": "bandit",
            "type": "static",
            "path": str(self.proj_path),
            "success": code == 0,
            "errors": err,
            "results": filtered,
        }

    def _filter_data(self, data: dict) -> list[dict]:
        if not data:
            return []

        result = [
            {
                "Target": str(self.proj_path),
                "Type": "bandit",
                "Vulnerabilities": [],
            }
        ]

        vulns = result[0]["Vulnerabilities"]

        for issue in data.get("results", []):
            vuln = {
                "VulnerabilityID": issue.get("test_id"),
                "Severity": issue.get("issue_severity"),
                "Description": issue.get("issue_text"),
                "File": issue.get("filename"),
                "Line": issue.get("line_number"),
                "CVSS": {},
                "DataSource": "Bandit",
                "PublishedDate": "",
                "LastModifiedDate": "",
            }
            vulns.append(vuln)

        return result
