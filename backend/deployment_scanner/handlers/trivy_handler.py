from .base_handler import BaseHandler


class TrivyHandler(BaseHandler):
    def scan_image(self, image: str):
        cmd = [
            "docker",
            "run",
            "--rm",
            "aquasec/trivy:latest",
            "image",
            "--format",
            "json",
            image,
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        return {
            "tool": "trivy",
            "type": "IMAGE_SCAN",
            "results": self._extract_vulnerabilities(data, image),
            "errors": err,
        }

    def _extract_vulnerabilities(self, data: dict, image: str) -> list[dict]:
        if not data:
            return []

        target = {"Target": image, "Type": "image", "Vulnerabilities": []}

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                target["Vulnerabilities"].append(
                    {
                        "VulnerabilityID": vuln.get("VulnerabilityID"),
                        "Severity": vuln.get("Severity"),
                        "Title": vuln.get("Title"),
                        "Description": vuln.get("Description"),
                        "Package": vuln.get("PkgName"),
                        "InstalledVersion": vuln.get("InstalledVersion"),
                        "FixedVersion": vuln.get("FixedVersion"),
                        "CVSS": vuln.get("CVSS", {}),
                        "DataSource": "Trivy",
                        "PublishedDate": vuln.get("PublishedDate"),
                        "LastModifiedDate": vuln.get("LastModifiedDate"),
                    }
                )

        return [target]
