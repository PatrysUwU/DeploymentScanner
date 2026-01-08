from typing import Any, Dict, Optional

from .base_handler import BaseHandler


class TrivyHandler(BaseHandler):
    def scan_image(self, image: str):
        cmd = [
            "trivy",
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

    def _extract_vulnerabilities(
        self, data: Optional[Dict[str, Any]], image: str
    ) -> list[dict]:
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

    def scan_misconfig(self, path: str):
        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "misconfig",
            path,
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        return {
            "tool": "trivy",
            "type": "MISCONFIG_SCAN",
            "results": self._extract_misconfigurations(data, path),
            "errors": err,
        }

    def _extract_misconfigurations(
        self, data: Optional[Dict[str, Any]], path: str
    ) -> list[dict]:
        if not data:
            return []

        target = {"Target": path, "Type": "misconfig", "Misconfigurations": []}

        for result in data.get("Results", []):
            # Informacje o pliku z poziomu Result
            result_target = result.get("Target", "")

            for misconfig in result.get("Misconfigurations", []):
                # Pobierz informacje o lokalizacji z CauseMetadata
                cause_metadata = misconfig.get("CauseMetadata", {})

                misconfig_entry = {
                    "ID": misconfig.get("ID"),
                    "Severity": misconfig.get("Severity"),
                    "Title": misconfig.get("Title"),
                    "Description": misconfig.get("Description"),
                    "Message": misconfig.get("Message"),
                    "Type": misconfig.get("Type"),
                    "Status": misconfig.get("Status"),
                    "DataSource": "Trivy",
                    "File": result_target,
                }

                # Dodaj numery linii jeśli dostępne
                if "StartLine" in cause_metadata:
                    misconfig_entry["StartLine"] = cause_metadata["StartLine"]
                if "EndLine" in cause_metadata:
                    misconfig_entry["EndLine"] = cause_metadata["EndLine"]

                target["Misconfigurations"].append(misconfig_entry)

        return [target]
