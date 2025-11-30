from .base_handler import BaseHandler
import logging

logging.basicConfig(level="DEBUG")


class TrivyHandler(BaseHandler):

    def scan_image(self, image: str) -> dict:
        cmd = ["trivy", "image", "--format", "json", image]

        code, out, err = self.run_cmd(cmd)
        out = self._filter_data(self.parse_json(out))
        logging.debug(out)
        return {
            "tool": "trivy",
            "type": "image",
            "image": image,
            "success": code == 0,
            "output_raw": out,
            "errors": err,
            "results": out,
        }

    def scan_filesystem(self) -> dict:
        cmd = ["trivy", "fs", "--format", "json", str(self.proj_path)]

        code, out, err = self.run_cmd(cmd)
        return {
            "tool": "trivy",
            "type": "filesystem",
            "path": str(self.proj_path),
            "success": code == 0,
            "output_raw": out,
            "errors": err,
            "results": self.parse_json(out),
        }

    def _filter_data(self, data):
        result = []
        for res in data.get("Results", []):
            temp = {}
            temp["Target"] = res.get("Target", "")
            temp["Type"] = res.get("Type", "")
            temp["Vulnerabilities"] = []

            for vuln in res.get("Vulnerabilities", []):
                temp_vul = {
                    "VulnerabilityID": vuln.get("VulnerabilityID", ""),
                    "Status": vuln.get("Status", ""),
                    "InstalledVersion": vuln.get("InstalledVersion", ""),
                    "CVSS": vuln.get("CVSS", {}),
                    "PublishedDate": vuln.get("PublishedDate", ""),
                    "LastModifiedDate": vuln.get("LastModifiedDate", ""),
                    "DataSource": vuln.get("DataSource", ""),
                    "NVDUrl": vuln.get("PrimaryURL", ""),
                }
                if vuln.get("Status") == "fixed":
                    temp_vul["FixedVersion"] = vuln.get("FixedVersion", "")
                temp["Vulnerabilities"].append(temp_vul)
                logging.debug(
                    f"Adding vulnerability: {temp_vul['VulnerabilityID']}"
                )

            result.append(temp)
        return result
