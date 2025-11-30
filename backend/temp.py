import json
import logging

logging.basicConfig(level=logging.DEBUG)

# Open Trivy result file
with open("trivy_res.json", "r") as f:
    data = json.load(f)

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
        logging.debug(f"Adding vulnerability: {temp_vul['VulnerabilityID']}")

    result.append(temp)

# Write to output file
with open("TESTSTESTESTSE.json", "w") as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

logging.info("Processing complete!")
