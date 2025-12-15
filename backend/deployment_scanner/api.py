from deployment_scanner.handlers.trivy_handler import TrivyHandler
from deployment_scanner.handlers.bandit_handler import BanditHandler
from deployment_scanner.handlers.dependency_check_handler import (
    DependencyCheckHandler,
)
import json
import logging

logging.basicConfig(level="DEBUG")

# from handlers.codeql_handler import CodeQLHandler


def scan(proj_path: str) -> dict:
    results = {}

    trivy = TrivyHandler(proj_path)
    bandit = BanditHandler(proj_path)
    dep = DependencyCheckHandler(proj_path)
    #    codeql = CodeQLHandler(proj_path)

    results["trivy_image"] = trivy.scan_image("python:3.11.4-alpine")
    results["bandit"] = bandit.scan_repo()
    results["dependency_check"] = dep.scan()
    # results["codeql"] = codeql.scan()  # bardzo wolne — opcjonalne

    with open("results.json", "w") as f:
        f.write(json.dumps(results, indent=4, ensure_ascii=True))

    i = 0
    total = 0

    for target in results["trivy_image"]["output_raw"]:
        for vuln in target.get("Vulnerabilities", []):
            cvss = vuln.get("CVSS", {})
            nvd = cvss.get("nvd")

            if nvd and "V3Score" in nvd:
                score = nvd["V3Score"]
                logging.debug(score)
                total += score
                i += 1

    if i > 0:
        print(total / i)
    else:
        print("Brak podatności z CVSS")
