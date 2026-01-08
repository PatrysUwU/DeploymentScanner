import json
import logging

from deployment_scanner.handlers.bandit_handler import BanditHandler
from deployment_scanner.handlers.checkov_handler import CheckovHandler
from deployment_scanner.handlers.trivy_handler import TrivyHandler

logging.basicConfig(level="DEBUG")

# from handlers.codeql_handler import CodeQLHandler


def scan(proj_path: str) -> dict:
    results = {}

    trivy = TrivyHandler(proj_path)
    bandit = BanditHandler(proj_path)
    checkov = CheckovHandler(proj_path)

    results["trivy_image"] = trivy.scan_image("python:3.11.4-alpine")
    results["bandit"] = bandit.scan_repo()
    results["checkov"] = checkov.scan_repo()

    with open("results.json", "w") as f:
        f.write(json.dumps(results, indent=4, ensure_ascii=True))
