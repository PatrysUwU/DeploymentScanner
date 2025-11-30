from deployment_scanner.handlers.trivy_handler import TrivyHandler
from deployment_scanner.handlers.bandit_handler import BanditHandler
from deployment_scanner.handlers.dependency_check_handler import (
    DependencyCheckHandler,
)
import json

# from handlers.codeql_handler import CodeQLHandler


def scan(proj_path: str) -> dict:
    results = {}

    trivy = TrivyHandler(proj_path)
    bandit = BanditHandler(proj_path)
    dep = DependencyCheckHandler(proj_path)
    #    codeql = CodeQLHandler(proj_path)

    results["trivy_image"] = trivy.scan_image("python:3.11.4-alpine")
    # results["bandit"] = bandit.scan_repo()
    # results["dependency_check"] = dep.scan()
    # results["codeql"] = codeql.scan()  # bardzo wolne — opcjonalne

    with open("results.json", "w") as f:
        f.write(json.dumps(results, indent=4, ensure_ascii=True))

    return results
