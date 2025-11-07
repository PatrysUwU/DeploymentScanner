from deployment_scanner.handlers.bandit_handler import BanditHandler
from deployment_scanner.handlers.trivy_handler import TrivyHandler


def scan(proj_path):
    trivy = TrivyHandler(proj_path)
    bandit = BanditHandler(proj_path)
    trivy.scan_image("python:3.11.4-alpine")
    bandit.scan_repo()


def runserver(args: dict):
    pass
