import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from deployment_scanner.handlers.bandit_handler import BanditHandler
from deployment_scanner.handlers.trivy_handler import TrivyHandler
from deployment_scanner.scanners.docker_compose_scanner import DockerComposeScanner

logging.basicConfig(level="DEBUG")


def aggregate_scan(proj_path: str, docker_compose_path: Optional[str] = None) -> dict:
    """
    Przeprowadza pełny skan bezpieczeństwa projektu:
    - Trivy: skany obrazów Docker i misconfiguration
    - Bandit: SAST (Static Application Security Testing)

    Args:
        proj_path: Ścieżka do projektu
        docker_compose_path: Ścieżka do pliku docker-compose.yml (opcjonalne)

    Returns:
        Dict z wynikami wszystkich skanów
    """
    results = {}
    proj_path_obj = Path(proj_path).resolve()

    logging.info(f"Rozpoczynanie agregacyjnego skanu projektu: {proj_path_obj}")

    # Inicjalizacja handlerów
    trivy = TrivyHandler(str(proj_path_obj))
    bandit = BanditHandler(str(proj_path_obj))

    # 1. SKANOWANIE BANDIT (SAST)
    logging.info("Uruchamianie skanu Bandit (SAST)...")
    results["bandit"] = bandit.scan_repo()

    # 2. SKANOWANIE TRIVY MISCONFIGURATION
    logging.info("Uruchamianie skanu Trivy misconfiguration...")
    results["trivy_misconfig"] = trivy.scan_misconfig(str(proj_path_obj))

    # 3. SKANOWANIE DOCKER COMPOSE SECURITY ISSUES
    logging.info("Uruchamianie skanu Docker Compose security issues...")
    results["docker_compose_security"] = _scan_docker_compose_security(
        proj_path_obj, docker_compose_path
    )

    # 4. WYCIĄGNIĘCIE OBRAZÓW Z DOCKER COMPOSE I SKANOWANIE
    images_and_configs = _extract_images_with_config_from_project(
        proj_path_obj, docker_compose_path
    )

    if images_and_configs:
        logging.info(f"Znaleziono {len(images_and_configs)} obrazów do skanowania")
        results["trivy_images"] = {}

        for image_data in images_and_configs:
            image = image_data["image"]
            container_config = image_data["config"]
            logging.info(f"Skanowanie obrazu: {image}")
            try:
                scan_result = trivy.scan_image(image)
                # Dodaj konfigurację kontenera do wyników
                scan_result["container_config"] = container_config
                results["trivy_images"][image] = scan_result
            except Exception as e:
                logging.error(f"Błąd podczas skanowania obrazu {image}: {e}")
                results["trivy_images"][image] = {
                    "tool": "trivy",
                    "type": "IMAGE_SCAN",
                    "results": [],
                    "errors": str(e),
                    "container_config": container_config,
                }
    else:
        logging.warning("Nie znaleziono obrazów do skanowania")
        results["trivy_images"] = {}

    # 4. GENEROWANIE PODSUMOWANIA
    results["summary"] = _generate_summary(results)

    return results


def _extract_images_with_config_from_project(
    proj_path: Path, docker_compose_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Wyciąga nazwy obrazów Docker wraz z konfiguracją kontenerów z projektu

    Args:
        proj_path: Ścieżka do projektu
        docker_compose_path: Opcjonalna ścieżka do pliku docker-compose.yml

    Returns:
        Lista słowników z danymi obrazów i konfiguracji kontenerów
    """
    images_with_config = []

    # Jeśli podano konkretną ścieżkę do docker-compose
    if docker_compose_path:
        compose_file = Path(docker_compose_path)
        if compose_file.exists():
            images_with_config.extend(
                _scan_docker_compose_file_with_config(compose_file)
            )
        else:
            logging.warning(
                f"Podany plik docker-compose nie istnieje: {docker_compose_path}"
            )
    else:
        # Szukanie plików docker-compose w projekcie
        compose_files = _find_docker_compose_files(proj_path)

        for compose_file in compose_files:
            logging.info(f"Analizuję plik: {compose_file}")
            images_with_config.extend(
                _scan_docker_compose_file_with_config(compose_file)
            )

    # Filtrowanie obrazów "custom" i usuwanie duplikatów
    filtered_images = []
    seen_images = set()

    for item in images_with_config:
        image = item["image"]
        if image != "custom" and image and image not in seen_images:
            filtered_images.append(item)
            seen_images.add(image)

    image_names = [item["image"] for item in filtered_images]
    logging.info(f"Znaleziono obrazy: {image_names}")
    return filtered_images


def _find_docker_compose_files(proj_path: Path) -> List[Path]:
    """Znajduje wszystkie pliki docker-compose w projekcie"""
    compose_files = []

    # Typowe nazwy plików docker-compose
    compose_patterns = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.*.yml",
        "docker-compose.*.yaml",
    ]

    for pattern in compose_patterns:
        compose_files.extend(proj_path.glob(pattern))
        # Szukanie również w podkatalogach (do 2 poziomów głębokości)
        compose_files.extend(proj_path.glob(f"*/{pattern}"))
        compose_files.extend(proj_path.glob(f"*/*/{pattern}"))

    return list(set(compose_files))  # Usuwanie duplikatów


def _scan_docker_compose_file_with_config(compose_file: Path) -> List[Dict[str, Any]]:
    """
    Skanuje pojedynczy plik docker-compose i wyciąga obrazy wraz z konfiguracją

    Args:
        compose_file: Ścieżka do pliku docker-compose

    Returns:
        Lista słowników z obrazami i konfiguracją kontenerów
    """
    images_with_config = []

    try:
        scanner = DockerComposeScanner()
        scan_result = scanner.scan_docker_compose(str(compose_file))

        # Wyciąganie obrazów i konfiguracji z wyników skanowania
        for service_name, service_data in scan_result.get("services", {}).items():
            # Wyciągnij konfigurację bezpieczeństwa z service_data
            container_config = _extract_security_config(service_data, service_name)

            image = service_data.get("image")
            build_context = service_data.get("build_context")

            # Jeśli jest podany gotowy obraz
            if image and image != "custom":
                images_with_config.append(
                    {
                        "image": image,
                        "service_name": service_name,
                        "config": container_config,
                        "compose_file": str(compose_file),
                    }
                )
                logging.debug(
                    f"Znaleziono obraz '{image}' w serwisie '{service_name}' z konfiguracją"
                )

            # Jeśli jest build context, wyciągnij obraz bazowy z Dockerfile
            elif build_context:
                dockerfile_path = _get_dockerfile_path(
                    build_context, compose_file.parent, service_data.get("dockerfile")
                )
                base_image = _extract_base_image_from_dockerfile(dockerfile_path)

                if base_image:
                    images_with_config.append(
                        {
                            "image": base_image,
                            "service_name": service_name,
                            "config": container_config,
                            "compose_file": str(compose_file),
                            "from_dockerfile": True,
                            "dockerfile_path": str(dockerfile_path)
                            if dockerfile_path
                            else None,
                        }
                    )
                    logging.debug(
                        f"Znaleziono obraz bazowy '{base_image}' z Dockerfile dla serwisu '{service_name}'"
                    )

    except Exception as e:
        logging.error(f"Błąd podczas analizy pliku {compose_file}: {e}")

    return images_with_config


def _extract_security_config(
    service_data: Dict[str, Any], service_name: str
) -> Dict[str, Any]:
    """
    Wyciąga konfigurację kontenera z danych serwisu docker-compose

    Args:
        service_data: Dane serwisu z wyników skanowania
        service_name: Nazwa serwisu

    Returns:
        Słownik z konfiguracją kontenera
    """
    config = {
        "service_name": service_name,
        "image": service_data.get("image", ""),
        "ports": service_data.get("ports", []),
        "environment": service_data.get("environment", {}),
        "volumes": service_data.get("volumes", []),
        "build_context": service_data.get("build_context"),
        "dockerfile": service_data.get("dockerfile"),
        "depends_on": service_data.get("depends_on", []),
        "command": service_data.get("command"),
        "source_files": service_data.get("source_files", []),
        "mounted_code": service_data.get("mounted_code", []),
        "dockerfile_instructions": service_data.get("dockerfile_instructions", []),
    }

    return config


def _get_dockerfile_path(
    build_context: str, compose_dir: Path, dockerfile_name: Optional[str] = None
) -> Optional[Path]:
    """
    Znajduje ścieżkę do Dockerfile

    Args:
        build_context: Ścieżka do build context
        compose_dir: Katalog z plikiem docker-compose
        dockerfile_name: Opcjonalna nazwa pliku Dockerfile

    Returns:
        Ścieżka do Dockerfile lub None
    """
    # Ścieżka do build context
    build_path = (
        compose_dir / build_context
        if not Path(build_context).is_absolute()
        else Path(build_context)
    )

    if not build_path.exists():
        logging.warning(f"Build context nie istnieje: {build_path}")
        return None

    # Nazwa pliku Dockerfile
    dockerfile_file = dockerfile_name if dockerfile_name else "Dockerfile"

    dockerfile_path = build_path / dockerfile_file

    if dockerfile_path.exists():
        return dockerfile_path
    else:
        logging.warning(f"Dockerfile nie znaleziony: {dockerfile_path}")
        return None


def _extract_base_image_from_dockerfile(
    dockerfile_path: Optional[Path],
) -> Optional[str]:
    """
    Wyciąga obraz bazowy z klauzuli FROM w Dockerfile

    Args:
        dockerfile_path: Ścieżka do Dockerfile

    Returns:
        Nazwa obrazu bazowego lub None
    """
    if not dockerfile_path or not dockerfile_path.exists():
        return None

    try:
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            # Sprawdź czy linia zaczyna się od FROM
            if line.upper().startswith("FROM "):
                # Wyciągnij nazwę obrazu (usuń FROM i ewentualne aliasy)
                parts = line.split()
                if len(parts) >= 2:
                    base_image = parts[1]
                    # Jeśli jest alias (AS alias), weź tylko nazwę obrazu
                    if "AS" in parts or "as" in parts:
                        base_image = parts[1]
                    logging.debug(f"Znaleziono obraz bazowy: {base_image}")
                    return base_image

        logging.warning(f"Nie znaleziono klauzuli FROM w {dockerfile_path}")
        return None

    except Exception as e:
        logging.error(f"Błąd podczas czytania Dockerfile {dockerfile_path}: {e}")
        return None


def _scan_docker_compose_security(
    proj_path: Path, docker_compose_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Skanuje problemy bezpieczeństwa w plikach docker-compose
    """
    security_issues = []

    # Jeśli podano konkretną ścieżkę do docker-compose
    if docker_compose_path:
        compose_file = Path(docker_compose_path)
        if compose_file.exists():
            security_issues.extend(_extract_security_issues_from_compose(compose_file))
        else:
            logging.warning(
                f"Podany plik docker-compose nie istnieje: {docker_compose_path}"
            )
    else:
        # Szukanie plików docker-compose w projekcie
        compose_files = _find_docker_compose_files(proj_path)

        for compose_file in compose_files:
            logging.info(f"Skanuję problemy bezpieczeństwa w: {compose_file}")
            security_issues.extend(_extract_security_issues_from_compose(compose_file))

    return {
        "tool": "docker_compose_scanner",
        "type": "MISCONFIG_SCAN",
        "results": [
            {
                "Target": str(proj_path),
                "Type": "docker_compose_security",
                "SecurityIssues": security_issues,
            }
        ],
        "errors": "",
    }


def _extract_security_issues_from_compose(compose_file: Path) -> List[Dict[str, Any]]:
    """
    Wyciąga problemy bezpieczeństwa z pojedynczego pliku docker-compose
    """
    issues = []

    try:
        scanner = DockerComposeScanner()
        scan_result = scanner.scan_docker_compose(str(compose_file))

        # Wyciągnij security issues z wszystkich serwisów
        for service_name, service_data in scan_result.get("services", {}).items():
            service_issues = service_data.get("security_issues", [])
            for issue in service_issues:
                # Dodaj informacje o serwisie i pliku
                issue_copy = issue.copy()
                issue_copy["service_name"] = service_name
                issue_copy["compose_file"] = str(compose_file)
                issues.append(issue_copy)

    except Exception as e:
        logging.error(f"Błąd podczas skanowania bezpieczeństwa {compose_file}: {e}")

    return issues


def _generate_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generuje podsumowanie wyników skanowania"""
    summary = {
        "total_scans": 0,
        "bandit_issues": 0,
        "trivy_misconfig_issues": 0,
        "trivy_image_vulnerabilities": 0,
        "docker_compose_security_issues": 0,
        "scanned_images": 0,
        "severity_breakdown": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        },
    }

    # Bandit
    if "bandit" in results:
        summary["total_scans"] += 1
        bandit_results = results["bandit"].get("results", [])
        for target in bandit_results:
            summary["bandit_issues"] += len(target.get("Vulnerabilities", []))
            for vuln in target.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "unknown").lower()
                if severity in summary["severity_breakdown"]:
                    summary["severity_breakdown"][severity] += 1

    # Trivy misconfiguration
    if "trivy_misconfig" in results:
        summary["total_scans"] += 1
        misconfig_results = results["trivy_misconfig"].get("results", [])
        for target in misconfig_results:
            summary["trivy_misconfig_issues"] += len(
                target.get("Misconfigurations", [])
            )
            for misconfig in target.get("Misconfigurations", []):
                severity = misconfig.get("Severity", "unknown").lower()
                if severity in summary["severity_breakdown"]:
                    summary["severity_breakdown"][severity] += 1

    # Docker Compose security issues
    if "docker_compose_security" in results:
        summary["total_scans"] += 1
        docker_compose_results = results["docker_compose_security"].get("results", [])
        for target in docker_compose_results:
            summary["docker_compose_security_issues"] += len(
                target.get("SecurityIssues", [])
            )
            for issue in target.get("SecurityIssues", []):
                severity = issue.get("severity", "unknown").lower()
                if severity in summary["severity_breakdown"]:
                    summary["severity_breakdown"][severity] += 1

    # Trivy obrazy
    if "trivy_images" in results:
        summary["scanned_images"] = len(results["trivy_images"])
        for image_name, image_results in results["trivy_images"].items():
            summary["total_scans"] += 1
            image_scan_results = image_results.get("results", [])
            for target in image_scan_results:
                vulnerabilities = target.get("Vulnerabilities", [])
                summary["trivy_image_vulnerabilities"] += len(vulnerabilities)
                for vuln in vulnerabilities:
                    severity = vuln.get("Severity", "unknown").lower()
                    if severity in summary["severity_breakdown"]:
                        summary["severity_breakdown"][severity] += 1

    summary["total_issues"] = (
        summary["bandit_issues"]
        + summary["trivy_misconfig_issues"]
        + summary["trivy_image_vulnerabilities"]
        + summary["docker_compose_security_issues"]
    )

    return summary
