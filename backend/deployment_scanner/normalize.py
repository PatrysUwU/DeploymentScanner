import logging
from typing import Any, Dict

logging.basicConfig(level="DEBUG")


def normalize_scan_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizuje wyniki skanowania z aggregate_scan i dodaje pola wage oraz final scoring
    do każdego vulnerability osobno w podobiekcie "after_normalizing".

    Reguły scoringu:
    - Podatności w zależnościach: CVSS z NVD * 10 * 0.4
    - Konfiguracja infrastruktury: severity (1-10) * 0.35
    - SAST (Bandit): severity (1-10) * 0.25

    Args:
        results: Wyniki z aggregate_scan

    Returns:
        Wyniki z dodanym podobiektem "after_normalizing" do każdego vulnerability
    """
    logging.info("Rozpoczynanie normalizacji wyników skanowania")

    # 1. Normalizacja podatności w zależnościach (Trivy Image Scans)
    _normalize_dependency_vulnerabilities(results.get("trivy_images", {}))

    # 2. Normalizacja konfiguracji infrastruktury (Trivy Misconfiguration)
    _normalize_infrastructure_config(results.get("trivy_misconfig", {}))

    # 3. Normalizacja problemów SAST (Bandit)
    _normalize_sast_issues(results.get("bandit", {}))

    logging.info("Normalizacja zakończona")

    return results


def _normalize_dependency_vulnerabilities(trivy_images: Dict[str, Any]):
    """
    Dodaje after_normalizing do każdej podatności w zależnościach z Trivy Image Scans
    CVSS z NVD * 10 * 0.4
    """
    for image_name, image_data in trivy_images.items():
        image_results = image_data.get("results", [])

        for target in image_results:
            vulnerabilities = target.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                # Pobierz CVSS score z NVD
                cvss_score = _extract_cvss_score(vuln)

                # Oblicz score dla tej podatności: CVSS * 10 * 0.4
                vuln_score = cvss_score * 10

                # Dodaj podobiekct after_normalizing do vulnerability
                vuln["after_normalizing"] = {
                    "weight": 0.4,
                    "final_scoring": vuln_score,
                    "cvss_score": cvss_score,
                }

    logging.debug("Dependency vulnerabilities normalized")


def _normalize_infrastructure_config(trivy_misconfig: Dict[str, Any]):
    """
    Dodaje after_normalizing do każdego problemu konfiguracji infrastruktury z Trivy Misconfiguration
    severity (1-10) * 0.35
    """
    misconfig_results = trivy_misconfig.get("results", [])

    for target in misconfig_results:
        misconfigurations = target.get("Misconfigurations", [])

        for misconfig in misconfigurations:
            # Konwertuj severity na wartość numeryczną (1-10)
            severity_score = _convert_severity_to_numeric(
                misconfig.get("Severity", "UNKNOWN")
            )

            # Oblicz score dla tej konfiguracji: severity * 0.35
            config_score = severity_score

            # Dodaj podobiekct after_normalizing do misconfiguration
            misconfig["after_normalizing"] = {
                "weight": 0.35,
                "final_scoring": config_score,
                "severity_score": severity_score,
            }

    logging.debug("Infrastructure config normalized")


def _normalize_sast_issues(bandit_results: Dict[str, Any]):
    """
    Dodaje after_normalizing do każdego problemu SAST z Bandit
    severity (1-10) * 0.25
    """
    sast_results = bandit_results.get("results", [])

    for target in sast_results:
        vulnerabilities = target.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            # Konwertuj severity na wartość numeryczną (1-10)
            severity_score = _convert_severity_to_numeric(
                vuln.get("Severity", "UNKNOWN")
            )

            # Oblicz score dla tego problemu SAST: severity * 0.25
            sast_score = severity_score

            # Dodaj podobiekct after_normalizing do vulnerability
            vuln["after_normalizing"] = {
                "weight": 0.25,
                "final_scoring": sast_score,
                "severity_score": severity_score,
            }

    logging.debug("SAST issues normalized")


def _extract_cvss_score(vulnerability: Dict[str, Any]) -> float:
    """
    Wyciąga CVSS score z podatności. Sprawdza różne możliwe lokalizacje.
    """
    cvss_data = vulnerability.get("CVSS", {})

    # Próbuj różne możliwe ścieżki do CVSS score
    possible_paths = [
        cvss_data.get("nvd", {}).get("V3Score")
        if isinstance(cvss_data.get("nvd"), dict)
        else None,
        cvss_data.get("nvd", {}).get("V2Score")
        if isinstance(cvss_data.get("nvd"), dict)
        else None,
        cvss_data.get("redhat", {}).get("V3Score")
        if isinstance(cvss_data.get("redhat"), dict)
        else None,
        cvss_data.get("V3Score"),
        cvss_data.get("V2Score"),
        cvss_data.get("BaseScore"),
    ]

    for score in possible_paths:
        if score and isinstance(score, (int, float)):
            return float(score)

    severity = vulnerability.get("Severity", "UNKNOWN").upper()
    severity_to_cvss = {
        "CRITICAL": 90,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "UNKNOWN": 0.0,
    }

    return severity_to_cvss.get(severity, 0.0)


def _convert_severity_to_numeric(severity: str) -> float:
    """
    Konwertuje severity string na wartość numeryczną w przedziale 1-10
    """
    severity_mapping = {
        "CRITICAL": 100,
        "HIGH": 80,
        "MEDIUM": 50,
        "LOW": 20,
        "INFO": 10,
        "UNKNOWN": 00,
    }

    return severity_mapping.get(severity.upper(), 0.0)


def main():
    """Funkcja główna do testowania modułu"""
    import json

    from deployment_scanner.aggregate import aggregate_scan

    try:
        print("Uruchamianie testu normalizacji...")

        # Wykonaj skan
        results = aggregate_scan("../examples/insecure-cloud-app")

        # Normalizuj wyniki
        normalized_results = normalize_scan_results(results)

        # Sprawdź czy dodano after_normalizing do vulnerability
        total_normalized = 0

        # Sprawdź trivy images
        for image_name, image_data in normalized_results.get(
            "trivy_images", {}
        ).items():
            for target in image_data.get("results", []):
                for vuln in target.get("Vulnerabilities", []):
                    if "after_normalizing" in vuln:
                        total_normalized += 1
                        if total_normalized <= 3:  # Pokaż pierwsze 3
                            print(
                                f"Trivy vuln {vuln.get('VulnerabilityID', 'N/A')}: score={vuln['after_normalizing']['final_scoring']:.2f}, weight={vuln['after_normalizing']['weight']}"
                            )

        # Sprawdź trivy misconfig
        for target in normalized_results.get("trivy_misconfig", {}).get("results", []):
            for misconfig in target.get("Misconfigurations", []):
                if "after_normalizing" in misconfig:
                    total_normalized += 1
                    if total_normalized <= 6:  # Pokaż kolejne 3
                        print(
                            f"Trivy misconfig {misconfig.get('ID', 'N/A')}: score={misconfig['after_normalizing']['final_scoring']:.2f}, weight={misconfig['after_normalizing']['weight']}"
                        )

        # Sprawdź bandit
        for target in normalized_results.get("bandit", {}).get("results", []):
            for vuln in target.get("Vulnerabilities", []):
                if "after_normalizing" in vuln:
                    total_normalized += 1
                    if total_normalized <= 9:  # Pokaż kolejne 3
                        print(
                            f"Bandit vuln {vuln.get('VulnerabilityID', 'N/A')}: score={vuln['after_normalizing']['final_scoring']:.2f}, weight={vuln['after_normalizing']['weight']}"
                        )

        print(f"\n✅ Znormalizowano {total_normalized} vulnerability/misconfigurations")

        # Zapisz znormalizowane wyniki
        with open("normalized_results.json", "w", encoding="utf-8") as f:
            json.dump(normalized_results, f, indent=4, ensure_ascii=False)

        print("Znormalizowane wyniki zapisane do: normalized_results.json")

    except Exception as e:
        logging.error(f"Błąd podczas testu: {e}")
        return 1

    return 0
