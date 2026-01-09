import logging
import re
from typing import Any, Dict, Optional

logging.basicConfig(level="DEBUG")


def contextualize_scan_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dodaje kontekst do wyników skanowania na podstawie konfiguracji kontenerów.

    Głównie sprawdza czy są otwarte porty i modyfikuje context_wage dla podatności
    z wektorem ataku sieciowego gdy porty są zamknięte.

    Args:
        results: Wyniki z aggregate_scan (po normalize_scan_results)

    Returns:
        Wyniki z dodanym context_wage do odpowiednich vulnerability
    """
    logging.info("Rozpoczynanie kontekstualizacji wyników skanowania")

    # Dodaj kontekst do skanów obrazów
    _contextualize_image_scans(results.get("trivy_images", {}))

    logging.info("Kontekstualizacja zakończona")
    return results


def _contextualize_image_scans(trivy_images: Dict[str, Any]):
    """
    Dodaje kontekst do skanów obrazów na podstawie konfiguracji kontenerów
    """
    for image_name, image_data in trivy_images.items():
        # Sprawdź czy są otwarte porty w konfiguracji kontenera
        container_config = image_data.get("container_config", {})
        has_open_ports = _check_for_open_ports(container_config)

        logging.debug(f"Obraz {image_name}: otwarte porty = {has_open_ports}")

        # Przetworz wszystkie vulnerability w tym obrazie
        image_results = image_data.get("results", [])
        for target in image_results:
            vulnerabilities = target.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                # Dodaj kontekst do każdej podatności
                _add_vulnerability_context(vuln, has_open_ports, image_name)


def _check_for_open_ports(container_config: Dict[str, Any]) -> bool:
    """
    Sprawdza czy kontener ma otwarte porty na podstawie konfiguracji

    Args:
        container_config: Konfiguracja kontenera z docker-compose

    Returns:
        True jeśli są otwarte porty, False w przeciwnym razie
    """
    ports = container_config.get("ports", [])

    # Jeśli brak konfiguracji portów, uznaj że są zamknięte
    if not ports:
        return False

    # Sprawdź czy są jakiekolwiek zmapowane porty
    for port in ports:
        if isinstance(port, str) and port.strip():
            # Port jest skonfigurowany - uznaj że jest otwarty
            return True

    return False


def _add_vulnerability_context(
    vuln: Dict[str, Any], has_open_ports: bool, image_name: str
):
    """
    Dodaje kontekst do pojedynczej podatności

    Args:
        vuln: Słownik vulnerability
        has_open_ports: Czy kontener ma otwarte porty
        image_name: Nazwa obrazu (dla logowania)
    """
    # Domyślnie context_wage = 1.0 (bez modyfikacji)
    context_wage = 1.0

    # Sprawdź wektor ataku z CVSS
    attack_vector = _extract_attack_vector(vuln)

    if attack_vector == "NETWORK" and not has_open_ports:
        context_wage = 0.1
        logging.debug(
            f"Vulnerability {vuln.get('VulnerabilityID', 'N/A')} w obrazie {image_name}: "
            f"wektor NETWORK ale zamknięte porty - context_wage = {context_wage}"
        )

    # Dodaj context_wage do vulnerability
    vuln["context_wage"] = context_wage


def _extract_attack_vector(vuln: Dict[str, Any]) -> Optional[str]:
    """
    Wyciąga wektor ataku z CVSS string vulnerability

    Args:
        vuln: Słownik vulnerability

    Returns:
        Wektor ataku ("NETWORK", "ADJACENT", "LOCAL", "PHYSICAL") lub None
    """
    # Sprawdź różne możliwe lokalizacje CVSS
    cvss_data = vuln.get("CVSS", {})

    # Możliwe ścieżki do CVSS vector string
    possible_vectors = []

    # CVSS v3 vector strings
    if isinstance(cvss_data.get("nvd"), dict):
        nvd_data = cvss_data["nvd"]
        if "V3Vector" in nvd_data:
            possible_vectors.append(nvd_data["V3Vector"])

    if isinstance(cvss_data.get("redhat"), dict):
        redhat_data = cvss_data["redhat"]
        if "V3Vector" in redhat_data:
            possible_vectors.append(redhat_data["V3Vector"])

    # Inne możliwe lokalizacje
    if "V3Vector" in cvss_data:
        possible_vectors.append(cvss_data["V3Vector"])
    if "Vector" in cvss_data:
        possible_vectors.append(cvss_data["Vector"])

    # Parsuj vector string w poszukiwaniu Attack Vector (AV)
    for vector_string in possible_vectors:
        if isinstance(vector_string, str):
            attack_vector = _parse_attack_vector_from_cvss(vector_string)
            if attack_vector:
                return attack_vector

    return None


def _parse_attack_vector_from_cvss(cvss_vector: str) -> Optional[str]:
    """
    Parsuje CVSS vector string w poszukiwaniu Attack Vector (AV)

    Przykład CVSS v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Args:
        cvss_vector: CVSS vector string

    Returns:
        Wektor ataku w pełnej nazwie lub None
    """
    if not cvss_vector:
        return None

    # Znajdź AV (Attack Vector) w vector string
    av_match = re.search(r"AV:([NALP])", cvss_vector)

    if av_match:
        av_code = av_match.group(1)
        # Mapowanie kodów na pełne nazwy
        av_mapping = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
        return av_mapping.get(av_code)

    return None


def main():
    """Funkcja główna do testowania modułu"""
    import json

    from deployment_scanner.aggregate import aggregate_scan
    from deployment_scanner.normalize import normalize_scan_results

    try:
        print("=== Test kontekstualizacji ===")

        # Wykonaj pełny pipeline: scan -> normalize -> contextualize
        results = aggregate_scan("../examples/insecure-cloud-app")
        normalized_results = normalize_scan_results(results)
        contextualized_results = contextualize_scan_results(normalized_results)

        # Sprawdź wyniki kontekstualizacji
        print("\n🔍 Sprawdzenie context_wage:")

        total_vulnerabilities = 0
        network_vulnerabilities = 0
        reduced_wage_vulnerabilities = 0

        trivy_images = contextualized_results.get("trivy_images", {})
        for image_name, image_data in trivy_images.items():
            container_config = image_data.get("container_config", {})
            has_ports = bool(container_config.get("ports", []))

            print(f"\n📦 Obraz: {image_name}")
            print(f"   Otwarte porty: {has_ports}")
            print(f"   Porty: {container_config.get('ports', [])}")

            for target in image_data.get("results", []):
                vulnerabilities = target.get("Vulnerabilities", [])
                total_vulnerabilities += len(vulnerabilities)

                for vuln in vulnerabilities[:3]:  # Pokaż pierwsze 3
                    vuln_id = vuln.get("VulnerabilityID", "N/A")
                    context_wage = vuln.get("context_wage", "N/A")

                    # Sprawdź wektor ataku
                    attack_vector = _extract_attack_vector(vuln)

                    if attack_vector == "NETWORK":
                        network_vulnerabilities += 1

                    if context_wage == 0.1:
                        reduced_wage_vulnerabilities += 1

                    print(
                        f"     • {vuln_id}: AV={attack_vector}, context_wage={context_wage}"
                    )

        print("\n📊 Podsumowanie:")
        print(f"   Wszystkie vulnerability: {total_vulnerabilities}")
        print(f"   Z wektorem NETWORK: {network_vulnerabilities}")
        print(f"   Ze zredukowaną wagą (0.1): {reduced_wage_vulnerabilities}")

        # Zapisz wyniki
        with open("contextualized_results.json", "w", encoding="utf-8") as f:
            json.dump(contextualized_results, f, indent=4, ensure_ascii=False)

        print("\nWyniki zapisane do: contextualized_results.json")

    except Exception as e:
        logging.error(f"Błąd podczas testu: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
