import json
import logging

from deployment_scanner import aggregate, contextualize, normalize

logging.basicConfig(level="DEBUG")


def scan(proj_path: str) -> dict:
    results = aggregate.aggregate_scan(proj_path)
    normalized_results = normalize.normalize_scan_results(results)
    contextualized_results = contextualize.contextualize_scan_results(
        normalized_results
    )

    # Oblicz końcowy wynik bezpieczeństwa
    security_score = _calculate_security_score(contextualized_results)
    contextualized_results["final_security_score"] = security_score

    with open("scan_results.json", "w") as f:
        json.dump(contextualized_results, f, indent=4, ensure_ascii=False)

    return contextualized_results


def _calculate_security_score(results: dict) -> float:
    """
    Oblicza końcowy wynik bezpieczeństwa aplikacji na podstawie wzoru:
    suma(vulnerability["after_normalizing"]["final_scoring"] * context_wage) / suma(weight)

    Args:
        results: Wyniki skanowania po normalizacji i kontekstualizacji

    Returns:
        Końcowy wynik bezpieczeństwa
    """
    total_weighted_score = 0.0
    total_weight = 0.0

    # Scores per category
    bandit_score = 0.0
    trivy_images_score = 0.0
    trivy_misconfig_score = 0.0
    trivy_images_weight = 0.0
    trivy_misconfig_weight = 0.0
    bandit_weight = 0.0

    # 1. Trivy Image Vulnerabilities
    trivy_images = results.get("trivy_images", {})
    for image_name, image_data in trivy_images.items():
        for target in image_data.get("results", []):
            for vuln in target.get("Vulnerabilities", []):
                if "after_normalizing" in vuln:
                    after_norm = vuln["after_normalizing"]
                    final_scoring = after_norm.get("final_scoring", 0.0)
                    weight = after_norm.get("weight", 0.0)
                    context_wage = vuln.get("context_wage", 1.0)

                    weighted_score = final_scoring * context_wage
                    total_weighted_score += weighted_score
                    total_weight += weight
                    trivy_images_weight += weight
                    trivy_images_score += weighted_score

    # 2. Trivy Misconfiguration
    trivy_misconfig = results.get("trivy_misconfig", {})
    for target in trivy_misconfig.get("results", []):
        for misconfig in target.get("Misconfigurations", []):
            if "after_normalizing" in misconfig:
                after_norm = misconfig["after_normalizing"]
                final_scoring = after_norm.get("final_scoring", 0.0)
                weight = after_norm.get("weight", 0.0)
                context_wage = misconfig.get("context_wage", 1.0)

                weighted_score = final_scoring * context_wage
                total_weighted_score += weighted_score
                total_weight += weight
                trivy_misconfig_weight += weight
                trivy_misconfig_score += weighted_score

    # 3. Bandit SAST Issues
    bandit_results = results.get("bandit", {})
    for target in bandit_results.get("results", []):
        for vuln in target.get("Vulnerabilities", []):
            if "after_normalizing" in vuln:
                after_norm = vuln["after_normalizing"]
                final_scoring = after_norm.get("final_scoring", 0.0)
                weight = after_norm.get("weight", 0.0)
                context_wage = vuln.get("context_wage", 1.0)

                weighted_score = final_scoring * context_wage
                total_weighted_score += weighted_score
                total_weight += weight
                bandit_weight += weight
                bandit_score += weighted_score

    # Oblicz końcowy wynik
    if total_weight > 0:
        risk_score = total_weighted_score / total_weight
    else:
        risk_score = 0.0

    security_score = 100 - risk_score

    # Oblicz proporcjonalny wkład każdej kategorii do końcowego risk_score
    if total_weight > 0:
        bandit_risk_contribution = (
            (bandit_score / total_weight) if bandit_weight > 0 else 0.0
        )
        trivy_images_risk_contribution = (
            (trivy_images_score / total_weight) if trivy_images_weight > 0 else 0.0
        )
        trivy_misconfig_risk_contribution = (
            (trivy_misconfig_score / total_weight)
            if trivy_misconfig_weight > 0
            else 0.0
        )
    else:
        bandit_risk_contribution = 0.0
        trivy_images_risk_contribution = 0.0
        trivy_misconfig_risk_contribution = 0.0

    # Add risk_scores to summary
    if "summary" not in results:
        results["summary"] = {}

    results["summary"]["risk_scores"] = {
        "bandit": bandit_risk_contribution,
        "trivy_images": trivy_images_risk_contribution,
        "trivy_misconfig": trivy_misconfig_risk_contribution,
    }

    logging.info(
        f"Security score: {security_score:.2f} (total_weighted: {total_weighted_score:.2f}, total_weight: {total_weight:.2f})"
    )
    return security_score
