import os

from deployment_scanner.handlers import bandit_remediate

HANDLED_VULNERABILITIES_BANDIT = ["B105"]


def remediate_repo(scan_results, proj_path: str, remediated_dir):
    if scan_results["bandit"] != {}:
        _remediate_bandit(scan_results, proj_path, remediated_dir)


def _remediate_bandit(scan_results, proj_path, remediated_dir):
    for result in scan_results["bandit"]["results"]:
        processed_file = None
        file_contents = []

        for vuln in result["Vulnerabilities"]:
            current_file = vuln["File"]
            print("handling file:", current_file)

            # Jeśli to nowy plik
            if processed_file is None or current_file != processed_file:
                # Zapisz poprzedni plik (jeśli był)
                if processed_file is not None:
                    output_path = os.path.join(
                        remediated_dir, os.path.basename(processed_file)
                    )
                    with open(output_path, "w") as f:
                        f.writelines(file_contents)

                # Wczytaj nowy plik
                processed_file = current_file
                with open(processed_file, "r") as f:
                    file_contents = f.readlines()

            # Napraw podatność
            if vuln["VulnerabilityID"] in HANDLED_VULNERABILITIES_BANDIT:
                file_contents = _bandit_vulnerability_controller(vuln, file_contents)

        # Zapisz ostatni plik
        if processed_file is not None:
            output_path = os.path.join(remediated_dir, os.path.basename(processed_file))
            with open(output_path, "w") as f:
                f.writelines(file_contents)


def _bandit_vulnerability_controller(vuln_info, file_contents):
    if vuln_info["VulnerabilityID"] == "B105":
        return bandit_remediate.handle_b105(vuln_info, file_contents)
