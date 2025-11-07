import subprocess


class TrivyHandler:
    def __init__(self, path: str = ""):
        self.path = path

    def scan_image(self, image: str, output_path: str = "trivy_output.json"):
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--output",
            output_path,
            image,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Skan Trivy zakończył się błędem:")
            print(result.stderr)
        else:
            print(f"Wynik zapisany do pliku: {output_path}")
