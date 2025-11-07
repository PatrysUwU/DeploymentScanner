import subprocess


class BanditHandler:
    def __init__(self, path: str = ""):
        self.path = path

    def scan_repo(self, output_path: str = "bandit_output.json"):
        cmd = [
            "bandit",
            "-r",
            ".",
            "-x",
            "./.venv",
            "--format",
            "json",
            "--output",
            output_path,
        ]
        subprocess.run(cmd, capture_output=True, text=True)
        print(f"Wynik zapisany do pliku: {output_path}")
