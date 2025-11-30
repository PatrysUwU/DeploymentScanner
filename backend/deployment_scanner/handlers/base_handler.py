import subprocess
import json
from pathlib import Path


class BaseHandler:
    def __init__(self, proj_path: str):
        self.proj_path = Path(proj_path)

    def run_cmd(self, cmd: list[str]) -> tuple[int, str, str]:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            out, err = proc.communicate()
            return proc.returncode, out, err
        except Exception as e:
            return -1, "", str(e)

    def parse_json(self, text: str):
        try:
            return json.loads(text)
        except Exception:
            return None
