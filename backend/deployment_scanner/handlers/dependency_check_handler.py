from .base_handler import BaseHandler


class DependencyCheckHandler(BaseHandler):

    def scan(self) -> dict:
        cmd = [
            "dependency-check.sh",
            "--project",
            "deployment_scan",
            "--scan",
            str(self.proj_path),
            "--format",
            "JSON",
            "--out",
            "-",
        ]

        code, out, err = self.run_cmd(cmd)

        return {
            "tool": "dependency-check",
            "type": "sast",
            "path": str(self.proj_path),
            "success": code == 0,
            "output_raw": out,
            "errors": err,
            "results": self.parse_json(out),
        }
