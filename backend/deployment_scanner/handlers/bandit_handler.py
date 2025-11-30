from .base_handler import BaseHandler


class BanditHandler(BaseHandler):

    def scan_repo(self) -> dict:
        cmd = ["bandit", "-r", str(self.proj_path), "-f", "json"]

        code, out, err = self.run_cmd(cmd)

        return {
            "tool": "bandit",
            "type": "repo",
            "path": str(self.proj_path),
            "success": code == 0,
            "output_raw": out,
            "errors": err,
            "results": self.parse_json(out),
        }
