import logging
import subprocess
import sys
from pathlib import Path

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT


log = logging.getLogger(__name__)


class Kspnreport(Report):
    """Generate a standalone KSPN-style report after normal CAPE reporting completes."""

    order = 9999

    def run(self, results):
        task_id = self.task.get("id")
        script_path = Path(CUCKOO_ROOT) / "utils" / "kspn_report.py"
        command = [sys.executable, str(script_path), "--id", str(task_id)]

        analyst = self.options.get("analyst", "")
        org = self.options.get("org", "")
        if analyst:
            command.extend(["--analyst", str(analyst)])
        if org:
            command.extend(["--org", str(org)])
        if self.options.get("all_artifacts"):
            command.append("--all-artifacts")
        if self.options.get("json_summary"):
            command.append("--json-summary")
        if not self.options.get("html", True):
            command.append("--no-html")

        try:
            completed = subprocess.run(
                command,
                cwd=CUCKOO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:
            log.warning("KSPN report generation failed for Task #%s: %s", task_id, exc)
            return

        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            stdout = completed.stdout.strip()
            detail = stderr or stdout or "no output"
            log.warning("KSPN report generation failed for Task #%s: %s", task_id, detail)
            return

        output = completed.stdout.strip()
        if output:
            log.info("KSPN report generation succeeded for Task #%s: %s", task_id, output.replace("\n", " | "))
        else:
            log.info("KSPN report generation succeeded for Task #%s", task_id)
