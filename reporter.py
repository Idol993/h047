import json
import sys
from typing import List, Dict, Tuple
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from config import SEVERITY_RANK


SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bright_red",
}


class Reporter:
    def __init__(self, output_file: str = None, output_format: str = "table"):
        self.output_file = output_file
        self.output_format = output_format
        self.console = Console()

    def generate(self, vulnerabilities: List, image_source: str, packages_count: int):
        if self.output_format == "json":
            self._generate_json(vulnerabilities, image_source, packages_count)
        else:
            self._generate_table(vulnerabilities, image_source, packages_count)

    def _get_output(self):
        if self.output_file and self.output_file != "/dev/stdout":
            return open(self.output_file, "w", encoding="utf-8")
        return sys.stdout

    def _generate_json(self, vulnerabilities: List, image_source: str, packages_count: int):
        report = {
            "image_source": image_source,
            "total_packages_scanned": packages_count,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_summary": self._get_severity_summary(vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }

        f = self._get_output()
        try:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        finally:
            if f is not sys.stdout:
                f.close()

    def _generate_table(self, vulnerabilities: List, image_source: str, packages_count: int):
        if self.output_file and self.output_file != "/dev/stdout":
            console = Console(file=self._get_output(), force_terminal=False)
        else:
            console = self.console

        console.print(f"\n[bold]Container Image Security Scan Report[/bold]")
        console.print(f"Image: [cyan]{image_source}[/cyan]")
        console.print(f"Packages Scanned: {packages_count}")
        console.print(f"Total Vulnerabilities: {len(vulnerabilities)}\n")

        summary = self._get_severity_summary(vulnerabilities)
        summary_table = Table(title="Severity Summary", show_header=True, header_style="bold")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")

        for severity in ["critical", "high", "medium", "low"]:
            count = summary.get(severity, 0)
            color = SEVERITY_COLORS.get(severity, "white")
            summary_table.add_row(
                Text(severity.capitalize(), style=color),
                str(count),
            )

        console.print(summary_table)
        console.print()

        if vulnerabilities:
            vuln_table = Table(
                title="Vulnerabilities",
                show_header=True,
                header_style="bold",
                show_lines=False,
            )
            vuln_table.add_column("CVE ID", style="bold cyan", no_wrap=True)
            vuln_table.add_column("Package", style="magenta")
            vuln_table.add_column("Version", style="yellow")
            vuln_table.add_column("CVSS", justify="right")
            vuln_table.add_column("Severity", justify="center")
            vuln_table.add_column("Description", overflow="fold")

            for vuln in vulnerabilities:
                severity_color = SEVERITY_COLORS.get(vuln.severity, "white")
                vuln_table.add_row(
                    vuln.cve_id,
                    vuln.package_name,
                    vuln.package_version,
                    f"{vuln.cvss_score:.1f}",
                    Text(vuln.severity.capitalize(), style=f"bold {severity_color}"),
                    vuln.description[:80] + "..." if len(vuln.description) > 80 else vuln.description,
                )

            console.print(vuln_table)
        else:
            console.print("[green]No vulnerabilities found.[/green]")

    def _get_severity_summary(self, vulnerabilities: List) -> Dict[str, int]:
        counter = Counter(v.severity for v in vulnerabilities)
        return dict(counter)

    def get_high_risk_count(self, vulnerabilities: List) -> int:
        count = 0
        high_rank = SEVERITY_RANK.get("high", 3)
        for v in vulnerabilities:
            if SEVERITY_RANK.get(v.severity, 1) >= high_rank:
                count += 1
        return count

    def should_fail(self, vulnerabilities: List, threshold: int = 5) -> bool:
        return self.get_high_risk_count(vulnerabilities) > threshold
