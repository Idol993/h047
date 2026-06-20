import json
import sys
import os
from datetime import datetime
from typing import List, Dict, Tuple
from collections import Counter, defaultdict

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

SEVERITY_EMOJI = {
    "low": "🟢",
    "medium": "🟡",
    "high": "🔴",
    "critical": "💥",
}

SOURCE_DISPLAY = {
    "os": "os",
    "python": "PyPI",
    "nodejs": "npm",
    "java": "Maven",
}


class Reporter:
    def __init__(
        self,
        output_file: str = None,
        output_format: str = "table",
        fail_threshold: int = 5,
        ignore_policy=None,
    ):
        self.output_file = output_file
        self.output_format = output_format
        self.fail_threshold = fail_threshold
        self.ignore_policy = ignore_policy
        self.console = Console()

    def generate(
        self,
        vulnerabilities: List,
        image_source: str,
        packages_count: int,
        packages_summary: Dict[str, int] = None,
        scan_warnings: List[str] = None,
        packages_list: List = None,
    ):
        self.active_vulns, self.ignored_vulns = self._split_vulns_by_ignore(vulnerabilities)

        if self.output_format == "json":
            self._generate_json(
                self.active_vulns, self.ignored_vulns, image_source,
                packages_count, packages_summary, scan_warnings
            )
        elif self.output_format == "markdown":
            self._generate_markdown(
                self.active_vulns, self.ignored_vulns, image_source,
                packages_count, packages_summary, scan_warnings
            )
        elif self.output_format == "cyclonedx":
            self._generate_cyclonedx(
                self.active_vulns, image_source,
                packages_count, packages_summary, scan_warnings, packages_list
            )
        else:
            self._generate_table(
                self.active_vulns, self.ignored_vulns, image_source,
                packages_count, packages_summary, scan_warnings
            )

    def _split_vulns_by_ignore(self, vulnerabilities: List) -> Tuple[List, List]:
        if not self.ignore_policy or not self.ignore_policy.has_rules():
            return vulnerabilities, []

        active = []
        ignored = []
        for v in vulnerabilities:
            if self.ignore_policy.is_ignored(
                cve_id=v.cve_id, package_name=v.package_name, severity=v.severity
            ):
                ignored.append(v)
            else:
                active.append(v)
        return active, ignored

    def _get_output(self):
        if self.output_file and self.output_file != "/dev/stdout":
            return open(self.output_file, "w", encoding="utf-8")
        return sys.stdout

    def _source_label(self, source: str) -> str:
        return SOURCE_DISPLAY.get(source, source)

    def _build_summary(
        self, vulnerabilities: List, packages_count: int, packages_summary: Dict[str, int] = None,
        ignored_vulns: List = None,
    ) -> dict:
        by_package: Dict[str, Dict] = defaultdict(
            lambda: {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "cves": [], "source": "os"}
        )

        for v in vulnerabilities:
            pkg_key = f"{v.package_name}@{v.package_version}"
            by_package[pkg_key]["count"] += 1
            by_package[pkg_key][v.severity] += 1
            by_package[pkg_key]["cves"].append(
                {"cve_id": v.cve_id, "cvss_score": v.cvss_score, "severity": v.severity}
            )
            by_package[pkg_key]["source"] = v.source

        by_package_sorted = sorted(
            by_package.items(),
            key=lambda x: (x[1]["critical"] * 1000 + x[1]["high"] * 100 + x[1]["medium"] * 10 + x[1]["low"]),
            reverse=True,
        )

        packages_dict = {}
        for pkg_key, stats in by_package_sorted:
            name, version = pkg_key.rsplit("@", 1)
            packages_dict[pkg_key] = {
                "name": name,
                "version": version,
                "source": self._source_label(stats["source"]),
                "total_vulns": stats["count"],
                "by_severity": {
                    "critical": stats["critical"],
                    "high": stats["high"],
                    "medium": stats["medium"],
                    "low": stats["low"],
                },
                "cves": stats["cves"],
            }

        high_rank = SEVERITY_RANK.get("high", 3)
        high_risk_count = sum(
            1 for v in vulnerabilities if SEVERITY_RANK.get(v.severity, 1) >= high_rank
        )

        by_source: Dict[str, int] = Counter(v.source for v in vulnerabilities)
        by_source_display = {self._source_label(k): v for k, v in by_source.items()}

        ci_summary = {
            "high_risk_count": high_risk_count,
            "fail_threshold": self.fail_threshold,
            "exceeds_threshold": high_risk_count > self.fail_threshold,
            "exit_code": 1 if high_risk_count > self.fail_threshold else 0,
        }

        ignored_summary = None
        if ignored_vulns:
            ignored_by_severity = {
                "critical": sum(1 for v in ignored_vulns if v.severity == "critical"),
                "high": sum(1 for v in ignored_vulns if v.severity == "high"),
                "medium": sum(1 for v in ignored_vulns if v.severity == "medium"),
                "low": sum(1 for v in ignored_vulns if v.severity == "low"),
            }
            ignored_summary = {
                "total_ignored": len(ignored_vulns),
                "by_severity": ignored_by_severity,
            }

        return {
            "total_packages_scanned": packages_count,
            "packages_by_source": packages_summary or {},
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": {
                "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
                "low": sum(1 for v in vulnerabilities if v.severity == "low"),
            },
            "by_source": by_source_display,
            "by_package": packages_dict,
            "ci": ci_summary,
            "ignored": ignored_summary,
        }

    def _generate_json(
        self,
        vulnerabilities: List,
        ignored_vulns: List,
        image_source: str,
        packages_count: int,
        packages_summary: Dict[str, int] = None,
        scan_warnings: List[str] = None,
    ):
        summary = self._build_summary(vulnerabilities, packages_count, packages_summary, ignored_vulns)

        report = {
            "scan_metadata": {
                "image_source": image_source,
                "scan_time": datetime.now().isoformat(),
                "scan_tool": "container-image-security-scanner",
                "version": "4.0",
            },
            "summary": summary,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }

        if ignored_vulns:
            report["ignored_vulnerabilities"] = [v.to_dict() for v in ignored_vulns]

        if self.ignore_policy and self.ignore_policy.has_rules():
            report["ignore_policy"] = {
                "rule_count": self.ignore_policy.rule_count(),
                "rules": [
                    {"type": r[0], "value": r[1]}
                    for r in self.ignore_policy.rules
                ],
            }

        if scan_warnings:
            report["scan_warnings"] = scan_warnings

        f = self._get_output()
        try:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        finally:
            if f is not sys.stdout:
                f.close()

    def _generate_markdown(
        self,
        vulnerabilities: List,
        ignored_vulns: List,
        image_source: str,
        packages_count: int,
        packages_summary: Dict[str, int] = None,
        scan_warnings: List[str] = None,
    ):
        summary = self._build_summary(vulnerabilities, packages_count, packages_summary, ignored_vulns)
        ci = summary["ci"]
        by_severity = summary["by_severity"]

        lines = []
        lines.append("# 🔒 Container Image Security Scan Report")
        lines.append("")
        lines.append(f"**Image**: `{image_source}`")
        lines.append(f"**Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        status_emoji = "❌" if ci["exceeds_threshold"] else "✅"
        status_text = "FAILED" if ci["exceeds_threshold"] else "PASSED"
        status_color = "red" if ci["exceeds_threshold"] else "green"
        lines.append(f"## {status_emoji} CI Status: <span style=\"color:{status_color}\">{status_text}</span>")
        lines.append("")
        lines.append(f"- High+ Risk Vulnerabilities: **{ci['high_risk_count']}** / Threshold: {ci['fail_threshold']}")
        lines.append(f"- Exit Code: `{ci['exit_code']}`")
        lines.append("")

        lines.append("## 📊 Vulnerability Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev.capitalize()} | **{by_severity[sev]}** |")
        lines.append(f"| **Total** | **{len(vulnerabilities)}** |")
        lines.append("")

        if ignored_vulns:
            lines.append("### 🙈 Ignored Vulnerabilities")
            lines.append("")
            ignored_stats = summary.get("ignored", {})
            ignored_by_sev = ignored_stats.get("by_severity", {}) if ignored_stats else {}
            lines.append("| Severity | Ignored |")
            lines.append("|----------|---------|")
            for sev in ["critical", "high", "medium", "low"]:
                count = ignored_by_sev.get(sev, 0)
                lines.append(f"| {sev.capitalize()} | {count} |")
            lines.append(f"| **Total Ignored** | **{len(ignored_vulns)}** |")
            lines.append("")

        if summary.get("by_source"):
            lines.append("### By Source")
            lines.append("")
            lines.append("| Source | Count |")
            lines.append("|--------|-------|")
            for source, count in sorted(summary["by_source"].items()):
                lines.append(f"| {source} | {count} |")
            lines.append("")

        if packages_summary:
            lines.append("## 📦 Packages Scanned")
            lines.append("")
            lines.append("| Source | Count |")
            lines.append("|--------|-------|")
            for source, count in sorted(packages_summary.items()):
                display = self._source_label(source)
                lines.append(f"| {display} | {count} |")
            lines.append(f"| **Total** | **{packages_count}** |")
            lines.append("")

        if summary["by_package"]:
            lines.append("## 🚨 Vulnerabilities by Package")
            lines.append("")
            lines.append("| Package | Version | Source | Critical | High | Medium | Low | Total |")
            lines.append("|---------|---------|--------|----------|------|--------|-----|-------|")
            for pkg_key, stats in summary["by_package"].items():
                if stats["total_vulns"] > 0:
                    bs = stats["by_severity"]
                    lines.append(
                        f"| {stats['name']} | {stats['version']} | {stats['source']} | "
                        f"{bs['critical']} | {bs['high']} | {bs['medium']} | {bs['low']} | "
                        f"**{stats['total_vulns']}** |"
                    )
            lines.append("")

        if vulnerabilities:
            lines.append("## 📋 Vulnerability Details")
            lines.append("")
            lines.append("| CVE ID | Source | Package | Version | CVSS | Severity | Description |")
            lines.append("|--------|--------|---------|---------|------|----------|-------------|")
            for v in vulnerabilities[:50]:
                emoji = SEVERITY_EMOJI.get(v.severity, "")
                desc = v.description.replace("|", "\\|").replace("\n", " ")
                desc = desc[:100] + "..." if len(desc) > 100 else desc
                source_display = self._source_label(v.source)
                lines.append(
                    f"| [{v.cve_id}](https://nvd.nist.gov/vuln/detail/{v.cve_id}) | "
                    f"{source_display} | "
                    f"{v.package_name} | {v.package_version} | "
                    f"{v.cvss_score:.1f} | {emoji} {v.severity.capitalize()} | {desc} |"
                )
            if len(vulnerabilities) > 50:
                lines.append("")
                lines.append(f"> Showing top 50 of {len(vulnerabilities)} vulnerabilities")
            lines.append("")

        if scan_warnings:
            lines.append("## ⚠️ Scan Warnings")
            lines.append("")
            for warning in scan_warnings:
                lines.append(f"- {warning}")
            lines.append("")

        lines.append("---")
        lines.append(f"_Generated by Container Image Security Scanner v4.0_")

        output_content = "\n".join(lines) + "\n"

        f = self._get_output()
        try:
            f.write(output_content)
        finally:
            if f is not sys.stdout:
                f.close()

    def _generate_table(
        self,
        vulnerabilities: List,
        ignored_vulns: List,
        image_source: str,
        packages_count: int,
        packages_summary: Dict[str, int] = None,
        scan_warnings: List[str] = None,
    ):
        if self.output_file and self.output_file != "/dev/stdout":
            console = Console(file=self._get_output(), force_terminal=False)
        else:
            console = self.console

        console.print(f"\n[bold]Container Image Security Scan Report[/bold]")
        console.print(f"Image: [cyan]{image_source}[/cyan]")
        console.print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"Packages Scanned: {packages_count}")

        if packages_summary:
            parts = [f"{self._source_label(k)}={v}" for k, v in sorted(packages_summary.items())]
            console.print(f"Package Sources: {', '.join(parts)}")

        high_risk = self.get_high_risk_count(vulnerabilities)
        exceeds = high_risk > self.fail_threshold
        status = "[bold red]FAILED[/bold red]" if exceeds else "[bold green]PASSED[/bold green]"
        console.print(f"CI Status: {status} (High+ risk: {high_risk}/{self.fail_threshold})")
        console.print(f"Active Vulnerabilities: {len(vulnerabilities)}")
        if ignored_vulns:
            console.print(f"Ignored Vulnerabilities: {len(ignored_vulns)} (not counted in CI status)")
        console.print()

        if scan_warnings:
            console.print("[yellow]Scan Warnings:[/yellow]")
            for warning in scan_warnings:
                console.print(f"  ⚠️  {warning}")
            console.print()

        severity_summary = self._get_severity_summary(vulnerabilities)
        summary_table = Table(title="Severity Summary", show_header=True, header_style="bold")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")

        for severity in ["critical", "high", "medium", "low"]:
            count = severity_summary.get(severity, 0)
            color = SEVERITY_COLORS.get(severity, "white")
            summary_table.add_row(
                Text(severity.capitalize(), style=color),
                str(count),
            )

        console.print(summary_table)
        console.print()

        source_summary = Counter(v.source for v in vulnerabilities)
        if source_summary:
            source_table = Table(title="By Source", show_header=True, header_style="bold")
            source_table.add_column("Source", style="bold")
            source_table.add_column("Count", justify="right")
            for source in sorted(source_summary.keys()):
                source_table.add_row(
                    self._source_label(source),
                    str(source_summary[source]),
                )
            console.print(source_table)
            console.print()

        if vulnerabilities:
            vuln_table = Table(
                title="Vulnerabilities",
                show_header=True,
                header_style="bold",
                show_lines=False,
            )
            vuln_table.add_column("CVE ID", style="bold cyan", no_wrap=True, min_width=16)
            vuln_table.add_column("Source", no_wrap=True, min_width=6, max_width=8)
            vuln_table.add_column("Package", style="magenta", no_wrap=False, min_width=12)
            vuln_table.add_column("Version", style="yellow", no_wrap=True, min_width=10)
            vuln_table.add_column("CVSS", justify="right", min_width=4)
            vuln_table.add_column("Severity", justify="center", min_width=8)
            vuln_table.add_column("Description", overflow="fold", min_width=30)

            for vuln in vulnerabilities:
                severity_color = SEVERITY_COLORS.get(vuln.severity, "white")
                source_display = self._source_label(vuln.source)
                vuln_table.add_row(
                    vuln.cve_id,
                    source_display,
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

    def get_high_risk_count(self, vulnerabilities: List = None) -> int:
        if vulnerabilities is None:
            vulnerabilities = getattr(self, 'active_vulns', [])
        count = 0
        high_rank = SEVERITY_RANK.get("high", 3)
        for v in vulnerabilities:
            if SEVERITY_RANK.get(v.severity, 1) >= high_rank:
                count += 1
        return count

    def should_fail(self, vulnerabilities: List = None, threshold: int = None) -> bool:
        if vulnerabilities is None:
            vulnerabilities = getattr(self, 'active_vulns', [])
        threshold = threshold if threshold is not None else self.fail_threshold
        return self.get_high_risk_count(vulnerabilities) > threshold

    def _generate_cyclonedx(
        self,
        vulnerabilities: List,
        image_source: str,
        packages_count: int,
        packages_summary: Dict[str, int] = None,
        scan_warnings: List[str] = None,
        packages_list: List = None,
    ):
        from datetime import datetime

        components = []
        bom_refs = {}

        all_packages = packages_list or []

        for pkg in all_packages:
            purl = self._make_purl(pkg.name, pkg.version, pkg.source)
            bom_ref = purl
            component = {
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": purl,
                "bom-ref": bom_ref,
            }
            if pkg.source:
                component["properties"] = [
                    {"name": "source", "value": self._source_label(pkg.source)}
                ]
            components.append(component)
            bom_refs[f"{pkg.name}@{pkg.version}"] = bom_ref

        vulns_cyclone = []
        for v in vulnerabilities:
            pkg_key = f"{v.package_name}@{v.package_version}"
            bom_ref = bom_refs.get(pkg_key, v.package_name)

            vuln_entry = {
                "id": v.cve_id,
                "source": {"name": self._source_label(v.source).upper()},
                "ratings": [
                    {
                        "severity": v.severity,
                        "score": v.cvss_score,
                        "method": "CVSSv31",
                    }
                ],
                "description": v.description,
                "affects": [{"ref": bom_ref}],
            }
            if v.fix_version:
                vuln_entry["fixes"] = [{"version": v.fix_version}]
            vulns_cyclone.append(vuln_entry)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "container-image-security-scanner",
                        "name": "scanner",
                        "version": "4.0",
                    }
                ],
                "component": {
                    "type": "container",
                    "name": image_source,
                },
            },
            "components": components,
            "vulnerabilities": vulns_cyclone,
        }

        if scan_warnings:
            bom["metadata"]["properties"] = [
                {"name": f"warning_{i}", "value": w}
                for i, w in enumerate(scan_warnings)
            ]

        f = self._get_output()
        try:
            json.dump(bom, f, indent=2, ensure_ascii=False)
            f.write("\n")
        finally:
            if f is not sys.stdout:
                f.close()

    def _make_purl(self, name: str, version: str, source: str) -> str:
        from urllib.parse import quote

        if source == "python":
            return f"pkg:pypi/{quote(name)}@{version}"
        elif source == "nodejs":
            return f"pkg:npm/{quote(name)}@{version}"
        elif source == "java":
            if ":" in name:
                gid, aid = name.split(":", 1)
                return f"pkg:maven/{quote(gid)}/{quote(aid)}@{version}"
            return f"pkg:maven/{quote(name)}@{version}"
        elif source == "os":
            return f"pkg:generic/{quote(name)}@{version}"
        else:
            return f"pkg:generic/{quote(name)}@{version}"
