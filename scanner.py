import sys
import click

from unpacker import ImageUnpacker
from vulndb import VulnDB
from reporter import Reporter


@click.group()
def cli():
    pass


@cli.command()
@click.argument("image")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    help="Output format (table, json, or markdown)",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path, use /dev/stdout for standard output",
    show_default=True,
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity level to report",
    show_default=True,
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Offline mode, only query local cache",
)
@click.option(
    "--cache-db",
    default="cache.db",
    help="Path to SQLite cache database",
    show_default=True,
)
@click.option(
    "--fail-threshold",
    type=int,
    default=5,
    help="Exit with code 1 if high+ vulnerabilities exceed this count",
    show_default=True,
)
def scan(
    image,
    output_format,
    output,
    severity_threshold,
    offline,
    cache_db,
    fail_threshold,
):
    """Scan a container image for vulnerabilities.

    IMAGE can be a Docker image name (e.g., nginx:latest) or a local tar file.
    """
    try:
        click.echo(f"Scanning image: {image}")
        unpacker = ImageUnpacker()
        scan_result = unpacker.scan(image)
        packages = scan_result.packages
        scan_warnings = scan_result.warnings

        package_summary = scan_result.package_count_by_source()
        summary_parts = [f"{k}={v}" for k, v in sorted(package_summary.items())]
        click.echo(f"Found {len(packages)} packages ({', '.join(summary_parts)})")

        if not packages:
            click.echo("Warning: No packages found in image.")
            if scan_warnings:
                for warning in scan_warnings:
                    click.echo(f"  - {warning}")
            return

        vulndb = VulnDB(db_path=cache_db, offline=offline)
        click.echo(f"Querying vulnerabilities (threshold: {severity_threshold})...")
        vulnerabilities = vulndb.scan_packages(packages, severity_threshold)
        click.echo(f"Found {len(vulnerabilities)} vulnerabilities")

        reporter = Reporter(
            output_file=output,
            output_format=output_format,
            fail_threshold=fail_threshold,
        )
        reporter.generate(
            vulnerabilities,
            image,
            len(packages),
            package_summary,
            scan_warnings,
        )

        high_risk_count = reporter.get_high_risk_count(vulnerabilities)
        if reporter.should_fail(vulnerabilities, fail_threshold):
            click.echo(
                f"\nERROR: {high_risk_count} high+ risk vulnerabilities found "
                f"exceed threshold of {fail_threshold}. "
                f"Exiting with code 1.",
                err=True,
            )
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(2)


@cli.command()
@click.option(
    "--cache-db",
    default="cache.db",
    help="Path to SQLite cache database",
    show_default=True,
)
def cache_info(cache_db):
    """Show information about the vulnerability cache database."""
    import sqlite3
    from rich.console import Console
    from rich.table import Table

    try:
        conn = sqlite3.connect(cache_db)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total = cursor.fetchone()[0]

        cursor.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        )
        by_severity = cursor.fetchall()

        cursor.execute(
            "SELECT COUNT(DISTINCT package_name || '|' || version) "
            "FROM vulnerabilities"
        )
        unique_packages = cursor.fetchone()[0]

        conn.close()

        sev_colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }

        click.echo(f"Cache Database: {cache_db}")
        click.echo(f"Total vulnerabilities cached: {total}")
        click.echo(f"Unique packages: {unique_packages}")

        console = Console()
        table = Table(title="By Severity", show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")

        for severity, count in by_severity:
            color = sev_colors.get(severity, "white")
            table.add_row(
                f"[{color}]{severity.capitalize()}[/{color}]",
                str(count),
            )

        console.print(table)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)


@cli.command()
@click.option(
    "--cache-db",
    default="cache.db",
    help="Path to SQLite cache database",
    show_default=True,
)
def clear_cache(cache_db):
    """Clear the vulnerability cache database."""
    import os

    try:
        if os.path.exists(cache_db):
            os.remove(cache_db)
            click.echo(f"Cache database {cache_db} cleared.")
        else:
            click.echo(f"Cache database {cache_db} does not exist.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    cli()
