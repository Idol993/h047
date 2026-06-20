import io
import tarfile
import tempfile
import os
import sys
import json
import sqlite3
from io import StringIO

sys.path.insert(0, os.path.dirname(__file__))

from unpacker import ImageUnpacker, Package, ScanResult
from vulndb import VulnDB, Vulnerability, get_severity_from_score
from reporter import Reporter, SOURCE_DISPLAY


def test_scan_result_class():
    print("Testing ScanResult class...")
    pkgs = [
        Package("bash", "5.1", "os"),
        Package("requests", "2.31.0", "python"),
        Package("express", "4.18.2", "nodejs"),
    ]
    warnings = ["Test warning"]
    result = ScanResult(packages=pkgs, warnings=warnings)

    assert result.has_packages() == True
    counts = result.package_count_by_source()
    assert counts["os"] == 1
    assert counts["python"] == 1
    assert counts["nodejs"] == 1
    assert len(result.warnings) == 1

    empty_result = ScanResult(packages=[])
    assert empty_result.has_packages() == False
    print("  OK")


def test_layer_merge_dpkg():
    print("Testing layer merge for dpkg (upgrade across layers)...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": ["layer0/layer.tar", "layer1/layer.tar"]}
            ])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            layer0_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer0_bytes, mode="w") as layer_tar:
                dpkg_v1 = "Package: openssl\nVersion: 1.1.1\nStatus: install ok installed\n\nPackage: bash\nVersion: 5.0\nStatus: install ok installed\n"
                info2 = tarfile.TarInfo(name="var/lib/dpkg/status")
                info2.size = len(dpkg_v1)
                layer_tar.addfile(info2, io.BytesIO(dpkg_v1.encode()))
            layer0_bytes.seek(0)

            info3 = tarfile.TarInfo(name="layer0/layer.tar")
            info3.size = len(layer0_bytes.getvalue())
            tar.addfile(info3, layer0_bytes)

            layer1_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer1_bytes, mode="w") as layer_tar:
                dpkg_v2 = "Package: openssl\nVersion: 3.0.2\nStatus: install ok installed\n\nPackage: bash\nVersion: 5.0\nStatus: install ok installed\n\nPackage: curl\nVersion: 7.88.0\nStatus: install ok installed\n"
                info4 = tarfile.TarInfo(name="var/lib/dpkg/status")
                info4.size = len(dpkg_v2)
                layer_tar.addfile(info4, io.BytesIO(dpkg_v2.encode()))
            layer1_bytes.seek(0)

            info5 = tarfile.TarInfo(name="layer1/layer.tar")
            info5.size = len(layer1_bytes.getvalue())
            tar.addfile(info5, layer1_bytes)

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        pkg_dict = {p.name: p.version for p in result.packages if p.source == "os"}
        assert "openssl" in pkg_dict, f"openssl not found in {pkg_dict}"
        assert pkg_dict["openssl"] == "3.0.2", f"openssl version should be 3.0.2 (upgraded), got {pkg_dict['openssl']}"
        assert "curl" in pkg_dict, f"curl should be added by layer1, got {pkg_dict}"
        assert "bash" in pkg_dict, f"bash should remain from layer1, got {pkg_dict}"

        total_pkgs = len(pkg_dict)
        assert total_pkgs == 3, f"Expected 3 unique packages after merge, got {total_pkgs}: {pkg_dict}"

        print(f"  OK - openssl upgraded 1.1.1 -> 3.0.2, bash preserved, curl added, no duplicates")
    finally:
        os.unlink(tar_path)


def test_rpm_multiple_paths():
    print("Testing RPM multiple database paths...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": ["layer0/layer.tar"]}
            ])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            db_bytes = _create_rpm_sqlite_db()

            layer0_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer0_bytes, mode="w") as layer_tar:
                info2 = tarfile.TarInfo(name="usr/lib/sysimage/rpm/rpmdb.sqlite")
                info2.size = len(db_bytes)
                layer_tar.addfile(info2, io.BytesIO(db_bytes))
            layer0_bytes.seek(0)

            info3 = tarfile.TarInfo(name="layer0/layer.tar")
            info3.size = len(layer0_bytes.getvalue())
            tar.addfile(info3, layer0_bytes)

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        rpm_pkgs = [p for p in result.packages if p.source == "os"]
        assert len(rpm_pkgs) >= 2, f"Expected at least 2 RPM packages, got {len(rpm_pkgs)}"
        pkg_names = [p.name for p in rpm_pkgs]
        assert "bash" in pkg_names, f"bash not found in {pkg_names}"
        print(f"  OK - found {len(rpm_pkgs)} packages from /usr/lib/sysimage/rpm/rpmdb.sqlite")
    finally:
        os.unlink(tar_path)


def _create_rpm_sqlite_db() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE Packages (
            Name TEXT,
            Version TEXT,
            Release TEXT
        )
    """)
    cursor.execute("INSERT INTO Packages VALUES ('bash', '5.1', '8.el9')")
    cursor.execute("INSERT INTO Packages VALUES ('openssl-libs', '3.0.7', '2.el9')")
    conn.commit()
    conn.close()
    with open(db_path, "rb") as f:
        data = f.read()
    os.unlink(db_path)
    return data


def test_rpm_bdb_format_warning():
    print("Testing RPM BDB format precise warning...")
    unpacker = ImageUnpacker()
    bdb_header = b"\x00\x06\x15\x61" + b"\x00" * 100
    packages = unpacker._parse_rpm_packages(bdb_header, "test", "var/lib/rpm/Packages")
    assert len(packages) == 0
    warning_found = False
    for w in unpacker.warnings:
        if "Berkeley DB" in w and "RHEL 7" in w:
            warning_found = True
            assert "var/lib/rpm/Packages" in w, f"Warning should mention path: {w}"
            break
    assert warning_found, f"Expected BDB warning with path, got: {unpacker.warnings}"
    print("  OK - BDB warning includes path and specific guidance")


def test_rpm_ndb_format_warning():
    print("Testing RPM NDB format precise warning...")
    unpacker = ImageUnpacker()
    ndb_header = b"RPM\x00NDBC" + b"\x00" * 100
    packages = unpacker._parse_rpm_packages(ndb_header, "test", "usr/lib/sysimage/rpm/Packages")
    assert len(packages) == 0
    warning_found = False
    for w in unpacker.warnings:
        if "NDB" in w and "RHEL 9" in w:
            warning_found = True
            assert "usr/lib/sysimage/rpm/Packages" in w
            break
    assert warning_found, f"Expected NDB warning with path, got: {unpacker.warnings}"
    print("  OK - NDB warning includes path and specific guidance")


def test_rpm_unrecognized_format_warning():
    print("Testing RPM unrecognized format precise warning...")
    unpacker = ImageUnpacker()
    unknown_data = b"\xDE\xAD\xBE\xEF" * 50
    packages = unpacker._parse_rpm_packages(unknown_data, "test", "var/lib/rpm/Packages")
    assert len(packages) == 0
    warning_found = False
    for w in unpacker.warnings:
        if "unrecognized" in w and "magic:" in w:
            warning_found = True
            assert "var/lib/rpm/Packages" in w
            break
    assert warning_found, f"Expected unrecognized format warning, got: {unpacker.warnings}"
    print("  OK - unrecognized format warning includes path, size and magic bytes")


def test_osv_ecosystem_routing():
    print("Testing OSV ecosystem routing...")
    from config import OSV_ECOSYSTEM_MAP

    assert OSV_ECOSYSTEM_MAP["python"] == "PyPI"
    assert OSV_ECOSYSTEM_MAP["nodejs"] == "npm"
    assert OSV_ECOSYSTEM_MAP["java"] == "Maven"

    from vulndb import VulnDB
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        vulndb = VulnDB(db_path=db_path, offline=True)
        assert vulndb.offline == True

        test_vulns_python = [
            Vulnerability(
                cve_id="CVE-2023-0001",
                cvss_score=7.5,
                severity="high",
                description="PyPI vulnerability",
                fix_version="2.32.0",
                package_name="requests",
                package_version="2.31.0",
                source="python",
            )
        ]
        vulndb._cache_vulns("requests", "2.31.0", test_vulns_python)
        cached = vulndb._get_cached("requests", "2.31.0")
        assert len(cached) == 1
        assert cached[0].source == "python"

        test_vulns_npm = [
            Vulnerability(
                cve_id="CVE-2023-0002",
                cvss_score=9.8,
                severity="critical",
                description="npm vulnerability",
                fix_version="4.18.3",
                package_name="express",
                package_version="4.18.2",
                source="nodejs",
            )
        ]
        vulndb._cache_vulns("express", "4.18.2", test_vulns_npm)
        cached = vulndb._get_cached("express", "4.18.2")
        assert len(cached) == 1
        assert cached[0].source == "nodejs"

        print("  OK - OSV ecosystem routing correctly caches with source")
    finally:
        os.unlink(db_path)


def test_osv_query_payload():
    print("Testing OSV query payload construction...")
    from config import OSV_ECOSYSTEM_MAP

    for source, ecosystem in OSV_ECOSYSTEM_MAP.items():
        payload = {
            "version": "1.0.0",
            "package": {
                "name": "testpkg",
                "ecosystem": ecosystem,
            }
        }
        assert payload["package"]["ecosystem"] in ["PyPI", "npm", "Maven"]
    print(f"  OK - all ecosystems mapped: {OSV_ECOSYSTEM_MAP}")


def test_vulnerability_source_in_dict():
    print("Testing Vulnerability.to_dict() includes source...")
    v = Vulnerability(
        cve_id="CVE-2023-0001",
        cvss_score=7.5,
        severity="high",
        description="test",
        fix_version="1.0.1",
        package_name="requests",
        package_version="2.31.0",
        source="python",
    )
    d = v.to_dict()
    assert "source" in d
    assert d["source"] == "python"

    v2 = Vulnerability(
        cve_id="CVE-2023-0002",
        cvss_score=9.8,
        severity="critical",
        source="nodejs",
    )
    d2 = v2.to_dict()
    assert d2["source"] == "nodejs"

    v3 = Vulnerability(
        cve_id="CVE-2023-0003",
        cvss_score=5.0,
        severity="medium",
        source="os",
    )
    d3 = v3.to_dict()
    assert d3["source"] == "os"
    print("  OK - source field present in all Vulnerability dicts")


def test_reporter_json_with_source():
    print("Testing reporter JSON output with source field...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="OS vuln",
            package_name="openssl",
            package_version="1.1.1",
            source="os",
        ),
        Vulnerability(
            cve_id="CVE-2023-0002",
            cvss_score=9.8,
            severity="critical",
            description="PyPI vuln",
            package_name="requests",
            package_version="2.31.0",
            source="python",
        ),
        Vulnerability(
            cve_id="CVE-2023-0003",
            cvss_score=5.0,
            severity="medium",
            description="npm vuln",
            package_name="express",
            package_version="4.18.2",
            source="nodejs",
        ),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="json", fail_threshold=5)

    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "test:latest", 10, {"os": 3, "python": 2, "nodejs": 5})
        output = captured.getvalue()
        data = json.loads(output)

        assert data["scan_metadata"]["version"] == "3.0"

        for v in data["vulnerabilities"]:
            assert "source" in v, f"source missing in vulnerability: {v}"

        assert data["vulnerabilities"][0]["source"] == "os"
        assert data["vulnerabilities"][1]["source"] == "python"
        assert data["vulnerabilities"][2]["source"] == "nodejs"

        summary = data["summary"]
        assert "by_source" in summary
        assert summary["by_source"]["os"] == 1
        assert summary["by_source"]["PyPI"] == 1
        assert summary["by_source"]["npm"] == 1

        for pkg_key, stats in summary["by_package"].items():
            assert "source" in stats, f"source missing in by_package entry: {pkg_key}"

        print("  OK - JSON vulnerabilities have source, summary has by_source")
    finally:
        sys.stdout = old_stdout


def test_reporter_markdown_with_source():
    print("Testing reporter Markdown output with source column...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="PyPI vuln",
            package_name="requests",
            package_version="2.31.0",
            source="python",
        ),
        Vulnerability(
            cve_id="CVE-2023-0002",
            cvss_score=9.8,
            severity="critical",
            description="npm vuln",
            package_name="express",
            package_version="4.18.2",
            source="nodejs",
        ),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="markdown", fail_threshold=1)

    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "myapp:latest", 10, {"os": 5, "python": 2, "nodejs": 3})
        output = captured.getvalue()

        assert "| Source |" in output
        assert "PyPI" in output
        assert "npm" in output
        assert "By Source" in output
        assert "v3.0" in output

        print("  OK - Markdown includes Source column and By Source section")
    finally:
        sys.stdout = old_stdout


def test_source_display_mapping():
    print("Testing source display mapping...")
    assert SOURCE_DISPLAY["os"] == "os"
    assert SOURCE_DISPLAY["python"] == "PyPI"
    assert SOURCE_DISPLAY["nodejs"] == "npm"
    assert SOURCE_DISPLAY["java"] == "Maven"
    print("  OK")


def test_dpkg_parsing():
    print("Testing dpkg status parsing...")
    dpkg_content = """Package: bash
Version: 5.1-6ubuntu1
Status: install ok installed
Priority: required
Section: shells

Package: coreutils
Version: 8.32-4.1ubuntu1
Status: install ok installed
Priority: required
Section: utils

Package: oldpkg
Version: 1.0
Status: deinstall ok config-files
Priority: optional
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_dpkg_status(dpkg_content)
    assert len(packages) == 2
    assert packages[0].name == "bash"
    assert packages[1].name == "coreutils"
    pkg_names = [p.name for p in packages]
    assert "oldpkg" not in pkg_names, "deinstall packages should be excluded"
    print(f"  OK - parsed {len(packages)} packages, excluded deinstalled")


def test_apk_parsing():
    print("Testing apk installed parsing...")
    apk_content = """P:musl
V:1.2.3-r0
A:x86_64
S:612832

P:busybox
V:1.35.0-r29
A:x86_64
S:481280
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_apk_installed(apk_content)
    assert len(packages) == 2
    assert packages[0].name == "musl"
    assert packages[0].version == "1.2.3-r0"
    print(f"  OK - parsed {len(packages)} packages")


def test_requirements_parsing():
    print("Testing requirements.txt parsing...")
    req_content = """requests==2.31.0
flask>=2.0.0
numpy
# comment
click~=8.1.0
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_requirements_txt(req_content)
    assert len(packages) >= 3
    for pkg in packages:
        assert pkg.source == "python"
    print(f"  OK - parsed {len(packages)} packages")


def test_package_json_parsing():
    print("Testing package.json parsing...")
    pkg_data = {
        "name": "test-app",
        "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
        "devDependencies": {"jest": "^29.0.0"}
    }
    unpacker = ImageUnpacker()
    packages = unpacker._parse_package_json(pkg_data)
    assert len(packages) == 3
    for pkg in packages:
        assert pkg.source == "nodejs"
    print(f"  OK - parsed {len(packages)} packages")


def test_pom_xml_parsing():
    print("Testing pom.xml parsing...")
    pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.20</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.15.0</version>
        </dependency>
    </dependencies>
</project>
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_pom_xml(pom_content)
    assert len(packages) == 2
    assert packages[0].name == "spring-core"
    assert packages[0].version == "5.3.20"
    for pkg in packages:
        assert pkg.source == "java"
    print(f"  OK - parsed {len(packages)} packages")


def test_severity_from_score():
    print("Testing CVSS severity calculation...")
    assert get_severity_from_score(2.5) == "low"
    assert get_severity_from_score(5.0) == "medium"
    assert get_severity_from_score(7.5) == "high"
    assert get_severity_from_score(9.8) == "critical"
    print("  OK")


def test_high_risk_count():
    print("Testing high risk count and CI threshold...")
    vulns = [
        Vulnerability("CVE-1", 9.8, "critical", source="os"),
        Vulnerability("CVE-2", 7.5, "high", source="python"),
        Vulnerability("CVE-3", 5.0, "medium", source="nodejs"),
        Vulnerability("CVE-4", 2.0, "low", source="java"),
    ]
    reporter = Reporter(fail_threshold=2)
    high_count = reporter.get_high_risk_count(vulns)
    assert high_count == 2
    assert reporter.should_fail(vulns, 1) == True
    assert reporter.should_fail(vulns, 2) == False
    print(f"  OK - high risk count = {high_count}")


def test_cvss_vector_extraction():
    print("Testing CVSS vector extraction from OSV data...")
    vulndb = VulnDB.__new__(VulnDB)
    vulndb.db_path = ":memory:"
    vulndb.offline = True
    vulndb._lock = threading.Lock()
    vulndb._last_request_time = 0.0

    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = vulndb._extract_cvss_from_vector(vector)
    assert score > 0, f"Score should be > 0 for {vector}, got {score}"
    assert 9.0 <= score <= 10.0, f"Expected critical score, got {score}"

    vector2 = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
    score2 = vulndb._extract_cvss_from_vector(vector2)
    assert 0 < score2 < 5.0, f"Expected low score, got {score2}"

    print(f"  OK - CVSS vector extraction: N/A/L/L/H = {score:.1f}, L/H/H/R/L/L = {score2:.1f}")


if __name__ == "__main__":
    import threading

    print("=" * 60)
    print("Running unit tests for v3.0...")
    print("=" * 60)

    test_scan_result_class()
    test_layer_merge_dpkg()
    test_rpm_multiple_paths()
    test_rpm_bdb_format_warning()
    test_rpm_ndb_format_warning()
    test_rpm_unrecognized_format_warning()
    test_osv_ecosystem_routing()
    test_osv_query_payload()
    test_vulnerability_source_in_dict()
    test_reporter_json_with_source()
    test_reporter_markdown_with_source()
    test_source_display_mapping()
    test_dpkg_parsing()
    test_apk_parsing()
    test_requirements_parsing()
    test_package_json_parsing()
    test_pom_xml_parsing()
    test_severity_from_score()
    test_high_risk_count()
    test_cvss_vector_extraction()

    print("=" * 60)
    print("All tests passed!")
    print("=" * 60)
