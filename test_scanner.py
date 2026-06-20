import io
import tarfile
import tempfile
import os
import sys
import json
from io import StringIO

sys.path.insert(0, os.path.dirname(__file__))

from unpacker import ImageUnpacker, Package, ScanResult
from vulndb import VulnDB, Vulnerability, get_severity_from_score
from reporter import Reporter


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


def test_docker_save_format_detection():
    print("Testing docker save format detection...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([{"Config": "config.json", "Layers": ["layer0/layer.tar"]}])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            layer_tar_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer_tar_bytes, mode="w") as layer_tar:
                dpkg_status = "Package: testpkg\nVersion: 1.0.0\nStatus: install ok installed\n"
                info2 = tarfile.TarInfo(name="var/lib/dpkg/status")
                info2.size = len(dpkg_status)
                layer_tar.addfile(info2, io.BytesIO(dpkg_status.encode()))
            layer_tar_bytes.seek(0)

            info3 = tarfile.TarInfo(name="layer0/layer.tar")
            info3.size = len(layer_tar_bytes.getvalue())
            tar.addfile(info3, layer_tar_bytes)

        with tarfile.open(tar_path, "r") as tar:
            assert unpacker._is_docker_save_format(tar) == True
        print("  OK - docker save format detected")

        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f2:
            tar_path2 = f2.name
        try:
            with tarfile.open(tar_path2, "w") as tar:
                test_content = b"test" * 3
                info = tarfile.TarInfo(name="var/lib/dpkg/status")
                info.size = len(test_content)
                tar.addfile(info, io.BytesIO(test_content))
            with tarfile.open(tar_path2, "r") as tar:
                assert unpacker._is_docker_save_format(tar) == False
            print("  OK - filesystem format detected")
        finally:
            os.unlink(tar_path2)
    finally:
        os.unlink(tar_path)


def test_parallel_os_and_lang_scanning():
    print("Testing parallel OS package and language dependency scanning...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([{"Config": "config.json", "Layers": ["layer0/layer.tar", "layer1/layer.tar"]}])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            layer0_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer0_bytes, mode="w") as layer_tar:
                dpkg_status = "Package: bash\nVersion: 5.1\nStatus: install ok installed\n"
                info2 = tarfile.TarInfo(name="var/lib/dpkg/status")
                info2.size = len(dpkg_status)
                layer_tar.addfile(info2, io.BytesIO(dpkg_status.encode()))

                req_content = "requests==2.31.0\nflask>=2.0.0\n"
                info3 = tarfile.TarInfo(name="app/requirements.txt")
                info3.size = len(req_content)
                layer_tar.addfile(info3, io.BytesIO(req_content.encode()))
            layer0_bytes.seek(0)

            info4 = tarfile.TarInfo(name="layer0/layer.tar")
            info4.size = len(layer0_bytes.getvalue())
            tar.addfile(info4, layer0_bytes)

            layer1_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer1_bytes, mode="w") as layer_tar:
                pkg_json = '{"name": "test", "dependencies": {"express": "^4.18.2"}}'
                info5 = tarfile.TarInfo(name="app/package.json")
                info5.size = len(pkg_json)
                layer_tar.addfile(info5, io.BytesIO(pkg_json.encode()))
            layer1_bytes.seek(0)

            info6 = tarfile.TarInfo(name="layer1/layer.tar")
            info6.size = len(layer1_bytes.getvalue())
            tar.addfile(info6, layer1_bytes)

        result = unpacker._scan_local_tar(tar_path)
        print(f"  Found {len(result.packages)} packages total")

        sources = [p.source for p in result.packages]
        assert "os" in sources, "OS packages should be found"
        assert "python" in sources, "Python dependencies should be found"
        assert "nodejs" in sources, "Node.js dependencies should be found"

        counts = result.package_count_by_source()
        assert counts.get("os", 0) >= 1
        assert counts.get("python", 0) >= 2
        assert counts.get("nodejs", 0) >= 1

        print(f"  Package counts: {counts}")
        print("  OK - OS packages and language dependencies are scanned in parallel")
    finally:
        os.unlink(tar_path)


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

Package: libc6
Version: 2.35-0ubuntu3.1
Status: install ok installed
Priority: required
Section: libs
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_dpkg_status(dpkg_content)
    assert len(packages) == 3
    assert packages[0].name == "bash"
    assert packages[0].version == "5.1-6ubuntu1"
    assert packages[1].name == "coreutils"
    assert packages[2].name == "libc6"
    print(f"  OK - parsed {len(packages)} packages")


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

P:ssl_client
V:1.35.0-r29
A:x86_64
S:481280
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_apk_installed(apk_content)
    assert len(packages) == 3
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
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.21"
        },
        "devDependencies": {
            "jest": "^29.0.0"
        }
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
    <modelVersion>4.0.0</modelVersion>
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
    print("  OK - severity levels correct")


def test_vulndb_cache():
    print("Testing VulnDB cache functionality...")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        vulndb = VulnDB(db_path=db_path, offline=True)
        test_vulns = [
            Vulnerability(
                cve_id="CVE-2023-0001",
                cvss_score=7.5,
                severity="high",
                description="Test vulnerability 1",
                fix_version="1.0.1",
                package_name="testpkg",
                package_version="1.0.0",
            )
        ]
        vulndb._cache_vulns("testpkg", "1.0.0", test_vulns)

        cached = vulndb._get_cached("testpkg", "1.0.0")
        assert len(cached) == 1
        assert cached[0].cve_id == "CVE-2023-0001"
        assert cached[0].cvss_score == 7.5
        print("  OK - cache works correctly")
    finally:
        os.unlink(db_path)


def test_rpm_sqlite_parsing():
    print("Testing RPM SQLite database parsing...")
    import sqlite3

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
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
        cursor.execute("INSERT INTO Packages VALUES ('openssl', '3.0.7', '2.el9')")
        cursor.execute("INSERT INTO Packages VALUES ('glibc', '2.34', '28.el9')")
        conn.commit()
        conn.close()

        with open(db_path, "rb") as f:
            db_content = f.read()

        unpacker = ImageUnpacker()
        packages = unpacker._parse_rpm_sqlite(db_content)

        assert len(packages) == 3
        assert packages[0].name == "bash"
        assert packages[0].version == "5.1-8.el9"
        assert packages[1].name == "openssl"
        assert packages[1].version == "3.0.7-2.el9"
        print(f"  OK - parsed {len(packages)} packages from RPM SQLite database")
    finally:
        os.unlink(db_path)


def test_tar_extraction():
    print("Testing tar package extraction...")
    dpkg_status = """Package: testpkg
Version: 1.0.0
Status: install ok installed
"""
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            info = tarfile.TarInfo(name="var/lib/dpkg/status")
            info.size = len(dpkg_status)
            tar.addfile(info, io.BytesIO(dpkg_status.encode()))

        unpacker = ImageUnpacker()
        result = unpacker._scan_local_tar(tar_path)
        assert len(result.packages) >= 1
        assert result.packages[0].name == "testpkg"
        assert result.packages[0].version == "1.0.0"
        print(f"  OK - extracted {len(result.packages)} packages from tar")
    finally:
        os.unlink(tar_path)


def test_reporter_json_summary():
    print("Testing reporter JSON summary output...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="Test vulnerability 1",
            fix_version="1.0.1",
            package_name="testpkg",
            package_version="1.0.0",
        ),
        Vulnerability(
            cve_id="CVE-2023-0002",
            cvss_score=9.8,
            severity="critical",
            description="Test vulnerability 2",
            fix_version="1.0.2",
            package_name="testpkg",
            package_version="1.0.0",
        ),
        Vulnerability(
            cve_id="CVE-2023-0003",
            cvss_score=5.0,
            severity="medium",
            description="Test vulnerability 3",
            fix_version="2.0.1",
            package_name="otherpkg",
            package_version="2.0.0",
        ),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="json", fail_threshold=5)

    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "test:latest", 5, {"os": 3, "python": 2})
        output = captured.getvalue()
        data = json.loads(output)

        assert "scan_metadata" in data
        assert data["scan_metadata"]["image_source"] == "test:latest"
        assert data["scan_metadata"]["version"] == "2.0"

        assert "summary" in data
        summary = data["summary"]
        assert summary["total_packages_scanned"] == 5
        assert summary["total_vulnerabilities"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 0
        assert summary["packages_by_source"]["os"] == 3
        assert summary["packages_by_source"]["python"] == 2

        assert "by_package" in summary
        assert len(summary["by_package"]) == 2
        testpkg = summary["by_package"]["testpkg@1.0.0"]
        assert testpkg["name"] == "testpkg"
        assert testpkg["version"] == "1.0.0"
        assert testpkg["total_vulns"] == 2
        assert testpkg["by_severity"]["high"] == 1
        assert testpkg["by_severity"]["critical"] == 1

        assert "ci" in summary
        assert summary["ci"]["high_risk_count"] == 2
        assert summary["ci"]["fail_threshold"] == 5
        assert summary["ci"]["exceeds_threshold"] == False
        assert summary["ci"]["exit_code"] == 0

        assert len(data["vulnerabilities"]) == 3
        print("  OK - JSON report with summary generated correctly")
    finally:
        sys.stdout = old_stdout


def test_reporter_markdown():
    print("Testing reporter Markdown output...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="Test vulnerability with some description",
            fix_version="1.0.1",
            package_name="testpkg",
            package_version="1.0.0",
        ),
        Vulnerability(
            cve_id="CVE-2023-0002",
            cvss_score=9.8,
            severity="critical",
            description="Another vulnerability description",
            fix_version="1.0.2",
            package_name="testpkg",
            package_version="1.0.0",
        ),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="markdown", fail_threshold=1)

    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "myapp:latest", 10, {"os": 5, "nodejs": 5}, ["Warning: RPM database not parsed"])
        output = captured.getvalue()

        assert "# 🔒 Container Image Security Scan Report" in output
        assert "**Image**: `myapp:latest`" in output
        assert "CI Status" in output
        assert "FAILED" in output
        assert "High+ Risk Vulnerabilities: **2**" in output
        assert "Vulnerability Summary" in output
        assert "Packages Scanned" in output
        assert "Vulnerabilities by Package" in output
        assert "Vulnerability Details" in output
        assert "CVE-2023-0001" in output
        assert "CVE-2023-0002" in output
        assert "Scan Warnings" in output
        assert "RPM database not parsed" in output
        assert "testpkg" in output

        print("  OK - Markdown report generated correctly")
    finally:
        sys.stdout = old_stdout


def test_high_risk_count():
    print("Testing high risk count and CI threshold...")
    vulns = [
        Vulnerability("CVE-1", 9.8, "critical", "", "", "", ""),
        Vulnerability("CVE-2", 7.5, "high", "", "", "", ""),
        Vulnerability("CVE-3", 5.0, "medium", "", "", "", ""),
        Vulnerability("CVE-4", 2.0, "low", "", "", "", ""),
    ]
    reporter = Reporter(fail_threshold=2)
    high_count = reporter.get_high_risk_count(vulns)
    assert high_count == 2
    assert reporter.should_fail(vulns, 1) == True
    assert reporter.should_fail(vulns, 2) == False
    assert reporter.should_fail(vulns, 5) == False
    print(f"  OK - high risk count = {high_count}")


def test_empty_image_warning():
    print("Testing empty image detection and warning...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            info = tarfile.TarInfo(name="empty_dir/")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)

        import sys
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        assert not result.has_packages()
        assert len(result.warnings) > 0
        assert ("empty" in result.warnings[0].lower() or
                "unsupported" in result.warnings[0].lower())
        print(f"  OK - empty image warning: {result.warnings[0]}")
    finally:
        os.unlink(tar_path)


def test_rpm_unrecognized_format_warning():
    print("Testing RPM unrecognized format warning...")
    unpacker = ImageUnpacker()

    bdb_header = b"\x00\x06\x15\x61" + b"\x00" * 100
    packages = unpacker._parse_rpm_berkeley_db(bdb_header)
    assert len(packages) == 0
    assert len(unpacker.warnings) > 0
    print(f"  OK - BDB format warning present: {len(unpacker.warnings)} warnings")


if __name__ == "__main__":
    print("=" * 60)
    print("Running unit tests for v2.0...")
    print("=" * 60)

    test_scan_result_class()
    test_docker_save_format_detection()
    test_parallel_os_and_lang_scanning()
    test_dpkg_parsing()
    test_apk_parsing()
    test_requirements_parsing()
    test_package_json_parsing()
    test_pom_xml_parsing()
    test_severity_from_score()
    test_vulndb_cache()
    test_rpm_sqlite_parsing()
    test_tar_extraction()
    test_reporter_json_summary()
    test_reporter_markdown()
    test_high_risk_count()
    test_empty_image_warning()
    test_rpm_unrecognized_format_warning()

    print("=" * 60)
    print("All tests passed!")
    print("=" * 60)
