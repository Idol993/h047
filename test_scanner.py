import io
import tarfile
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from unpacker import ImageUnpacker, Package
from vulndb import VulnDB, Vulnerability, get_severity_from_score
from reporter import Reporter


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
        packages = unpacker._scan_local_tar(tar_path)
        assert len(packages) >= 1
        assert packages[0].name == "testpkg"
        assert packages[0].version == "1.0.0"
        print(f"  OK - extracted {len(packages)} packages from tar")
    finally:
        os.unlink(tar_path)


def test_reporter_json():
    print("Testing reporter JSON output...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="Test vulnerability",
            fix_version="1.0.1",
            package_name="testpkg",
            package_version="1.0.0",
        )
    ]
    import json
    from io import StringIO
    import sys

    reporter = Reporter(output_file="/dev/stdout", output_format="json")
    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "test:latest", 1)
        output = captured.getvalue()
        data = json.loads(output)
        assert data["total_vulnerabilities"] == 1
        assert data["vulnerabilities"][0]["cve_id"] == "CVE-2023-0001"
        print("  OK - JSON report generated correctly")
    finally:
        sys.stdout = old_stdout


def test_high_risk_count():
    print("Testing high risk count...")
    vulns = [
        Vulnerability("CVE-1", 9.8, "critical", "", "", "", ""),
        Vulnerability("CVE-2", 7.5, "high", "", "", "", ""),
        Vulnerability("CVE-3", 5.0, "medium", "", "", "", ""),
        Vulnerability("CVE-4", 2.0, "low", "", "", "", ""),
    ]
    reporter = Reporter()
    high_count = reporter.get_high_risk_count(vulns)
    assert high_count == 2
    assert reporter.should_fail(vulns, 1) == True
    assert reporter.should_fail(vulns, 5) == False
    print(f"  OK - high risk count = {high_count}")


if __name__ == "__main__":
    print("=" * 50)
    print("Running unit tests...")
    print("=" * 50)

    test_dpkg_parsing()
    test_apk_parsing()
    test_requirements_parsing()
    test_package_json_parsing()
    test_severity_from_score()
    test_vulndb_cache()
    test_tar_extraction()
    test_reporter_json()
    test_high_risk_count()

    print("=" * 50)
    print("All tests passed!")
    print("=" * 50)
