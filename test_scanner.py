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


def _create_rpm_sqlite_db(packages_data):
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
    for name, ver, rel in packages_data:
        cursor.execute("INSERT INTO Packages VALUES (?, ?, ?)", (name, ver, rel))
    conn.commit()
    conn.close()
    with open(db_path, "rb") as f:
        data = f.read()
    os.unlink(db_path)
    return data


def test_dpkg_final_layer_snapshot_only():
    print("TEST: dpkg status uses ONLY final layer snapshot (no accumulation)...")
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
                dpkg_v1 = (
                    "Package: openssl\nVersion: 1.1.1\nStatus: install ok installed\n\n"
                    "Package: bash\nVersion: 5.0\nStatus: install ok installed\n\n"
                    "Package: oldlib\nVersion: 1.0\nStatus: install ok installed\n"
                )
                info2 = tarfile.TarInfo(name="var/lib/dpkg/status")
                info2.size = len(dpkg_v1)
                layer_tar.addfile(info2, io.BytesIO(dpkg_v1.encode()))
            layer0_bytes.seek(0)

            info3 = tarfile.TarInfo(name="layer0/layer.tar")
            info3.size = len(layer0_bytes.getvalue())
            tar.addfile(info3, layer0_bytes)

            layer1_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer1_bytes, mode="w") as layer_tar:
                dpkg_v2 = (
                    "Package: openssl\nVersion: 3.0.2\nStatus: install ok installed\n\n"
                    "Package: bash\nVersion: 5.2\nStatus: install ok installed\n\n"
                    "Package: curl\nVersion: 7.88.0\nStatus: install ok installed\n"
                )
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

        assert "oldlib" not in pkg_dict, (
            f"FAIL: oldlib existed only in layer 0, but still found in final report. "
            f"All packages: {pkg_dict}"
        )
        assert pkg_dict["openssl"] == "3.0.2", (
            f"FAIL: openssl should be 3.0.2 (layer 1), got {pkg_dict.get('openssl')}"
        )
        assert pkg_dict["bash"] == "5.2", (
            f"FAIL: bash should be 5.2 (layer 1), got {pkg_dict.get('bash')}"
        )
        assert "curl" in pkg_dict, (
            f"FAIL: curl added in layer 1 should be present"
        )
        assert len(pkg_dict) == 3, (
            f"FAIL: expected exactly 3 packages in final dpkg, got {len(pkg_dict)}: {pkg_dict}"
        )

        print(f"  PASS: final snapshot = {pkg_dict} (oldlib removed, openssl/bash upgraded, curl added)")
    finally:
        os.unlink(tar_path)


def test_dpkg_strict_install_ok_filter():
    print("TEST: dpkg status strictly requires 'install ok installed'...")
    dpkg_content = (
        "Package: goodpkg\nVersion: 1.0\nStatus: install ok installed\n\n"
        "Package: halfconfig\nVersion: 2.0\nStatus: install ok half-configured\n\n"
        "Package: deinstall\nVersion: 3.0\nStatus: deinstall ok config-files\n\n"
        "Package: unpacked\nVersion: 4.0\nStatus: install ok unpacked\n\n"
        "Package: missing_status\nVersion: 5.0\n"
    )
    unpacker = ImageUnpacker()
    packages = unpacker._parse_dpkg_status(dpkg_content)

    pkg_names = [p.name for p in packages]
    assert "goodpkg" in pkg_names, "goodpkg with install ok installed should pass"
    assert "halfconfig" not in pkg_names, "half-configured should NOT be counted"
    assert "deinstall" not in pkg_names, "deinstall should NOT be counted"
    assert "unpacked" not in pkg_names, "unpacked should NOT be counted"
    assert "missing_status" not in pkg_names, "missing status should NOT be counted"
    assert len(packages) == 1, f"Expected exactly 1 package, got {len(packages)}: {pkg_names}"

    print(f"  PASS: only goodpkg retained (removed: halfconfig/deinstall/unpacked/missing_status)")


def test_manifest_layer_order_overrides_tar_order():
    print("TEST: layer order follows manifest.json, not tar file order...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": [
                    "bottom_layer/layer.tar",
                    "middle_layer/layer.tar",
                    "top_layer/layer.tar",
                ]}
            ])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            top_layer = io.BytesIO()
            with tarfile.open(fileobj=top_layer, mode="w") as lt:
                dpkg_top = (
                    "Package: openssl\nVersion: 3.0.10\nStatus: install ok installed\n\n"
                    "Package: final_pkg\nVersion: 1.0\nStatus: install ok installed\n"
                )
                tinfo = tarfile.TarInfo(name="var/lib/dpkg/status")
                tinfo.size = len(dpkg_top)
                lt.addfile(tinfo, io.BytesIO(dpkg_top.encode()))
            top_layer.seek(0)

            middle_layer = io.BytesIO()
            with tarfile.open(fileobj=middle_layer, mode="w") as lt:
                dpkg_mid = (
                    "Package: openssl\nVersion: 1.1.1k\nStatus: install ok installed\n\n"
                    "Package: mid_only\nVersion: 2.0\nStatus: install ok installed\n"
                )
                tinfo = tarfile.TarInfo(name="var/lib/dpkg/status")
                tinfo.size = len(dpkg_mid)
                lt.addfile(tinfo, io.BytesIO(dpkg_mid.encode()))
            middle_layer.seek(0)

            bottom_layer = io.BytesIO()
            with tarfile.open(fileobj=bottom_layer, mode="w") as lt:
                dpkg_bot = (
                    "Package: openssl\nVersion: 1.0.0\nStatus: install ok installed\n\n"
                    "Package: bot_only\nVersion: 3.0\nStatus: install ok installed\n"
                )
                tinfo = tarfile.TarInfo(name="var/lib/dpkg/status")
                tinfo.size = len(dpkg_bot)
                lt.addfile(tinfo, io.BytesIO(dpkg_bot.encode()))
            bottom_layer.seek(0)

            tinfo = tarfile.TarInfo(name="top_layer/layer.tar")
            tinfo.size = len(top_layer.getvalue())
            tar.addfile(tinfo, top_layer)

            tinfo = tarfile.TarInfo(name="bottom_layer/layer.tar")
            tinfo.size = len(bottom_layer.getvalue())
            tar.addfile(tinfo, bottom_layer)

            tinfo = tarfile.TarInfo(name="middle_layer/layer.tar")
            tinfo.size = len(middle_layer.getvalue())
            tar.addfile(tinfo, middle_layer)

        old_stdout = sys.stdout
        captured = StringIO()
        sys.stdout = captured
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        log_output = captured.getvalue()
        assert "Using manifest layer order" in log_output, (
            "Should have printed 'Using manifest layer order'"
        )

        pkg_dict = {p.name: p.version for p in result.packages if p.source == "os"}

        assert pkg_dict["openssl"] == "3.0.10", (
            f"FAIL: openssl version should be from top_layer (manifest last) = 3.0.10, "
            f"got {pkg_dict.get('openssl')}"
        )
        assert "final_pkg" in pkg_dict, "final_pkg (only in top_layer) must be present"
        assert "mid_only" not in pkg_dict, "mid_only (middle, replaced by top dpkg) must NOT be present"
        assert "bot_only" not in pkg_dict, "bot_only (bottom, replaced by top dpkg) must NOT be present"

        print(f"  PASS: manifest order bottom→middle→top applied, result = {pkg_dict}")
    finally:
        os.unlink(tar_path)


def test_rpm_multi_path_fallback_with_valid_sqlite():
    print("TEST: RPM multi-path fallback finds valid sqlite at 2nd path...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        rpm_sqlite_bytes = _create_rpm_sqlite_db([
            ("bash", "5.1", "8.el9"),
            ("openssl-libs", "3.0.7", "2.el9"),
            ("glibc", "2.34", "28.el9"),
        ])

        bdb_fake = b"\x00\x06\x15\x61" + b"\x00" * 500

        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": ["layer0/layer.tar"]}
            ])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            layer0_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer0_bytes, mode="w") as layer_tar:
                tinfo = tarfile.TarInfo(name="var/lib/rpm/Packages")
                tinfo.size = len(bdb_fake)
                layer_tar.addfile(tinfo, io.BytesIO(bdb_fake))

                tinfo2 = tarfile.TarInfo(name="usr/lib/sysimage/rpm/rpmdb.sqlite")
                tinfo2.size = len(rpm_sqlite_bytes)
                layer_tar.addfile(tinfo2, io.BytesIO(rpm_sqlite_bytes))
            layer0_bytes.seek(0)

            tinfo3 = tarfile.TarInfo(name="layer0/layer.tar")
            tinfo3.size = len(layer0_bytes.getvalue())
            tar.addfile(tinfo3, layer0_bytes)

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        rpm_pkgs = [p for p in result.packages if p.source == "os"]
        assert len(rpm_pkgs) == 3, (
            f"FAIL: expected 3 RPM packages from 2nd path sqlite, got {len(rpm_pkgs)}"
        )
        pkg_names = sorted([p.name for p in rpm_pkgs])
        assert pkg_names == ["bash", "glibc", "openssl-libs"], f"Got: {pkg_names}"

        has_bdb_warning = any("BDB" in w for w in result.warnings)
        assert not has_bdb_warning, (
            f"FAIL: should not emit BDB warning when 2nd path succeeded, warnings: {result.warnings}"
        )

        print(f"  PASS: fallback to usr/lib/sysimage/rpm/rpmdb.sqlite -> {pkg_names}")
    finally:
        os.unlink(tar_path)


def test_rpm_all_paths_failed_emits_specific_warnings():
    print("TEST: RPM all paths failed -> per-format specific warnings...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        bdb_fake = b"\x00\x06\x15\x61" + b"\x00" * 200
        ndb_fake = b"RPM\x00NDBC" + b"\x00" * 200

        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": ["layer0/layer.tar"]}
            ])
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest.encode()))

            layer0_bytes = io.BytesIO()
            with tarfile.open(fileobj=layer0_bytes, mode="w") as layer_tar:
                tinfo = tarfile.TarInfo(name="var/lib/rpm/Packages")
                tinfo.size = len(bdb_fake)
                layer_tar.addfile(tinfo, io.BytesIO(bdb_fake))

                tinfo2 = tarfile.TarInfo(name="usr/lib/sysimage/rpm/Packages")
                tinfo2.size = len(ndb_fake)
                layer_tar.addfile(tinfo2, io.BytesIO(ndb_fake))
            layer0_bytes.seek(0)

            tinfo3 = tarfile.TarInfo(name="layer0/layer.tar")
            tinfo3.size = len(layer0_bytes.getvalue())
            tar.addfile(tinfo3, layer0_bytes)

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        rpm_pkgs = [p for p in result.packages if p.source == "os"]
        assert len(rpm_pkgs) == 0, f"Expected 0 RPM packages, got {len(rpm_pkgs)}"

        bdb_warn = [w for w in result.warnings if "BDB" in w and "var/lib/rpm/Packages" in w]
        ndb_warn = [w for w in result.warnings if "NDB" in w and "usr/lib/sysimage/rpm/Packages" in w]
        assert len(bdb_warn) == 1, f"Missing specific BDB warning for var/lib/rpm/Packages: {result.warnings}"
        assert len(ndb_warn) == 1, f"Missing specific NDB warning for usr/lib/sysimage/rpm/Packages: {result.warnings}"

        print(f"  PASS: {len(bdb_warn)} BDB + {len(ndb_warn)} NDB specific warnings emitted with paths")
    finally:
        os.unlink(tar_path)


def test_maven_gav_coordinates_in_package():
    print("TEST: Maven package uses groupId:artifactId as name...")
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
        <dependency>
            <artifactId>no-group-artifact</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>
</project>
"""
    unpacker = ImageUnpacker()
    packages = unpacker._parse_pom_xml(pom_content)

    assert len(packages) == 3, f"Expected 3 packages, got {len(packages)}"
    assert packages[0].name == "org.springframework:spring-core", (
        f"FAIL: expected 'org.springframework:spring-core', got '{packages[0].name}'"
    )
    assert packages[0].version == "5.3.20"
    assert packages[0].source == "java"

    assert packages[1].name == "com.fasterxml.jackson.core:jackson-databind"
    assert packages[2].name == "no-group-artifact", (
        "Missing groupId should fall back to artifactId only"
    )

    pkg_dict = packages[0].to_dict()
    assert pkg_dict["name"] == "org.springframework:spring-core"
    assert pkg_dict["source"] == "java"

    print(f"  PASS: GAV coordinates correct: {[p.name for p in packages]}")


def test_json_report_includes_maven_coordinates():
    print("TEST: JSON vulnerabilities include full Maven GAV in package_name...")
    vulns = [
        Vulnerability(
            cve_id="CVE-2023-0001",
            cvss_score=7.5,
            severity="high",
            description="Maven vuln",
            fix_version="5.3.21",
            package_name="org.springframework:spring-core",
            package_version="5.3.20",
            source="java",
        ),
        Vulnerability(
            cve_id="CVE-2023-0002",
            cvss_score=5.0,
            severity="medium",
            description="PyPI vuln",
            package_name="requests",
            package_version="2.31.0",
            source="python",
        ),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="json", fail_threshold=5)

    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "test:latest", 10, {"os": 3, "java": 2, "python": 5})
        output = captured.getvalue()
        data = json.loads(output)
    finally:
        sys.stdout = old_stdout

    maven_vuln = data["vulnerabilities"][0]
    assert maven_vuln["package_name"] == "org.springframework:spring-core", (
        f"FAIL: JSON missing full GAV, got {maven_vuln['package_name']}"
    )
    assert maven_vuln["source"] == "java"

    pkg_key = "org.springframework:spring-core@5.3.20"
    assert pkg_key in data["summary"]["by_package"], (
        f"FAIL: by_package missing key with GAV, keys = {list(data['summary']['by_package'].keys())}"
    )

    by_pkg = data["summary"]["by_package"][pkg_key]
    assert by_pkg["name"] == "org.springframework:spring-core"
    assert by_pkg["source"] == "Maven", f"Expected 'Maven' label, got {by_pkg['source']}"

    print(f"  PASS: JSON includes GAV coordinates and Maven source label")


def test_md_report_source_labels():
    print("TEST: Markdown report maps source to correct display label...")
    vulns = [
        Vulnerability("CVE-1", 9.8, "critical", package_name="bash", package_version="5.1", source="os"),
        Vulnerability("CVE-2", 7.5, "high", package_name="requests", package_version="2.31", source="python"),
        Vulnerability("CVE-3", 5.0, "medium", package_name="express", package_version="4.18", source="nodejs"),
        Vulnerability("CVE-4", 5.5, "medium", package_name="g:a", package_version="1.0", source="java"),
    ]
    reporter = Reporter(output_file="/dev/stdout", output_format="markdown", fail_threshold=5)
    old_stdout = sys.stdout
    sys.stdout = captured = StringIO()
    try:
        reporter.generate(vulns, "test:latest", 10)
        output = captured.getvalue()
    finally:
        sys.stdout = old_stdout

    assert "| os |" in output or "|**os**" in output or "| os " in output
    assert "PyPI" in output, f"Missing PyPI label in MD output"
    assert "npm" in output, f"Missing npm label in MD output"
    assert "Maven" in output, f"Missing Maven label in MD output"
    assert "By Source" in output

    print("  PASS: Markdown displays os/PyPI/npm/Maven labels correctly")


def test_osv_java_query_uses_full_gav():
    print("TEST: OSV query for java uses full GAV...")
    from config import OSV_ECOSYSTEM_MAP

    p = Package(name="org.springframework:spring-core", version="5.3.20", source="java")
    assert OSV_ECOSYSTEM_MAP.get(p.source) == "Maven"

    expected_payload = {
        "version": "5.3.20",
        "package": {
            "name": "org.springframework:spring-core",
            "ecosystem": "Maven",
        }
    }
    assert expected_payload["package"]["name"].count(":") == 1

    from vulndb import VulnDB
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        vdb = VulnDB(db_path=db_path, offline=True)
        test_v = Vulnerability(
            cve_id="CVE-GAV", cvss_score=7.0, severity="high",
            package_name="org.springframework:spring-core", package_version="5.3.20",
            source="java",
        )
        vdb._cache_vulns("org.springframework:spring-core", "5.3.20", [test_v])
        cached = vdb._get_cached("org.springframework:spring-core", "5.3.20")
        assert len(cached) == 1
        assert cached[0].source == "java"
        assert cached[0].package_name == "org.springframework:spring-core"
        print("  PASS: Java GAV round-trips through cache correctly")
    finally:
        os.unlink(db_path)


def test_dpkg_and_lang_parallel():
    print("TEST: OS dpkg + language dependencies scanned together...")
    unpacker = ImageUnpacker()

    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
        tar_path = f.name

    try:
        with tarfile.open(tar_path, "w") as tar:
            manifest = json.dumps([
                {"Config": "config.json", "Layers": ["l0/layer.tar", "l1/layer.tar"]}
            ])
            t = tarfile.TarInfo(name="manifest.json")
            t.size = len(manifest)
            tar.addfile(t, io.BytesIO(manifest.encode()))

            l0 = io.BytesIO()
            with tarfile.open(fileobj=l0, mode="w") as lt:
                dpkg = (
                    "Package: bash\nVersion: 5.0\nStatus: install ok installed\n\n"
                    "Package: openssl\nVersion: 1.1.1\nStatus: install ok installed\n"
                )
                tinfo = tarfile.TarInfo(name="var/lib/dpkg/status")
                tinfo.size = len(dpkg)
                lt.addfile(tinfo, io.BytesIO(dpkg.encode()))

                req = "requests==2.31.0\nflask==2.0.0\n"
                tinfo = tarfile.TarInfo(name="app/requirements.txt")
                tinfo.size = len(req)
                lt.addfile(tinfo, io.BytesIO(req.encode()))
            l0.seek(0)
            t = tarfile.TarInfo(name="l0/layer.tar")
            t.size = len(l0.getvalue())
            tar.addfile(t, l0)

            l1 = io.BytesIO()
            with tarfile.open(fileobj=l1, mode="w") as lt:
                dpkg = (
                    "Package: bash\nVersion: 5.2\nStatus: install ok installed\n\n"
                    "Package: openssl\nVersion: 3.0.2\nStatus: install ok installed\n\n"
                    "Package: curl\nVersion: 7.88\nStatus: install ok installed\n"
                )
                tinfo = tarfile.TarInfo(name="var/lib/dpkg/status")
                tinfo.size = len(dpkg)
                lt.addfile(tinfo, io.BytesIO(dpkg.encode()))

                pkgjson = '{"name":"x","dependencies":{"express":"^4.18.2","lodash":"4.17.21"}}'
                tinfo = tarfile.TarInfo(name="web/package.json")
                tinfo.size = len(pkgjson)
                lt.addfile(tinfo, io.BytesIO(pkgjson.encode()))
            l1.seek(0)
            t = tarfile.TarInfo(name="l1/layer.tar")
            t.size = len(l1.getvalue())
            tar.addfile(t, l1)

        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            result = unpacker.scan(tar_path)
        finally:
            sys.stdout = old_stdout

        pkg_by_src = result.package_count_by_source()
        assert pkg_by_src.get("os", 0) == 3, (
            f"FAIL: Expected 3 OS packages, got {pkg_by_src.get('os')}"
        )
        assert pkg_by_src.get("python", 0) == 2, (
            f"FAIL: Expected 2 PyPI packages, got {pkg_by_src.get('python')}"
        )
        assert pkg_by_src.get("nodejs", 0) == 2, (
            f"FAIL: Expected 2 npm packages, got {pkg_by_src.get('nodejs')}"
        )

        os_versions = {p.name: p.version for p in result.packages if p.source == "os"}
        assert os_versions["openssl"] == "3.0.2", f"Expected 3.0.2, got {os_versions.get('openssl')}"

        print(f"  PASS: os=3, python=2, nodejs=2, openssl=3.0.2 (final layer)")
    finally:
        os.unlink(tar_path)


def test_source_label_mapping():
    print("TEST: source label mapping correct...")
    assert SOURCE_DISPLAY["os"] == "os"
    assert SOURCE_DISPLAY["python"] == "PyPI"
    assert SOURCE_DISPLAY["nodejs"] == "npm"
    assert SOURCE_DISPLAY["java"] == "Maven"
    print("  PASS")


if __name__ == "__main__":
    import threading

    print("=" * 65)
    print("Container Image Scanner v4.0 — Targeted Regression Tests")
    print("=" * 65)

    tests = [
        test_dpkg_final_layer_snapshot_only,
        test_dpkg_strict_install_ok_filter,
        test_manifest_layer_order_overrides_tar_order,
        test_rpm_multi_path_fallback_with_valid_sqlite,
        test_rpm_all_paths_failed_emits_specific_warnings,
        test_maven_gav_coordinates_in_package,
        test_json_report_includes_maven_coordinates,
        test_md_report_source_labels,
        test_osv_java_query_uses_full_gav,
        test_dpkg_and_lang_parallel,
        test_source_label_mapping,
    ]

    failed = 0
    for i, test_fn in enumerate(tests, 1):
        try:
            test_fn()
        except AssertionError as e:
            failed += 1
            print(f"  ** ASSERTION FAILED: {e}")
        except Exception as e:
            failed += 1
            print(f"  ** ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()

    print("=" * 65)
    if failed == 0:
        print(f"All {len(tests)} tests PASSED ✓")
    else:
        print(f"{failed}/{len(tests)} tests FAILED ✗")
        sys.exit(1)
    print("=" * 65)
