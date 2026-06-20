import os
import io
import tarfile
import json
import re
import struct
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

from config import PACKAGE_DB_PATHS, LANGUAGE_DEP_FILES


class ScanResult:
    def __init__(self, packages: List["Package"], warnings: List[str] = None):
        self.packages = packages
        self.warnings = warnings or []

    def has_packages(self) -> bool:
        return len(self.packages) > 0

    def package_count_by_source(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for pkg in self.packages:
            counts[pkg.source] = counts.get(pkg.source, 0) + 1
        return counts


class Package:
    def __init__(self, name: str, version: str, source: str = "os"):
        self.name = name
        self.version = version
        self.source = source

    def __repr__(self):
        return f"Package(name={self.name}, version={self.version}, source={self.source})"

    def to_dict(self):
        return {"name": self.name, "version": self.version, "source": self.source}


class ImageUnpacker:
    def __init__(self):
        self.warnings: List[str] = []

    def scan(self, image_source: str) -> ScanResult:
        self.warnings = []

        if os.path.isfile(image_source) and image_source.endswith(".tar"):
            result = self._scan_local_tar(image_source)
        else:
            result = self._scan_remote_image(image_source)

        if not result.has_packages():
            if not result.warnings:
                result.warnings.append(
                    "No packages found. This appears to be an empty image "
                    "or an unsupported image format."
                )
            for warning in result.warnings:
                print(f"Warning: {warning}")

        return result

    def _is_docker_save_format(self, tar: tarfile.TarFile) -> bool:
        try:
            manifest = tar.getmember("manifest.json")
            return manifest is not None
        except KeyError:
            pass

        for member in tar.getmembers():
            if member.name.endswith("/layer.tar"):
                return True

        return False

    def _scan_local_tar(self, tar_path: str) -> ScanResult:
        all_packages: List[Package] = []

        with tarfile.open(tar_path, "r") as tar:
            if self._is_docker_save_format(tar):
                print(f"Detected docker save format, extracting from layers...")
                return self._extract_packages_from_image_tar(tar)
            else:
                print(f"Detected filesystem tar format, extracting directly...")
                packages = self._extract_packages_from_filesystem_tar(tar)
                return ScanResult(packages=packages, warnings=self.warnings)

    def _scan_remote_image(self, image_name: str) -> ScanResult:
        try:
            import docker
        except ImportError:
            raise RuntimeError(
                "docker package not installed. Install with: pip install docker"
            )

        client = docker.from_env()

        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            print(f"Pulling image {image_name}...")
            client.images.pull(image_name)

        image = client.images.get(image_name)

        tar_stream = image.save()
        tar_bytes = b"".join(tar_stream)
        tar_file = io.BytesIO(tar_bytes)

        with tarfile.open(fileobj=tar_file, mode="r") as tar:
            return self._extract_packages_from_image_tar(tar)

    def _extract_packages_from_image_tar(self, outer_tar: tarfile.TarFile) -> ScanResult:
        layer_tars = []
        for member in outer_tar.getmembers():
            if member.isfile() and member.name.endswith("/layer.tar"):
                layer_tars.append(member.name)

        print(f"Found {len(layer_tars)} layers to scan")

        all_packages: List[Package] = []
        found_os_dbs: Set[str] = set()
        seen_lang_files: Set[str] = set()

        for layer_idx, layer_tar_name in enumerate(layer_tars):
            layer_file = outer_tar.extractfile(layer_tar_name)
            if layer_file is None:
                continue

            with tarfile.open(fileobj=layer_file, mode="r") as layer_tar:
                os_packages, dbs_found = self._scan_layer_for_os_packages(
                    layer_tar, found_os_dbs, layer_idx
                )
                all_packages.extend(os_packages)
                found_os_dbs.update(dbs_found)

                lang_packages, new_files = self._scan_layer_for_language_deps(
                    layer_tar, seen_lang_files
                )
                all_packages.extend(lang_packages)
                seen_lang_files.update(new_files)

        if not all_packages:
            for warning in self.warnings:
                print(f"Warning: {warning}")

        return ScanResult(packages=all_packages, warnings=self.warnings)

    def _extract_packages_from_filesystem_tar(self, tar: tarfile.TarFile) -> List[Package]:
        os_packages, _ = self._scan_layer_for_os_packages(tar, set(), 0)
        lang_packages, _ = self._scan_layer_for_language_deps(tar, set())
        return os_packages + lang_packages

    def _scan_layer_for_os_packages(
        self, tar: tarfile.TarFile, found_dbs: Set[str], layer_idx: int
    ) -> Tuple[List[Package], Set[str]]:
        packages: List[Package] = []
        new_dbs: Set[str] = set()

        for db_type, db_path in PACKAGE_DB_PATHS.items():
            if db_type in found_dbs:
                continue

            member = self._find_member_in_tar(tar, db_path)

            if member and member.isfile():
                f = tar.extractfile(member)
                if f:
                    content_bytes = f.read()
                    content = content_bytes.decode("utf-8", errors="ignore")
                    parsed_packages = []
                    parse_success = True

                    if db_type == "dpkg":
                        parsed_packages = self._parse_dpkg_status(content)
                    elif db_type == "rpm":
                        parsed_packages = self._parse_rpm_packages(content_bytes, member.name)
                        if not parsed_packages:
                            parse_success = False
                            self.warnings.append(
                                f"RPM database found but could not be parsed. "
                                f"This may require system RPM tools or the database format is unsupported. "
                                f"Try running on a RHEL/CentOS system, or install 'rpm' command."
                            )
                    elif db_type == "apk":
                        parsed_packages = self._parse_apk_installed(content)

                    if parsed_packages:
                        print(f"  Layer {layer_idx}: Found {len(parsed_packages)} {db_type} packages")
                        packages.extend(parsed_packages)
                        new_dbs.add(db_type)

        return packages, new_dbs

    def _scan_layer_for_language_deps(
        self, tar: tarfile.TarFile, seen_files: Set[str]
    ) -> Tuple[List[Package], Set[str]]:
        packages: List[Package] = []
        new_files: Set[str] = set()

        for member in tar.getmembers():
            if not member.isfile():
                continue

            basename = os.path.basename(member.name)
            full_path = member.name

            if full_path in seen_files:
                continue

            if basename not in LANGUAGE_DEP_FILES.values():
                continue

            lang_type = None
            for lt, fname in LANGUAGE_DEP_FILES.items():
                if basename == fname:
                    lang_type = lt
                    break

            if lang_type is None:
                continue

            f = tar.extractfile(member)
            if f:
                content_bytes = f.read()
                content = content_bytes.decode("utf-8", errors="ignore")
                parsed = []

                if basename == "requirements.txt":
                    parsed = self._parse_requirements_txt(content)
                elif basename == "package.json":
                    try:
                        data = json.loads(content)
                        parsed = self._parse_package_json(data)
                    except (json.JSONDecodeError, Exception):
                        self.warnings.append(f"Failed to parse {full_path}: invalid JSON")
                        continue
                elif basename == "pom.xml":
                    parsed = self._parse_pom_xml(content)

                if parsed:
                    print(f"  Found {len(parsed)} {lang_type} dependencies in {full_path}")
                    packages.extend(parsed)
                    new_files.add(full_path)

        return packages, new_files

    def _find_member_in_tar(self, tar: tarfile.TarFile, db_path: str) -> Optional[tarfile.TarInfo]:
        try:
            return tar.getmember(db_path)
        except KeyError:
            pass

        try:
            return tar.getmember(f"./{db_path}")
        except KeyError:
            pass

        for m in tar.getmembers():
            if m.name == db_path or m.name.endswith("/" + db_path):
                return m

        return None

    def _parse_dpkg_status(self, content: str) -> List[Package]:
        packages = []
        current_package: Dict[str, str] = {}

        for line in content.splitlines():
            if line.startswith("Package:"):
                if current_package and "Package" in current_package:
                    packages.append(
                        Package(
                            name=current_package["Package"],
                            version=current_package.get("Version", "unknown"),
                            source="os",
                        )
                    )
                current_package = {"Package": line[len("Package:"):].strip()}
            elif line.startswith("Version:"):
                current_package["Version"] = line[len("Version:"):].strip()
            elif ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                current_package[key.strip()] = value.strip()

        if current_package and "Package" in current_package:
            packages.append(
                Package(
                    name=current_package["Package"],
                    version=current_package.get("Version", "unknown"),
                    source="os",
                )
            )

        return packages

    def _parse_rpm_packages(self, content_bytes: bytes, file_path: str) -> List[Package]:
        packages: List[Package] = []

        try:
            import rpm
            ts = rpm.TransactionSet()
            hdr = ts.hdrFromFdno(io.BytesIO(content_bytes))
            name = hdr[rpm.RPMTAG_NAME].decode() if hdr[rpm.RPMTAG_NAME] else ""
            version = hdr[rpm.RPMTAG_VERSION].decode() if hdr[rpm.RPMTAG_VERSION] else ""
            release = hdr[rpm.RPMTAG_RELEASE].decode() if hdr[rpm.RPMTAG_RELEASE] else ""
            if name:
                full_version = f"{version}-{release}" if release else version
                packages.append(Package(name=name, version=full_version, source="os"))
            return packages
        except ImportError:
            pass
        except Exception as e:
            self.warnings.append(f"Python rpm library error: {e}")

        try:
            import subprocess
            result = subprocess.run(
                ["rpm", "-qp", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n", "-"],
                input=content_bytes,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) == 2 and parts[0]:
                        packages.append(Package(name=parts[0], version=parts[1], source="os"))
                if packages:
                    return packages
            else:
                self.warnings.append(f"rpm command failed: {result.stderr.strip()}")
        except FileNotFoundError:
            self.warnings.append(
                "'rpm' command not found. Install rpm package manager to parse RPM databases."
            )
        except Exception as e:
            self.warnings.append(f"rpm command error: {e}")

        try:
            packages = self._parse_rpm_berkeley_db(content_bytes)
            if packages:
                return packages
        except Exception as e:
            self.warnings.append(f"Berkeley DB RPM parsing failed: {e}")

        try:
            packages = self._parse_rpm_ndb(content_bytes)
            if packages:
                return packages
        except Exception as e:
            pass

        try:
            packages = self._parse_rpm_sqlite(content_bytes)
            if packages:
                return packages
        except Exception as e:
            pass

        return packages

    def _parse_rpm_berkeley_db(self, content_bytes: bytes) -> List[Package]:
        packages: List[Package] = []
        if len(content_bytes) < 4:
            return packages

        magic = content_bytes[:4]
        if magic == b"\x00\x06\x15\x61":
            self.warnings.append(
                "RPM Berkeley DB format detected. "
                "Please install 'libdb' and 'rpm' libraries for proper parsing."
            )
            return packages

        return packages

    def _parse_rpm_ndb(self, content_bytes: bytes) -> List[Package]:
        packages: List[Package] = []
        if len(content_bytes) < 16:
            return packages

        if content_bytes[:8] == b"RPM\x00NDBC":
            self.warnings.append(
                "RPM NDB (New Database) format detected. "
                "This format requires the rpm command with NDB support."
            )
            return packages

        return packages

    def _parse_rpm_sqlite(self, content_bytes: bytes) -> List[Package]:
        packages: List[Package] = []
        if len(content_bytes) < 16:
            return packages

        if content_bytes[:16] == b"SQLite format 3\x00":
            try:
                import sqlite3
                import tempfile

                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                    temp_db_path = f.name
                    f.write(content_bytes)

                try:
                    conn = sqlite3.connect(temp_db_path)
                    cursor = conn.cursor()
                    try:
                        cursor.execute(
                            "SELECT Name, Version, Release FROM Packages"
                        )
                        rows = cursor.fetchall()
                        for row in rows:
                            name, version, release = row
                            if name:
                                full_version = f"{version}-{release}" if release else version
                                packages.append(
                                    Package(name=name, version=full_version, source="os")
                                )
                        if packages:
                            print(f"  Successfully parsed {len(packages)} packages from RPM SQLite database")
                    except Exception as e:
                        self.warnings.append(f"RPM SQLite query failed: {e}")
                    finally:
                        conn.close()
                finally:
                    try:
                        os.unlink(temp_db_path)
                    except Exception:
                        pass
            except Exception as e:
                self.warnings.append(f"RPM SQLite parse error: {e}")

            if not packages:
                self.warnings.append(
                    "RPM SQLite database detected but could not extract packages. "
                    "The schema may be incompatible."
                )

        return packages

    def _parse_apk_installed(self, content: str) -> List[Package]:
        packages = []
        current_package: Dict[str, str] = {}

        for line in content.splitlines():
            if line.startswith("P:"):
                if current_package and "P" in current_package:
                    packages.append(
                        Package(
                            name=current_package["P"],
                            version=current_package.get("V", "unknown"),
                            source="os",
                        )
                    )
                current_package = {"P": line[2:].strip()}
            elif line.startswith("V:"):
                current_package["V"] = line[2:].strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                current_package[key.strip()] = value.strip()

        if current_package and "P" in current_package:
            packages.append(
                Package(
                    name=current_package["P"],
                    version=current_package.get("V", "unknown"),
                    source="os",
                )
            )

        return packages

    def _parse_requirements_txt(self, content: str) -> List[Package]:
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_-]+)([<>=!~]+)([^,]+)", line)
            if match:
                name = match.group(1)
                version = match.group(3).strip()
                packages.append(Package(name=name, version=version, source="python"))
            else:
                name = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                if name:
                    packages.append(Package(name=name, version="unknown", source="python"))
        return packages

    def _parse_package_json(self, data: dict) -> List[Package]:
        packages = []
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        for name, version in all_deps.items():
            version_clean = version.lstrip("^~>=<")
            packages.append(Package(name=name, version=version_clean, source="nodejs"))
        return packages

    def _parse_pom_xml(self, content: str) -> List[Package]:
        packages = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}

            dependencies = root.findall(".//m:dependency", ns)
            use_ns = len(dependencies) > 0
            if not use_ns:
                dependencies = root.findall(".//dependency")

            for dep in dependencies:
                if use_ns:
                    groupId = dep.find("m:groupId", ns)
                    artifactId = dep.find("m:artifactId", ns)
                    version = dep.find("m:version", ns)
                else:
                    groupId = dep.find("groupId")
                    artifactId = dep.find("artifactId")
                    version = dep.find("version")

                if artifactId is not None and artifactId.text:
                    name = artifactId.text
                    ver = version.text if version is not None and version.text else "unknown"
                    packages.append(Package(name=name, version=ver, source="java"))
        except Exception as e:
            self.warnings.append(f"pom.xml parse error: {e}")
        return packages
