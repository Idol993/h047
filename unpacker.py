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

    def _is_oci_format(self, tar: tarfile.TarFile) -> bool:
        try:
            oci_layout = tar.getmember("oci-layout")
            if oci_layout is None:
                return False
        except KeyError:
            return False

        try:
            index_json = tar.getmember("index.json")
            if index_json is None:
                return False
        except KeyError:
            return False

        for member in tar.getmembers():
            if member.name.startswith("blobs/sha256/") and member.isfile():
                return True

        return False

    def _read_manifest_layer_order(self, outer_tar: tarfile.TarFile) -> Optional[List[str]]:
        try:
            manifest_member = outer_tar.getmember("manifest.json")
        except KeyError:
            return None

        f = outer_tar.extractfile(manifest_member)
        if f is None:
            return None

        try:
            manifest_data = json.loads(f.read().decode("utf-8"))
        except (json.JSONDecodeError, Exception):
            return None

        if isinstance(manifest_data, list) and len(manifest_data) > 0:
            layers = manifest_data[0].get("Layers", [])
            if layers:
                return layers
        return None

    def _scan_local_tar(self, tar_path: str) -> ScanResult:
        with tarfile.open(tar_path, "r") as tar:
            if self._is_oci_format(tar):
                print(f"Detected OCI archive format, extracting from blobs...")
                return self._extract_packages_from_oci_tar(tar)
            elif self._is_docker_save_format(tar):
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
        manifest_order = self._read_manifest_layer_order(outer_tar)

        if manifest_order:
            print(f"Using manifest layer order ({len(manifest_order)} layers)")
            layer_tars = manifest_order
        else:
            print("Warning: manifest.json missing or invalid, using tar file order")
            layer_tars = []
            for member in outer_tar.getmembers():
                if member.isfile() and member.name.endswith("/layer.tar"):
                    layer_tars.append(member.name)

        print(f"Found {len(layer_tars)} layers to scan")

        last_dpkg_content: Optional[str] = None
        last_rpm_content: Optional[bytes] = None
        last_rpm_path: Optional[str] = None
        last_apk_content: Optional[str] = None
        last_os_db_sources: Dict[str, str] = {}

        all_lang_packages: List[Package] = []
        seen_lang_files: Set[str] = set()

        for layer_idx, layer_tar_name in enumerate(layer_tars):
            try:
                layer_member = outer_tar.getmember(layer_tar_name)
            except KeyError:
                print(f"  Layer {layer_idx}: {layer_tar_name} not found in tar, skipping")
                continue

            layer_file = outer_tar.extractfile(layer_member)
            if layer_file is None:
                continue

            with tarfile.open(fileobj=layer_file, mode="r") as layer_tar:
                dpkg_status_content = self._extract_os_db_content(layer_tar, "dpkg", layer_idx)
                if dpkg_status_content is not None:
                    last_dpkg_content = dpkg_status_content
                    last_os_db_sources["dpkg"] = f"Layer {layer_idx}"

                rpm_content_tuple = self._extract_os_db_content(layer_tar, "rpm", layer_idx)
                if rpm_content_tuple is not None:
                    last_rpm_content, rpm_path = rpm_content_tuple
                    last_rpm_path = rpm_path
                    last_os_db_sources["rpm"] = f"Layer {layer_idx} ({rpm_path})"

                apk_content = self._extract_os_db_content(layer_tar, "apk", layer_idx)
                if apk_content is not None:
                    last_apk_content = apk_content
                    last_os_db_sources["apk"] = f"Layer {layer_idx}"

                lang_packages, new_files = self._scan_layer_for_language_deps(
                    layer_tar, seen_lang_files
                )
                all_lang_packages.extend(lang_packages)
                seen_lang_files.update(new_files)

        final_os_packages: List[Package] = []

        if last_dpkg_content is not None:
            dpkg_packages = self._parse_dpkg_status(last_dpkg_content)
            print(f"  Final dpkg packages: {len(dpkg_packages)} (from {last_os_db_sources.get('dpkg', 'unknown')})")
            final_os_packages.extend(dpkg_packages)

        if last_rpm_content is not None:
            rpm_packages = self._parse_rpm_packages(
                last_rpm_content, last_rpm_path or "unknown", last_rpm_path or "var/lib/rpm/Packages"
            )
            print(f"  Final rpm packages: {len(rpm_packages)} (from {last_os_db_sources.get('rpm', 'unknown')})")
            final_os_packages.extend(rpm_packages)

        if last_apk_content is not None:
            apk_packages = self._parse_apk_installed(last_apk_content)
            print(f"  Final apk packages: {len(apk_packages)} (from {last_os_db_sources.get('apk', 'unknown')})")
            final_os_packages.extend(apk_packages)

        for db_type, source_info in last_os_db_sources.items():
            print(f"  {db_type} database source: {source_info}")

        all_packages = final_os_packages + all_lang_packages

        if not all_packages:
            for warning in self.warnings:
                print(f"Warning: {warning}")

        return ScanResult(packages=all_packages, warnings=self.warnings)

    def _extract_packages_from_oci_tar(self, outer_tar: tarfile.TarFile) -> ScanResult:
        try:
            index_member = outer_tar.getmember("index.json")
            index_f = outer_tar.extractfile(index_member)
            if index_f is None:
                self.warnings.append("OCI index.json not readable")
                return ScanResult(packages=[], warnings=self.warnings)
            index_data = json.loads(index_f.read().decode("utf-8"))
        except (KeyError, json.JSONDecodeError, Exception) as e:
            self.warnings.append(f"Failed to parse OCI index.json: {e}")
            return ScanResult(packages=[], warnings=self.warnings)

        manifests = index_data.get("manifests", [])
        if not manifests:
            self.warnings.append("OCI index.json has no manifests")
            return ScanResult(packages=[], warnings=self.warnings)

        first_manifest = manifests[0]
        manifest_digest = first_manifest.get("digest", "")
        if not manifest_digest:
            self.warnings.append("OCI first manifest missing digest")
            return ScanResult(packages=[], warnings=self.warnings)

        manifest_blob_path = f"blobs/sha256/{manifest_digest.split(':')[-1]}"
        try:
            manifest_member = outer_tar.getmember(manifest_blob_path)
            manifest_f = outer_tar.extractfile(manifest_member)
            if manifest_f is None:
                self.warnings.append(f"OCI manifest blob not readable: {manifest_blob_path}")
                return ScanResult(packages=[], warnings=self.warnings)
            manifest_data = json.loads(manifest_f.read().decode("utf-8"))
        except (KeyError, json.JSONDecodeError, Exception) as e:
            self.warnings.append(f"Failed to read OCI manifest blob: {e}")
            return ScanResult(packages=[], warnings=self.warnings)

        layers = manifest_data.get("layers", [])
        layer_digests = [layer.get("digest", "") for layer in layers if layer.get("digest", "")]
        print(f"Using OCI manifest layer order ({len(layer_digests)} layers)")
        print(f"Found {len(layer_digests)} layers to scan")

        last_dpkg_content: Optional[str] = None
        last_rpm_content: Optional[bytes] = None
        last_rpm_path: Optional[str] = None
        last_apk_content: Optional[str] = None
        last_os_db_sources: Dict[str, str] = {}

        all_lang_packages: List[Package] = []
        seen_lang_files: Set[str] = set()

        for layer_idx, layer_digest in enumerate(layer_digests):
            layer_blob_path = f"blobs/sha256/{layer_digest.split(':')[-1]}"
            try:
                layer_member = outer_tar.getmember(layer_blob_path)
            except KeyError:
                print(f"  Layer {layer_idx}: {layer_blob_path} not found, skipping")
                continue

            layer_file = outer_tar.extractfile(layer_member)
            if layer_file is None:
                continue

            try:
                layer_tar = tarfile.open(fileobj=layer_file, mode="r")
            except Exception:
                continue

            with layer_tar:
                dpkg_status_content = self._extract_os_db_content(layer_tar, "dpkg", layer_idx)
                if dpkg_status_content is not None:
                    last_dpkg_content = dpkg_status_content
                    last_os_db_sources["dpkg"] = f"Layer {layer_idx}"

                rpm_content_tuple = self._extract_os_db_content(layer_tar, "rpm", layer_idx)
                if rpm_content_tuple is not None:
                    last_rpm_content, rpm_path = rpm_content_tuple
                    last_rpm_path = rpm_path
                    last_os_db_sources["rpm"] = f"Layer {layer_idx} ({rpm_path})"

                apk_content = self._extract_os_db_content(layer_tar, "apk", layer_idx)
                if apk_content is not None:
                    last_apk_content = apk_content
                    last_os_db_sources["apk"] = f"Layer {layer_idx}"

                lang_packages, new_files = self._scan_layer_for_language_deps(
                    layer_tar, seen_lang_files
                )
                all_lang_packages.extend(lang_packages)
                seen_lang_files.update(new_files)

        final_os_packages: List[Package] = []

        if last_dpkg_content is not None:
            dpkg_packages = self._parse_dpkg_status(last_dpkg_content)
            print(f"  Final dpkg packages: {len(dpkg_packages)} (from {last_os_db_sources.get('dpkg', 'unknown')})")
            final_os_packages.extend(dpkg_packages)

        if last_rpm_content is not None:
            rpm_packages = self._parse_rpm_packages(
                last_rpm_content, last_rpm_path or "unknown", last_rpm_path or "var/lib/rpm/Packages"
            )
            print(f"  Final rpm packages: {len(rpm_packages)} (from {last_os_db_sources.get('rpm', 'unknown')})")
            final_os_packages.extend(rpm_packages)

        if last_apk_content is not None:
            apk_packages = self._parse_apk_installed(last_apk_content)
            print(f"  Final apk packages: {len(apk_packages)} (from {last_os_db_sources.get('apk', 'unknown')})")
            final_os_packages.extend(apk_packages)

        for db_type, source_info in last_os_db_sources.items():
            print(f"  {db_type} database source: {source_info}")

        all_packages = final_os_packages + all_lang_packages

        if not all_packages:
            for warning in self.warnings:
                print(f"Warning: {warning}")

        return ScanResult(packages=all_packages, warnings=self.warnings)

    def _extract_os_db_content(
        self, tar: tarfile.TarFile, db_type: str, layer_idx: int
    ) -> Optional:
        db_paths = PACKAGE_DB_PATHS.get(db_type, [])
        if isinstance(db_paths, str):
            db_paths = [db_paths]

        if db_type == "rpm":
            return self._extract_rpm_content_multi_path(tar, db_paths, layer_idx)

        for db_path in db_paths:
            member = self._find_member_in_tar(tar, db_path)
            if member and member.isfile():
                f = tar.extractfile(member)
                if f:
                    content_bytes = f.read()
                    content = content_bytes.decode("utf-8", errors="ignore")
                    if content.strip():
                        print(f"  Layer {layer_idx}: Found {db_type} database ({db_path})")
                        return content
        return None

    def _extract_rpm_content_multi_path(
        self, tar: tarfile.TarFile, db_paths: List[str], layer_idx: int
    ) -> Optional[Tuple[bytes, str]]:
        rpm_warnings_for_layer = []

        for db_path in db_paths:
            member = self._find_member_in_tar(tar, db_path)
            if not (member and member.isfile()):
                continue

            f = tar.extractfile(member)
            if f is None:
                continue

            content_bytes = f.read()
            if not content_bytes:
                continue

            packages = self._parse_rpm_packages_fast(content_bytes, db_path)
            if packages:
                print(f"  Layer {layer_idx}: Found {len(packages)} rpm packages ({db_path})")
                return (content_bytes, db_path)
            else:
                if content_bytes[:16] == b"SQLite format 3\x00":
                    rpm_warnings_for_layer.append(
                        f"RPM SQLite at {db_path} (empty or unparseable)"
                    )
                elif len(content_bytes) >= 4 and content_bytes[:4] == b"\x00\x06\x15\x61":
                    rpm_warnings_for_layer.append(
                        f"RPM BDB at {db_path} (no rpm libs available)"
                    )
                elif len(content_bytes) >= 8 and content_bytes[:8] == b"RPM\x00NDBC":
                    rpm_warnings_for_layer.append(
                        f"RPM NDB at {db_path} (no rpm libs available)"
                    )
                else:
                    rpm_warnings_for_layer.append(
                        f"RPM database at {db_path} unrecognized format, "
                        f"magic={content_bytes[:8].hex() if len(content_bytes) >= 8 else 'N/A'}"
                    )

        if rpm_warnings_for_layer:
            self.warnings.extend(rpm_warnings_for_layer)

        return None

    def _parse_rpm_packages_fast(self, content_bytes: bytes, db_path: str) -> List[Package]:
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
        except Exception:
            pass

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
        except Exception:
            pass

        if content_bytes[:16] == b"SQLite format 3\x00":
            sqlite_packages = self._parse_rpm_sqlite(content_bytes)
            if sqlite_packages:
                return sqlite_packages

        return packages

    def _extract_packages_from_filesystem_tar(self, tar: tarfile.TarFile) -> List[Package]:
        os_packages = []

        dpkg_content = self._extract_os_db_content(tar, "dpkg", 0)
        if dpkg_content:
            os_packages.extend(self._parse_dpkg_status(dpkg_content))

        rpm_tuple = self._extract_rpm_content_multi_path(
            tar, PACKAGE_DB_PATHS.get("rpm", []), 0
        )
        if rpm_tuple is not None:
            rpm_bytes, rpm_path = rpm_tuple
            os_packages.extend(self._parse_rpm_packages(rpm_bytes, rpm_path, rpm_path))

        apk_content = self._extract_os_db_content(tar, "apk", 0)
        if apk_content:
            os_packages.extend(self._parse_apk_installed(apk_content))

        lang_packages, _ = self._scan_layer_for_language_deps(tar, set())
        return os_packages + lang_packages

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
                    status = current_package.get("Status", "")
                    if status == "install ok installed":
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
            elif line.startswith("Status:"):
                current_package["Status"] = line[len("Status:"):].strip()
            elif ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                current_package[key.strip()] = value.strip()

        if current_package and "Package" in current_package:
            status = current_package.get("Status", "")
            if status == "install ok installed":
                packages.append(
                    Package(
                        name=current_package["Package"],
                        version=current_package.get("Version", "unknown"),
                        source="os",
                    )
                )

        return packages

    def _parse_rpm_packages(self, content_bytes: bytes, file_path: str, db_path: str) -> List[Package]:
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
                err = result.stderr.strip()
                if err:
                    self.warnings.append(f"rpm command failed for {db_path}: {err}")
        except FileNotFoundError:
            self.warnings.append(
                f"'rpm' command not found. Install rpm package manager to parse RPM databases "
                f"at {db_path}."
            )
        except Exception as e:
            self.warnings.append(f"rpm command error for {db_path}: {e}")

        if content_bytes[:16] == b"SQLite format 3\x00":
            packages = self._parse_rpm_sqlite(content_bytes)
            if packages:
                return packages
            self.warnings.append(
                f"RPM SQLite database found at {db_path} but query failed. "
                f"The schema may differ from expected 'Packages' table with "
                f"'Name/Version/Release' columns. "
                f"Try: sqlite3 <image-extracted-path> '.tables' to inspect schema."
            )
            return packages

        if len(content_bytes) >= 4 and content_bytes[:4] == b"\x00\x06\x15\x61":
            self.warnings.append(
                f"RPM Berkeley DB format detected at {db_path}. "
                f"This is a BDB hash database used by rpm on RHEL 7 and earlier. "
                f"To parse it: (1) run on a RHEL/CentOS host with 'rpm' installed, "
                f"or (2) install python 'rpm' bindings (yum install rpm-python3)."
            )
            return packages

        if len(content_bytes) >= 8 and content_bytes[:8] == b"RPM\x00NDBC":
            self.warnings.append(
                f"RPM NDB format detected at {db_path}. "
                f"This is the newer rpm database format used in Fedora/RHEL 9+. "
                f"Requires rpm >= 4.17 with NDB support to parse. "
                f"Try: rpm --query --all on a compatible host."
            )
            return packages

        self.warnings.append(
            f"RPM database found at {db_path} but format is unrecognized "
            f"(not SQLite, BDB, or NDB). Size: {len(content_bytes)} bytes, "
            f"magic: {content_bytes[:8].hex() if len(content_bytes) >= 8 else 'N/A'}. "
            f"Try: file <path> to identify format, or use 'rpm -qa' on a compatible host."
        )
        return packages

    def _parse_rpm_sqlite(self, content_bytes: bytes) -> List[Package]:
        packages: List[Package] = []
        if len(content_bytes) < 16:
            return packages

        if content_bytes[:16] != b"SQLite format 3\x00":
            return packages

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
                    table_name, name_col, version_col, release_col = self._detect_rpm_sqlite_schema(cursor)

                    if table_name and name_col:
                        query = f'SELECT {name_col}, {version_col}, {release_col} FROM {table_name}'
                        cursor.execute(query)
                        rows = cursor.fetchall()
                        for row in rows:
                            name = row[0] if len(row) > 0 else ""
                            version = row[1] if len(row) > 1 else ""
                            release = row[2] if len(row) > 2 else ""
                            if name:
                                if isinstance(name, bytes):
                                    name = name.decode("utf-8", errors="ignore")
                                if isinstance(version, bytes):
                                    version = version.decode("utf-8", errors="ignore")
                                if isinstance(release, bytes):
                                    release = release.decode("utf-8", errors="ignore")
                                full_version = f"{version}-{release}" if release else version
                                packages.append(
                                    Package(name=name, version=full_version, source="os")
                                )
                    if packages:
                        print(f"  Successfully parsed {len(packages)} packages from RPM SQLite database ({table_name})")
                    else:
                        tbl = table_name or "(unknown)"
                        self.warnings.append(
                            f"RPM SQLite database detected but no packages found in table '{tbl}'. "
                            f"Schema may differ from expected. "
                            f"Try: sqlite3 <image-extracted-path> '.tables' to inspect schema."
                        )
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

        return packages

    def _detect_rpm_sqlite_schema(self, cursor) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        table_candidates = ["Packages", "packages", "rpm_packages", "Packages_table"]
        name_candidates = ["Name", "name", "pkgName", "pkg_name"]
        version_candidates = ["Version", "version", "pkgVersion", "pkg_version"]
        release_candidates = ["Release", "release", "pkgRelease", "pkg_release"]

        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            all_tables = [row[0] for row in cursor.fetchall()]
        except Exception:
            return None, None, None, None

        table_name = None
        for cand in table_candidates:
            if cand in all_tables:
                table_name = cand
                break

        if not table_name:
            for t in all_tables:
                if "package" in t.lower():
                    table_name = t
                    break

        if not table_name:
            return None, None, None, None

        try:
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [row[1] for row in cursor.fetchall()]
        except Exception:
            return None, None, None, None

        name_col = None
        for cand in name_candidates:
            if cand in columns:
                name_col = cand
                break
        if not name_col:
            for col in columns:
                if "name" in col.lower():
                    name_col = col
                    break

        version_col = None
        for cand in version_candidates:
            if cand in columns:
                version_col = cand
                break
        if not version_col:
            for col in columns:
                if "version" in col.lower():
                    version_col = col
                    break

        release_col = None
        for cand in release_candidates:
            if cand in columns:
                release_col = cand
                break
        if not release_col:
            for col in columns:
                if "release" in col.lower():
                    release_col = col
                    break

        return table_name, name_col, version_col, release_col

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
                    gid = groupId.text if groupId is not None and groupId.text else ""
                    aid = artifactId.text
                    ver = version.text if version is not None and version.text else "unknown"
                    if gid:
                        full_name = f"{gid}:{aid}"
                    else:
                        full_name = aid
                    packages.append(Package(name=full_name, version=ver, source="java"))
        except Exception as e:
            self.warnings.append(f"pom.xml parse error: {e}")
        return packages
