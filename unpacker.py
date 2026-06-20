import os
import io
import tarfile
import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from config import PACKAGE_DB_PATHS, LANGUAGE_DEP_FILES


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
        pass

    def scan(self, image_source: str) -> List[Package]:
        if os.path.isfile(image_source) and image_source.endswith(".tar"):
            return self._scan_local_tar(image_source)
        else:
            return self._scan_remote_image(image_source)

    def _scan_local_tar(self, tar_path: str) -> List[Package]:
        with tarfile.open(tar_path, "r") as tar:
            return self._extract_packages_from_tar(tar)

    def _scan_remote_image(self, image_name: str) -> List[Package]:
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

    def _extract_packages_from_image_tar(self, outer_tar: tarfile.TarFile) -> List[Package]:
        layer_tars = []
        for member in outer_tar.getmembers():
            if member.isfile() and member.name.endswith("/layer.tar"):
                layer_tars.append(member.name)

        all_packages: List[Package] = []
        found_dbs = set()

        for layer_tar_name in layer_tars:
            layer_file = outer_tar.extractfile(layer_tar_name)
            if layer_file is None:
                continue

            with tarfile.open(fileobj=layer_file, mode="r") as layer_tar:
                packages, dbs_found = self._scan_layer(layer_tar, found_dbs)
                all_packages.extend(packages)
                found_dbs.update(dbs_found)
                if found_dbs == set(PACKAGE_DB_PATHS.keys()):
                    break

        if not all_packages:
            for layer_tar_name in layer_tars:
                layer_file = outer_tar.extractfile(layer_tar_name)
                if layer_file is None:
                    continue
                with tarfile.open(fileobj=layer_file, mode="r") as layer_tar:
                    lang_packages = self._extract_language_deps(layer_tar)
                    all_packages.extend(lang_packages)

        return all_packages

    def _extract_packages_from_tar(self, tar: tarfile.TarFile) -> List[Package]:
        packages, _ = self._scan_layer(tar, set())
        lang_packages = self._extract_language_deps(tar)
        return packages + lang_packages

    def _scan_layer(
        self, tar: tarfile.TarFile, found_dbs: set
    ) -> Tuple[List[Package], set]:
        packages: List[Package] = []
        new_dbs = set()

        for db_type, db_path in PACKAGE_DB_PATHS.items():
            if db_type in found_dbs:
                continue

            member = None
            try:
                member = tar.getmember(db_path)
            except KeyError:
                alt_paths = [f"./{db_path}"]
                for p in alt_paths:
                    try:
                        member = tar.getmember(p)
                        break
                    except KeyError:
                        continue

            if member is None:
                for m in tar.getmembers():
                    if m.name.endswith("/" + db_path) or m.name == db_path:
                        member = m
                        break

            if member and member.isfile():
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    if db_type == "dpkg":
                        packages.extend(self._parse_dpkg_status(content))
                    elif db_type == "rpm":
                        packages.extend(self._parse_rpm_packages(content))
                    elif db_type == "apk":
                        packages.extend(self._parse_apk_installed(content))
                    new_dbs.add(db_type)

        return packages, new_dbs

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

    def _parse_rpm_packages(self, content: str) -> List[Package]:
        packages = []
        try:
            import rpm
            ts = rpm.TransactionSet()
            hdr = ts.hdrFromFdno(io.BytesIO(content.encode()))
            name = hdr[rpm.RPMTAG_NAME].decode() if hdr[rpm.RPMTAG_NAME] else ""
            version = hdr[rpm.RPMTAG_VERSION].decode() if hdr[rpm.RPMTAG_VERSION] else ""
            if name:
                packages.append(Package(name=name, version=version, source="os"))
        except ImportError:
            try:
                import subprocess
                result = subprocess.run(
                    ["rpm", "-qp", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n", "-"],
                    input=content.encode(),
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().splitlines():
                        parts = line.strip().split("\t")
                        if len(parts) == 2:
                            packages.append(Package(name=parts[0], version=parts[1], source="os"))
            except Exception:
                pass
        except Exception:
            pass
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

    def _extract_language_deps(self, tar: tarfile.TarFile) -> List[Package]:
        packages = []

        for member in tar.getmembers():
            if not member.isfile():
                continue

            basename = os.path.basename(member.name)

            if basename == "requirements.txt":
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    packages.extend(self._parse_requirements_txt(content))
            elif basename == "package.json":
                f = tar.extractfile(member)
                if f:
                    try:
                        data = json.loads(f.read().decode("utf-8", errors="ignore"))
                        packages.extend(self._parse_package_json(data))
                    except (json.JSONDecodeError, Exception):
                        pass
            elif basename == "pom.xml":
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="ignore")
                    packages.extend(self._parse_pom_xml(content))

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
            if not dependencies:
                dependencies = root.findall(".//dependency")
            for dep in dependencies:
                groupId = dep.find("groupId")
                artifactId = dep.find("artifactId")
                version = dep.find("version")
                if artifactId is not None and artifactId.text:
                    name = artifactId.text
                    ver = version.text if version is not None and version.text else "unknown"
                    packages.append(Package(name=name, version=ver, source="java"))
        except Exception:
            pass
        return packages
