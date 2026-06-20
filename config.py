import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
OSV_API_URL = "https://api.osv.dev/v1/query"

NVD_RATE_LIMIT = 5
REQUEST_INTERVAL = 1.0 / NVD_RATE_LIMIT
OSV_REQUEST_INTERVAL = 0.25
MAX_WORKERS = 5

CVSS_SEVERITY_LEVELS = {
    "low": (0.0, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

CACHE_DB_PATH = "cache.db"

PACKAGE_DB_PATHS = {
    "dpkg": ["var/lib/dpkg/status"],
    "rpm": [
        "var/lib/rpm/Packages",
        "usr/lib/sysimage/rpm/Packages",
        "var/lib/rpm/rpmdb.sqlite",
        "usr/lib/sysimage/rpm/rpmdb.sqlite",
    ],
    "apk": ["lib/apk/db/installed"],
}

LANGUAGE_DEP_FILES = {
    "python": "requirements.txt",
    "nodejs": "package.json",
    "java": "pom.xml",
}

OSV_ECOSYSTEM_MAP = {
    "python": "PyPI",
    "nodejs": "npm",
    "java": "Maven",
}

SOURCE_LABELS = {
    "os": "os",
    "python": "python",
    "nodejs": "nodejs",
    "java": "java",
}


class IgnorePolicy:
    def __init__(self):
        self.ignored_cves: set = set()
        self.ignored_packages: set = set()
        self.ignored_severities: set = set()
        self.rules: list = []

    def load_file(self, path: str) -> bool:
        import os
        if not os.path.exists(path):
            return False

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("cve:") or line.startswith("CVE-"):
                    cve = line[4:] if line.startswith("cve:") else line
                    cve = cve.strip().upper()
                    if cve:
                        self.ignored_cves.add(cve)
                        self.rules.append(("cve", cve))
                elif line.startswith("package:"):
                    pkg = line[len("package:"):].strip()
                    if pkg:
                        self.ignored_packages.add(pkg)
                        self.rules.append(("package", pkg))
                elif line.startswith("severity:"):
                    sev = line[len("severity:"):].strip().lower()
                    if sev in SEVERITY_RANK:
                        self.ignored_severities.add(sev)
                        self.rules.append(("severity", sev))
                else:
                    if line.upper().startswith("CVE-"):
                        self.ignored_cves.add(line.upper())
                        self.rules.append(("cve", line.upper()))

        return True

    def is_ignored(self, cve_id: str = "", package_name: str = "", severity: str = "") -> bool:
        if cve_id and cve_id.upper() in self.ignored_cves:
            return True
        if package_name and package_name in self.ignored_packages:
            return True
        if severity and severity.lower() in self.ignored_severities:
            return True
        return False

    def has_rules(self) -> bool:
        return len(self.rules) > 0

    def rule_count(self) -> int:
        return len(self.rules)
