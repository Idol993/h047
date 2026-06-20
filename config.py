import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
OSV_API_URL = "https://api.osv.dev/v1/query"

NVD_RATE_LIMIT = 5
REQUEST_INTERVAL = 1.0 / NVD_RATE_LIMIT
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
    "dpkg": "var/lib/dpkg/status",
    "rpm": "var/lib/rpm/Packages",
    "apk": "lib/apk/db/installed",
}

LANGUAGE_DEP_FILES = {
    "python": "requirements.txt",
    "nodejs": "package.json",
    "java": "pom.xml",
}
