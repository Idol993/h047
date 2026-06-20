import sqlite3
import time
import json
import threading
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from config import (
    NVD_API_URL,
    NVD_API_KEY,
    REQUEST_INTERVAL,
    MAX_WORKERS,
    CVSS_SEVERITY_LEVELS,
    SEVERITY_RANK,
    CACHE_DB_PATH,
)


class Vulnerability:
    def __init__(
        self,
        cve_id: str,
        cvss_score: float,
        severity: str,
        description: str = "",
        fix_version: str = "",
        package_name: str = "",
        package_version: str = "",
    ):
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.severity = severity
        self.description = description
        self.fix_version = fix_version
        self.package_name = package_name
        self.package_version = package_version

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "fix_version": self.fix_version,
            "package_name": self.package_name,
            "package_version": self.package_version,
        }


def get_severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    else:
        return "low"


class VulnDB:
    def __init__(self, db_path: str = CACHE_DB_PATH, offline: bool = False):
        self.db_path = db_path
        self.offline = offline
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                fix_version TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(package_name, version, cve_id)
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_pkg_version ON vulnerabilities(package_name, version)"
        )
        conn.commit()
        conn.close()

    def _get_cached(self, package_name: str, version: str) -> List[Vulnerability]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT cve_id, cvss_score, severity, description, fix_version
            FROM vulnerabilities
            WHERE package_name = ? AND version = ?
            """,
            (package_name, version),
        )
        rows = cursor.fetchall()
        conn.close()
        vulns = []
        for row in rows:
            vulns.append(
                Vulnerability(
                    cve_id=row[0],
                    cvss_score=row[1],
                    severity=row[2],
                    description=row[3] or "",
                    fix_version=row[4] or "",
                    package_name=package_name,
                    package_version=version,
                )
            )
        return vulns

    def _cache_vulns(
        self, package_name: str, version: str, vulns: List[Vulnerability]
    ):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for vuln in vulns:
            cursor.execute(
                """
                INSERT OR IGNORE INTO vulnerabilities
                (package_name, version, cve_id, cvss_score, severity, description, fix_version)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    package_name,
                    version,
                    vuln.cve_id,
                    vuln.cvss_score,
                    vuln.severity,
                    vuln.description,
                    vuln.fix_version,
                ),
            )
        conn.commit()
        conn.close()

    def _rate_limited_request(self, params: dict) -> Optional[dict]:
        if self.offline:
            return None

        with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < REQUEST_INTERVAL:
                time.sleep(REQUEST_INTERVAL - elapsed)
            self._last_request_time = time.time()

        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def _query_nvd(self, package_name: str, version: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        cpe_match = f"cpe:2.3:a:*:{package_name}:{version}:*:*:*:*:*:*:*"
        params = {"cpeMatchString": cpe_match, "resultsPerPage": 20}

        data = self._rate_limited_request(params)
        if not data:
            return vulns

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            cvss_score = 0.0
            severity = "low"
            metrics = cve.get("metrics", {})
            cvss_metric = None
            if "cvssMetricV31" in metrics:
                cvss_metric = metrics["cvssMetricV31"][0]
            elif "cvssMetricV30" in metrics:
                cvss_metric = metrics["cvssMetricV30"][0]
            elif "cvssMetricV2" in metrics:
                cvss_metric = metrics["cvssMetricV2"][0]

            if cvss_metric:
                cvss_data = cvss_metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_metric.get("baseSeverity", "").lower()
                if not severity:
                    severity = get_severity_from_score(cvss_score)

            fix_version = ""
            references = cve.get("references", [])
            for ref in references:
                tags = ref.get("tags", [])
                if "Patch" in tags or "Vendor Advisory" in tags:
                    fix_version = ref.get("url", "")
                    break

            vulns.append(
                Vulnerability(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    description=description,
                    fix_version=fix_version,
                    package_name=package_name,
                    package_version=version,
                )
            )

        return vulns

    def get_vulnerabilities(
        self, package_name: str, version: str
    ) -> List[Vulnerability]:
        cached = self._get_cached(package_name, version)
        if cached or self.offline:
            return cached

        vulns = self._query_nvd(package_name, version)
        if vulns:
            self._cache_vulns(package_name, version, vulns)

        return vulns

    def scan_packages(
        self, packages: List, severity_threshold: str = "low"
    ) -> List[Vulnerability]:
        all_vulns: List[Vulnerability] = []
        threshold_rank = SEVERITY_RANK.get(severity_threshold, 1)

        def scan_single(pkg):
            return self.get_vulnerabilities(pkg.name, pkg.version)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_pkg = {
                executor.submit(scan_single, pkg): pkg for pkg in packages}
            for future in as_completed(future_to_pkg):
                pkg = future_to_pkg[future]
                try:
                    vulns = future.result()
                    for vuln in vulns:
                        vuln_rank = SEVERITY_RANK.get(vuln.severity, 1)
                        if vuln_rank >= threshold_rank:
                            all_vulns.append(vuln)
                except Exception as e:
                    print(f"Error scanning {pkg.name}: {e}")

        all_vulns.sort(key=lambda v: v.cvss_score, reverse=True)
        return all_vulns
