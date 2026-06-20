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
    OSV_API_URL,
    REQUEST_INTERVAL,
    OSV_REQUEST_INTERVAL,
    MAX_WORKERS,
    CVSS_SEVERITY_LEVELS,
    SEVERITY_RANK,
    CACHE_DB_PATH,
    OSV_ECOSYSTEM_MAP,
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
        source: str = "os",
    ):
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.severity = severity
        self.description = description
        self.fix_version = fix_version
        self.package_name = package_name
        self.package_version = package_version
        self.source = source

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "fix_version": self.fix_version,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "source": self.source,
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
                source TEXT DEFAULT 'os',
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(package_name, version, cve_id)
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_pkg_version ON vulnerabilities(package_name, version)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_source ON vulnerabilities(source)"
        )
        conn.commit()
        conn.close()

    def _get_cached(self, package_name: str, version: str) -> List[Vulnerability]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT cve_id, cvss_score, severity, description, fix_version, source
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
                    source=row[5] or "os",
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
                (package_name, version, cve_id, cvss_score, severity, description, fix_version, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    package_name,
                    version,
                    vuln.cve_id,
                    vuln.cvss_score,
                    vuln.severity,
                    vuln.description,
                    vuln.fix_version,
                    vuln.source,
                ),
            )
        conn.commit()
        conn.close()

    def _rate_limited_nvd_request(self, params: dict) -> Optional[dict]:
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
            print(f"NVD request failed: {e}")
            return None

    def _rate_limited_osv_request(self, payload: dict) -> Optional[dict]:
        if self.offline:
            return None

        with self._lock:
            elapsed = time.time() - self._last_request_time
            min_interval = min(REQUEST_INTERVAL, OSV_REQUEST_INTERVAL)
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request_time = time.time()

        try:
            response = requests.post(OSV_API_URL, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"OSV request failed: {e}")
            return None

    def _query_nvd(self, package_name: str, version: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        cpe_match = f"cpe:2.3:a:*:{package_name}:{version}:*:*:*:*:*:*:*"
        params = {"cpeMatchString": cpe_match, "resultsPerPage": 20}

        data = self._rate_limited_nvd_request(params)
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
                    source="os",
                )
            )

        return vulns

    def _query_osv(
        self, package_name: str, version: str, ecosystem: str
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }

        data = self._rate_limited_osv_request(payload)
        if not data:
            return vulns

        osv_vulns = data.get("vulns", [])
        for osv_vuln in osv_vulns:
            vuln_id = osv_vuln.get("id", "")

            cve_id = vuln_id
            aliases = osv_vuln.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            cvss_score = 0.0
            severity = "low"
            severity_info = osv_vuln.get("database_specific", {}).get("severity", "")
            if severity_info:
                severity = severity_info.lower()

            for s in osv_vuln.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    cvss_vector = s.get("score", "")
                    if "CVSS:3" in cvss_vector:
                        try:
                            parts = cvss_vector.split("/")
                            for part in parts:
                                if part.startswith("AV:"):
                                    pass
                            import re
                            base_score_match = re.search(r'CVSS:3[._]\d./AV', cvss_vector)
                        except Exception:
                            pass
                        cvss_score = self._extract_cvss_from_vector(cvss_vector)
                        if not severity or severity not in SEVERITY_RANK:
                            severity = get_severity_from_score(cvss_score)
                        break

            if cvss_score == 0.0 and severity in SEVERITY_RANK:
                score_map = {"low": 2.0, "medium": 5.0, "high": 7.5, "critical": 9.5}
                cvss_score = score_map.get(severity, 0.0)

            description = ""
            details = osv_vuln.get("details", "")
            summary = osv_vuln.get("summary", "")
            if summary:
                description = summary
            elif details:
                description = details[:200] if len(details) > 200 else details

            fix_version = ""
            affected = osv_vuln.get("affected", [])
            for aff in affected:
                ranges = aff.get("ranges", [])
                for r in ranges:
                    events = r.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fix_version = event["fixed"]
                            break
                    if fix_version:
                        break
                if fix_version:
                    break

            source = "os"
            for eco_key, eco_val in OSV_ECOSYSTEM_MAP.items():
                if eco_val == ecosystem:
                    source = eco_key
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
                    source=source,
                )
            )

        return vulns

    def _extract_cvss_from_vector(self, vector: str) -> float:
        try:
            metrics = {}
            for part in vector.split("/"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    metrics[k] = v

            av_score = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
            ac_score = {"L": 0.77, "H": 0.44}
            pr_score_ui = {
                "N_None": (0.85, 0.85),
                "L_None": (0.62, 0.85),
                "H_None": (0.27, 0.85),
                "N_Changed": (0.85, 0.62),
                "L_Changed": (0.62, 0.62),
                "H_Changed": (0.27, 0.62),
            }
            scope_changed = metrics.get("S", "U") == "C"

            av = av_score.get(metrics.get("AV", "N"), 0.85)
            ac = ac_score.get(metrics.get("AC", "L"), 0.77)
            pr_ui_key = f"{metrics.get('PR', 'N')}_{metrics.get('UI', 'N')}"
            pr, ui = pr_score_ui.get(pr_ui_key, (0.85, 0.85))

            exploitability = 8.22 * av * ac * pr * ui

            c_score_map = {"H": 0.56, "L": 0.22, "N": 0.0}
            ci = c_score_map.get(metrics.get("C", "N"), 0.0)
            ii = c_score_map.get(metrics.get("I", "N"), 0.0)
            ai = c_score_map.get(metrics.get("A", "N"), 0.0)

            iss = 1.0 - ((1.0 - ci) * (1.0 - ii) * (1.0 - ai))

            if iss <= 0:
                return 0.0

            if scope_changed:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            else:
                impact = 6.42 * iss

            if impact <= 0:
                return 0.0

            if scope_changed:
                base = min(1.08 * (impact + exploitability), 10.0)
            else:
                base = min(impact + exploitability, 10.0)

            return round(base, 1)
        except Exception:
            return 0.0

    def get_vulnerabilities(
        self, package_name: str, version: str, source: str = "os"
    ) -> List[Vulnerability]:
        cached = self._get_cached(package_name, version)
        if cached or self.offline:
            return cached

        if source == "os":
            vulns = self._query_nvd(package_name, version)
        else:
            ecosystem = OSV_ECOSYSTEM_MAP.get(source)
            if ecosystem:
                vulns = self._query_osv(package_name, version, ecosystem)
            else:
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
            return self.get_vulnerabilities(pkg.name, pkg.version, pkg.source)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_pkg = {
                executor.submit(scan_single, pkg): pkg for pkg in packages
            }
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
