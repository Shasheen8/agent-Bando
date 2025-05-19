import requests
import time
from utils.config import CONFIG
from utils.logger import log_info, log_error

class NIST:
    def __init__(self):
        self.base_url = CONFIG["endpoints"]["nist_cve"]

    def get_cve(self, cve_id):
        time.sleep(0.6)  # Delay for rate limits
        url = f"{self.base_url}?cveId={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            log_info(f"NIST request for {cve_id}: Status {response.status_code}, Headers {response.headers}")
            response.raise_for_status()
            data = response.json()
            log_info(f"Raw NIST response for {cve_id}: {data}")
            return self._parse_cve(data)
        except requests.RequestException as e:
            log_error(f"NIST API error for {cve_id}: {str(e)}")
            return {"error": f"Failed to fetch CVE: {str(e)}"}

    def search_cve(self, keyword):
        time.sleep(0.6)
        url = f"{self.base_url}?keywordSearch={keyword}&resultsPerPage=10"
        try:
            response = requests.get(url, timeout=10)
            log_info(f"NIST search for {keyword}: Status {response.status_code}, Headers {response.headers}")
            response.raise_for_status()
            data = response.json()
            log_info(f"Raw NIST search response for {keyword}: {data}")
            return [self._parse_cve_item(item) for item in data.get("vulnerabilities", [])]
        except requests.RequestException as e:
            log_error(f"NIST API error for keyword {keyword}: {str(e)}")
            return {"error": f"Failed to search CVEs: {str(e)}"}

    def _parse_cve(self, data):
        if not data.get("vulnerabilities") or not data["vulnerabilities"]:
            log_error("No vulnerabilities found in NIST response")
            return {"error": "CVE not found"}
        cve_item = data["vulnerabilities"][0]["cve"]
        return self._parse_cve_item(cve_item)

    def _parse_cve_item(self, cve_item):
        metrics = cve_item.get("metrics", {})
        # Try CVSS v3.1, fallback to v3.0
        cvss_data = next(
            (m["cvssData"] for m in metrics.get("cvssMetricV31", []) if "cvssData" in m),
            next(
                (m["cvssData"] for m in metrics.get("cvssMetricV30", []) if "cvssData" in m),
                {}
            )
        )
        description = next(
            (desc["value"] for desc in cve_item.get("descriptions", []) if desc["lang"] == "en"),
            "No description available"
        )
        return {
            "cve_id": cve_item.get("id", "N/A"),
            "description": description,
            "severity": cvss_data.get("baseSeverity", "N/A"),
            "impact": str(cvss_data.get("impactScore", "N/A")),
            "published": cve_item.get("published", "N/A").split("T")[0],
            "references": [ref.get("url", "") for ref in cve_item.get("references", [])]
        }