import os
from typing import List

class NVDLookup:
    def fetch_cves(self, keyword: str, *, limit: int = 3) -> List[str]:
        # Import lazily so the backend can still boot without the optional dependency.
        try:
            import requests  # type: ignore[import-not-found]
        except Exception:
            return []

        keyword = (keyword or "").strip()
        if not keyword:
            return []

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        api_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else {}
        params = {"keywordSearch": keyword, "resultsPerPage": int(limit)}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=8)
            response.raise_for_status()
            data = response.json()
        except Exception:
            return []

        out: List[str] = []
        for item in data.get("vulnerabilities", []):
            cve = (item.get("cve") or {}).get("id")
            if isinstance(cve, str) and cve.startswith("CVE-"):
                out.append(cve)

        return out
