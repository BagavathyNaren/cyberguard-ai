from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import httpx, os

class ThreatIntelInput(BaseModel):
    indicator: str = Field(description="IP, domain, or hash to check")
    indicator_type: str = Field(description="'ip', 'domain', or 'hash'")

class ThreatIntelTool(BaseTool):
    name: str = "threat_intel_lookup"
    description: str = "Look up IP/domain/hash in AbuseIPDB. Enrich analysis."
    args_schema: type[BaseModel] = ThreatIntelInput

    def _run(self, indicator: str, indicator_type: str) -> str:
        key = os.getenv("ABUSEIPDB_KEY", "mock")
        if key == "mock":
            return (f"[MOCK] {indicator}: malicious=True, "
                    f"score=85/100, country=RU, reports=12, "
                    f"category=Port scanning")
        if indicator_type == "ip":
            try:
                r = httpx.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": indicator, "maxAgeInDays": 30},
                    headers={"Key": key, "Accept": "application/json"},
                    timeout=10
                )
                d = r.json()["data"]
                return (f"score:{d['abuseConfidenceScore']} "
                        f"country:{d['countryCode']} "
                        f"reports:{d['totalReports']} "
                        f"isp:{d['isp']}")
            except Exception as e:
                return f"ThreatIntel error: {e}"
        return f"[UNSUPPORTED] {indicator_type} lookup not impl"