from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os
import httpx

class ThreatIntelInput(BaseModel):
    ip_address: str = Field(description="The IP address to check for malicious activity.")

class ThreatIntelTool(BaseTool):
    name: str = "threat_intel_lookup"
    description: str = "Check an IP address against AbuseIPDB to see if it is a known malicious actor. Returns a threat score and report count. ALWAYS use this on external IP addresses."
    args_schema: type[BaseModel] = ThreatIntelInput

    def _run(self, ip_address: str) -> str:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return f"Error: ABUSEIPDB_API_KEY environment variable not set. Cannot check {ip_address}."

        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }

        try:
            # We use a 10-second timeout so the agent doesn't hang indefinitely if the API is slow
            response = httpx.get(url, headers=headers, params=querystring, timeout=10.0)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                isp = data.get("isp", "Unknown")
                domain = data.get("domain", "None")

                return (f"AbuseIPDB Report for {ip_address}:\n"
                        f"- Abuse Confidence Score: {score}/100\n"
                        f"- Total Reports (Last 90 days): {reports}\n"
                        f"- ISP/Owner: {isp}\n"
                        f"- Domain: {domain}")
            else:
                return f"API Error checking {ip_address}: HTTP {response.status_code} - {response.text}"
                
        except Exception as e:
            return f"Network request failed: {str(e)}"