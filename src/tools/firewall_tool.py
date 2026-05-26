from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import httpx, os

class FirewallInput(BaseModel):
    ip_address: str = Field(description="IP to block or unblock")
    action: str = Field(description="'block' or 'unblock'")
    reason: str = Field(description="Justification for action")
    duration_minutes: int = Field(default=60, description="Block TTL in minutes")

class FirewallTool(BaseTool):
    name: str = "firewall_ip_control"
    description: str = "Block/unblock IP via firewall API. Confirmed threats only."
    args_schema: type[BaseModel] = FirewallInput

    def _run(self, ip_address: str, action: str, reason: str,
             duration_minutes: int = 60) -> str:
        url = os.getenv("FIREWALL_API_URL", "mock")
        if url == "mock":
            return (f"[MOCK] {ip_address} {action}ed "
                    f"for {duration_minutes}min. Reason: {reason}")
        try:
            r = httpx.post(f"{url}/rules", json={
                "ip": ip_address, "action": action,
                "ttl": duration_minutes * 60, "reason": reason
            }, timeout=10)
            return f"Firewall: {r.status_code} — {r.text}"
        except Exception as e:
            return f"Firewall API error: {e}"