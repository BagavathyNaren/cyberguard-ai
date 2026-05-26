from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import httpx, os

class EDRInput(BaseModel):
    endpoint_id: str = Field(description="Hostname or IP of the endpoint to isolate")
    action: str = Field(description="'isolate' or 'unisolate'")
    reason: str = Field(description="Justification for isolation")

class EDRTool(BaseTool):
    name: str = "edr_host_isolation"
    description: str = "Isolate a compromised endpoint via EDR API. HIGH severity threats only."
    args_schema: type[BaseModel] = EDRInput

    def _run(self, endpoint_id: str, action: str, reason: str) -> str:
        url = os.getenv("EDR_API_URL", "mock")
        
        if url == "mock":
            return f"[MOCK] Endpoint {endpoint_id} {action}d via EDR. Reason: {reason}"
        
        try:
            r = httpx.post(f"{url}/endpoints/{endpoint_id}/isolate", json={
                "action": action,
                "reason": reason
            }, timeout=10)
            return f"EDR: {r.status_code} — {r.text}"
        except Exception as e:
            return f"EDR API error: {e}"