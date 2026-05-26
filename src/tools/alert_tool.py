from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import httpx, os

class AlertInput(BaseModel):
    severity: str = Field(description="LOW, MEDIUM, or HIGH")
    summary: str = Field(description="Threat summary for SOC analyst")
    recommended_action: str = Field(description="What the agent recommends")
    incident_id: str = Field(description="Unique incident identifier")
    requires_approval: bool = Field(default=False, description="True = block all further action until SOC approves")

class SlackAlertTool(BaseTool):
    name: str = "soc_alert"
    description: str = "Alert SOC via Slack. ALWAYS call this first."
    args_schema: type[BaseModel] = AlertInput

    def _run(self, severity: str, summary: str, recommended_action: str,
             incident_id: str, requires_approval: bool = False) -> str:
        url = os.getenv("SLACK_WEBHOOK_URL", "mock")
        colors = {"HIGH": "#E24B4A", "MEDIUM": "#EF9F27", "LOW": "#639922"}
        
        if url == "mock":
            return f"[MOCK] Alert sent | {severity} | {incident_id} | Approval needed: {requires_approval}"
            
        approval = "YES — Reply with INC ID to approve" if requires_approval else "NO — Auto-remediating"
        
        payload = {
            "attachments": [{
                "color": colors.get(severity, "#888"),
                "title": f"[{severity}] {incident_id}",
                "text": summary,
                "fields": [
                    {"title": "Recommended action", "value": recommended_action},
                    {"title": "Human approval", "value": approval, "short": True}
                ]
            }]
        }
        
        try:
            r = httpx.post(url, json=payload, timeout=10)
            return f"Slack: {r.status_code}"
        except Exception as e:
            return f"Slack error: {e}"