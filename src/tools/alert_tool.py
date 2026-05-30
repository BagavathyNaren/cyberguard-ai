from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import httpx
import os
import json

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
        
        if url == "mock":
            return f"[MOCK] Alert sent | {severity} | {incident_id} | Approval needed: {requires_approval}"
            
        # 1. Base structured text block layout
        payload = {
            "text": f"🚨 [{severity}] CyberGuard Threat Alert: {incident_id}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🚨 *[{severity}] Security Threat Detected*\n\n"
                                f"*Incident ID:* `{incident_id}`\n"
                                f"*Summary:* {summary}\n"
                                f"*Recommended Action:* {recommended_action}"
                    }
                }
            ]
        }
        
        # 2. Dynamically attach interactive buttons if Human approval is required
        if requires_approval:
            payload["blocks"].append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Approve Mitigation",
                            "emoji": True
                        },
                        "style": "primary",
                        "value": incident_id,
                        "action_id": "approve_incident_action"
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Deny / Ignore",
                            "emoji": True
                        },
                        "style": "danger",
                        "value": incident_id,
                        "action_id": "deny_incident_action"
                    }
                ]
            })
        else:
            # Informational notice for auto-remediations
            payload["blocks"].append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "⚡ *Auto-Remediation active:* Execution continuing without structural gates."
                    }
                ]
            })
        
        # 3. Ship payload to your Slack Webhook
        try:
            r = httpx.post(url, json=payload, timeout=10)
            return f"Slack: {r.status_code}"
        except Exception as e:
            return f"Slack error: {e}"