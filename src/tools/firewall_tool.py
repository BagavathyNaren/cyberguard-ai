from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from google.cloud import compute_v1
import google.auth
import os
from langsmith import traceable

class FirewallInput(BaseModel):
    action: str = Field(description="'block_ip' or 'unblock_ip'")
    ip_address: str = Field(description="The IP address to block or unblock")
    duration_minutes: int = Field(description="How long to block the IP (ignored on unblock)")
    reason: str = Field(description="Audit reason for this action")

class FirewallTool(BaseTool):
    name: str = "network_firewall_control"
    description: str = "Blocks or unblocks an attacker's IP at the perimeter using Google Cloud VPC Firewall."
    args_schema: type[BaseModel] = FirewallInput

    @traceable(name="firewall_block_control")
    def _run(self, action: str, ip_address: str, duration_minutes: int, reason: str) -> str:
        if os.getenv("ENVIRONMENT") == "local":
             return f"[MOCK] Firewall executed {action} on {ip_address}. Reason: {reason}"

        try:
            _, project_id = google.auth.default()
            client = compute_v1.FirewallsClient()
            rule_name = f"auto-block-{ip_address.replace('.', '-')}"
            
            if action == "block_ip":
                firewall_rule = compute_v1.Firewall(
                    name=rule_name,
                    description=reason,
                    network=f"projects/{project_id}/global/networks/default",
                    direction="INGRESS",
                    source_ranges=[f"{ip_address}/32"],
                    denied=[compute_v1.Denied(I_p_protocol="all")],
                    priority=100
                )
                
                client.insert(project=project_id, firewall_resource=firewall_rule)
                return f"SUCCESS: GCP VPC Firewall rule '{rule_name}' created blocking {ip_address}."
                
            elif action == "unblock_ip":
                # Physically delete the rule from Google Cloud
                client.delete(project=project_id, firewall=rule_name)
                return f"SUCCESS: GCP VPC Firewall rule '{rule_name}' deleted. {ip_address} is unblocked."
                
            return "Action not recognized."
            
        except Exception as e:
            return f"Failed to execute VPC Firewall change: {str(e)}"