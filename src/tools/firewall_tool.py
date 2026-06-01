from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from google.cloud import compute_v1
import google.auth
import os

class FirewallInput(BaseModel):
    action: str = Field(description="'block_ip' or 'unblock_ip'")
    ip_address: str = Field(description="The IP address to block")
    duration_minutes: int = Field(description="How long to block the IP")
    reason: str = Field(description="Audit reason for this block")

class FirewallTool(BaseTool):
    name: str = "network_firewall_control"
    description: str = "Blocks an attacker's IP at the perimeter using Google Cloud VPC Firewall."
    args_schema: type[BaseModel] = FirewallInput

    def _run(self, action: str, ip_address: str, duration_minutes: int, reason: str) -> str:
        # If testing locally, fallback to mock so it doesn't crash your local machine
        if os.getenv("ENVIRONMENT") == "local":
             return f"[MOCK] Firewall blocked {ip_address} for {duration_minutes} mins. Reason: {reason}"

        try:
            # Securely and automatically grab the GCP Project ID from Cloud Run's identity
            _, project_id = google.auth.default()
            
            client = compute_v1.FirewallsClient()
            rule_name = f"auto-block-{ip_address.replace('.', '-')}"
            
            if action == "block_ip":
                # Create a strict DENY rule for the attacker's IP
                firewall_rule = compute_v1.Firewall(
                    name=rule_name,
                    description=reason,
                    network=f"projects/{project_id}/global/networks/default",
                    direction="INGRESS",
                    source_ranges=[f"{ip_address}/32"],
                    denied=[compute_v1.Denied(I_p_protocol="all")],
                    priority=100  # High priority ensures it overrides allow rules
                )
                
                # Send the physical execution request to Google Cloud
                operation = client.insert(project=project_id, firewall_resource=firewall_rule)
                return f"SUCCESS: GCP VPC Firewall rule '{rule_name}' created blocking {ip_address}."
                
            return "Action not recognized."
            
        except Exception as e:
            return f"Failed to execute VPC Firewall change: {str(e)}"