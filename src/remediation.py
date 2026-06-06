import json
import logging
import re
from typing import Dict, Any

# Import your existing production tools
from src.tools.firewall_tool import FirewallTool
from src.tools.edr_tool import EDRTool

logger = logging.getLogger("cyberguard_api")

def execute_approved_remediation(incident_id: str, crew_output: dict) -> dict:
    from src.approval_endpoint import SessionLocal, Incident
    # 1. Fetch the dynamic IP from the database
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident or not incident.attacker_ip:
        db.close()
        logger.error(f"Execution failed: No attacker IP found in DB for {incident_id}")
        return {"status": "FAILED", "errors": ["No attacker IP found in database."]}
    
    target_ip = incident.attacker_ip
    db.close()

    summary = {"status": "SUCCESS", "actions": [], "errors": []}
    
    # 2. Execute Firewall Block Dynamically
    try:
        fw_tool = FirewallTool()
        # Pass the target_ip instead of a hardcoded string
        fw_result = fw_tool._run(
            action="block_ip", 
            ip_address=target_ip, 
            duration_minutes=60, 
            reason=f"Automated block for {incident_id}"
        )
        summary["actions"].append(f"Firewall block on {target_ip}: {fw_result}")
    except Exception as e:
        summary["status"] = "FAILED"
        summary["errors"].append(f"Firewall Tool Error: {str(e)}")

    # 3. Execute EDR Isolation Dynamically
    try:
        edr_tool = EDRTool()
        # Pass the target_ip instead of a hardcoded string
        edr_result = edr_tool._run(
            action="isolate", 
            endpoint_id=target_ip, 
            reason=f"Automated isolation for {incident_id}"
        )
        summary["actions"].append(f"EDR isolation on {target_ip}: {edr_result}")
    except Exception as e:
        summary["status"] = "FAILED"
        summary["errors"].append(f"EDR Tool Error: {str(e)}")

    return summary