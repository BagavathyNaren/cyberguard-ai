from crewai import Crew, Task, Process
from src.agents import triage_agent, analyzer_agent, executor_agent
import uuid, json

def run_security_crew(log_event: dict) -> dict:
    incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"

    triage_task = Task(
        description=f"""
        Classify this security event:
        {json.dumps(log_event, indent=2)}

        Return ONLY this JSON (no other text):
        {{
            "incident_id": "{incident_id}",
            "severity": "LOW|MEDIUM|HIGH",
            "confidence": 0-100,
            "threat_type": "port_scan|brute_force|malware|data_exfil|lateral_movement|unknown",
            "escalate": true|false,
            "source_ip": "from logs",
            "affected_endpoint": "hostname or ip",
            "summary": "one sentence max"
        }}
        """,
        expected_output="JSON threat classification",
        agent=triage_agent
    )

    analyze_task = Task(
        description=f"""
        Deep-dive analysis for incident {incident_id}.

        Steps:
        1. Use threat_intel_lookup on source IP from triage output
        2. Map attack to MITRE ATT&CK technique (name + ID)
        3. Estimate blast radius (what else could be compromised)
        4. Calculate false-positive risk: LOW|MEDIUM|HIGH
        5. Recommend specific remediation with exact parameters

        Output fields: confirmed_threat, attack_technique, mitre_id,
        blast_radius, false_positive_risk, recommended_action,
        action_params, requires_approval.
        """,
        expected_output="Structured incident report with recommendation",
        agent=analyzer_agent,
        context=[triage_task]
    )

    execute_task = Task(
        description=f"""
        Execute remediation for incident {incident_id}.

        MANDATORY step 1: Call soc_alert with full summary now.

        Step 2 — escalation logic:
        - HIGH + confirmed_threat=true:
            soc_alert with requires_approval=True, then STOP. Do nothing else.
        - MEDIUM:
            soc_alert + firewall_ip_control block 60min on source_ip
        - LOW:
            soc_alert only, no blocking

        Step 3: Return complete execution log.
        """,
        expected_output="Execution log: every tool called, params, result",
        agent=executor_agent,
        context=[triage_task, analyze_task]
    )

    crew = Crew(
        agents=[triage_agent, analyzer_agent, executor_agent],
        tasks=[triage_task, analyze_task, execute_task],
        process=Process.sequential,
        verbose=True,
        max_rpm=10  # It forces CrewAI to slow down its API calls to stay under the 15 RPM limit.
    )

    result = crew.kickoff()
    return {"incident_id": incident_id, "result": str(result)}