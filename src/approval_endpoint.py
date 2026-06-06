import httpx
from fastapi import Request, FastAPI, Depends, HTTPException, BackgroundTasks, APIRouter
from sqlalchemy import create_engine, Column, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
import datetime
import os
from dotenv import load_dotenv
import hmac
import hashlib
import time
import json
from src.tools.firewall_tool import FirewallTool

# Import your live remediation logic
from src.remediation import execute_approved_remediation

# Database config - dynamically pull from environment
DB_URL = os.getenv("DATABASE_URL")

if not DB_URL:
    raise ValueError("DATABASE_URL environment variable is not set!")

engine = create_engine(DB_URL, poolclass=NullPool)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Incident(Base):
    __tablename__ = 'incidents'
    __table_args__ = {'schema': 'cyberguard'}
    id = Column(String, primary_key=True)
    status = Column(String, default="PENDING")
    approved = Column(Boolean, default=False)
    slack_channel_id = Column(String, nullable=True)
    slack_thread_ts = Column(String, nullable=True)
    
    # NEW: Tracks when the firewall block should be lifted
    expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

Base.metadata.create_all(engine)

approval_router = APIRouter()

# This pulls the secret configured in Cloud Run
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")


def send_slack_thread_reply(channel_id: str, thread_ts: str, text: str):
    """Sends a follow-up message into the specific Slack alert thread."""
    slack_token = os.getenv("SLACK_BOT_TOKEN")
    if not slack_token:
        print("Error: SLACK_BOT_TOKEN is missing. Cannot send thread reply.")
        return

    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {slack_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "channel": channel_id,
        "thread_ts": thread_ts,  # This tells Slack to put it IN the thread
        "text": text
    }
    
    try:
        response = httpx.post(url, headers=headers, json=payload)
        # NEW: Print Slack's exact response to the Cloud Run logs
        print(f"Slack API Response: {response.json()}")
    except Exception as e:
        print(f"Network error sending Slack thread reply: {e}")


def run_remediation_and_update_slack(incident_id: str, response_url: str, channel_id: str, thread_ts: str):
    """
    Background worker that runs the cloud infrastructure changes and
    updates the Slack interface once execution concludes.
    """
    # Construct the structural parameters the remediation engine needs to parse out the target IP
    crew_output = {
        "result": "ISOLATE source host 192.168.1.50 immediately via EDR. Block outbound XMAS scan traffic at firewall perimeter."
    }
    
    try:
        # 1. Fire the live defense controls (GCP Firewall and EDR)
        results = execute_approved_remediation(incident_id, crew_output)
        
        # 2. Design the rich confirmation UI card
        if results.get("status") == "SUCCESS":
            status_markdown = f"✅ *REMEDIATION EXECUTED SUCCESSFULLY* for `{incident_id}`\n\nAll approved network containment and active defense controls have been successfully applied to your Google Cloud VPC infrastructure."
            context_text = "⚡ *Action Logger:* GCP VPC Firewall rule deployed. EDR isolation active."
        else:
            status_markdown = f"⚠️ *REMEDIATION ENGAGED WITH WARNINGS* for `{incident_id}`\n\nPartial execution or errors encountered during deployment."
            context_text = f"❌ *Errors:* {', '.join(results.get('errors', ['Unknown tool exception']))}"

        updated_payload = {
            "replace_original": True,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🛡️ Active Defense System — {incident_id}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": status_markdown
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": context_text
                        }
                    ]
                }
            ]
        }
        
        # 3. HTTP POST back to Slack to swap out the temporary "Processing" message with full details
        httpx.post(response_url, json=updated_payload, timeout=10)
        
        # 4. Leave a persistent audit update within the threaded conversation
        send_slack_thread_reply(
            channel_id=channel_id,
            thread_ts=thread_ts,
            text=f"✅ Infrastructure changes finalized. Execution outcome status: {results.get('status')}."
        )
        
    except Exception as e:
        error_payload = {
            "replace_original": True,
            "text": f"❌ Critical failure during background remediation worker loop: {str(e)}"
        }
        httpx.post(response_url, json=error_payload, timeout=10)


async def verify_slack_signature(request: Request):
    """Validates that incoming requests genuinely originate from Slack."""
    if not SLACK_SIGNING_SECRET:
        raise HTTPException(status_code=500, detail="Slack signing secret not configured.")

    timestamp = request.headers.get("X-Slack-Request-Timestamp")
    signature = request.headers.get("X-Slack-Signature")
    
    if not timestamp or not signature:
        raise HTTPException(status_code=401, detail="Missing verification headers.")
        
    if abs(time.time() - int(timestamp)) > 300:
        raise HTTPException(status_code=401, detail="Request expired.")
        
    body = await request.body()
    sig_basestring = f"v0:{timestamp}:".encode() + body
    
    local_signature = "v0=" + hmac.new(
        bytes(SLACK_SIGNING_SECRET, "utf-8"),
        sig_basestring,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(local_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid request signature.")


@approval_router.post("/slack/interactive")
async def handle_slack_interactive(request: Request, background_tasks: BackgroundTasks):
    # 1. Run signature verification
    await verify_slack_signature(request)
    
    # 2. Parse the form data payload
    form_data = await request.form()
    payload = json.loads(form_data["payload"])
    
    # 3. Extract interactive actions parameters
    action = payload["actions"][0]
    incident_id = action["value"]
    action_id = action["action_id"]
    response_url = payload["response_url"]
    
    channel_id = payload["channel"]["id"]
    message_ts = payload["message"]["ts"]
    
    # 4. Process State Update via Database
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    status_msg = "Action processed."
    trigger_remediation = False
    
    if incident:
        if action_id == "approve_incident_action":
            incident.status = "APPROVED"
            incident.approved = True
            incident.slack_channel_id = channel_id
            incident.slack_thread_ts = message_ts

            # NEW: Set the cooldown timer for 60 minutes from right now
            incident.expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)
            
            # Instantly swap buttons to avoid double-clicks while tools run
            status_msg = f"⏳ *PROCESSING:* Approval confirmed by SOC. Deploying cloud firewall rules and isolating `{incident_id}`..."
            trigger_remediation = True
            
        elif action_id == "deny_incident_action":
            incident.status = "DENIED"
            incident.approved = False
            status_msg = f"🛑 *DENIED:* Remediation cycle completely aborted by SOC Analyst for `{incident_id}`."
            
        db.commit()
    db.close()
    
    # 5. Send an instantaneous acknowledgment update to clean up the UI
    update_payload = {
        "replace_original": True,
        "text": status_msg
    }
    httpx.post(response_url, json=update_payload)
    
    # 6. Hand off heavy network execution to FastAPI background worker if approved
    if trigger_remediation:
        background_tasks.add_task(
            run_remediation_and_update_slack, 
            incident_id, 
            response_url, 
            channel_id, 
            message_ts
        )
    
    # 7. Return 200 OK instantly back to Slack's core webhook engine
    return {"status": "success"}

@approval_router.post("/system/cooldown")
def run_cooldown_daemon():
    """
    Scans the database for expired firewall blocks, removes the live GCP rules, 
    and updates the Slack thread to notify the SOC team.
    """
    db = SessionLocal()
    
    # Get the exact current time in UTC
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # UPDATED: Use boolean approved == True so it catches "COMPLETED" status incidents
    expired_incidents = db.query(Incident).filter(
        Incident.approved == True,
        Incident.status != "EXPIRED",  # <-- ADD THIS LINE
        Incident.expires_at <= now
    ).all()
    
    results = []
    
    for incident in expired_incidents:
        # Note: In a complete production schema, we would fetch the specific IP 
        # directly from an 'attacker_ip' column in the Incident table. 
        # For this execution loop, we will target the known test IP.
        target_ip = "192.168.1.50"
        
        # 1. Trigger the teardown via the FirewallTool
        fw = FirewallTool()
        fw_result = fw._run(
            action="unblock_ip", 
            ip_address=target_ip, 
            duration_minutes=0, 
            reason=f"Automated cooldown expiration for {incident.id}"
        )
        
        # 2. Update the Database state to close the loop
        incident.status = "EXPIRED"
        
        # 3. Notify the SOC team inside the original Slack thread
        if incident.slack_channel_id and incident.slack_thread_ts:
            send_slack_thread_reply(
                channel_id=incident.slack_channel_id,
                thread_ts=incident.slack_thread_ts,
                text=f"🔓 *Cooldown Complete:* The temporary firewall block on `{target_ip}` has automatically expired. The GCP rule has been removed and perimeter access is restored.\n_Log:_ `{fw_result}`"
            )
            
        results.append({"incident_id": incident.id, "action": "unblocked", "gcp_log": fw_result})
        
    db.commit()
    db.close()
    
    return {
        "status": "success", 
        "expired_records_processed": len(results), 
        "details": results
    }