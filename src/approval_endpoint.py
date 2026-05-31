import httpx
from fastapi import Request,FastAPI, Depends, HTTPException
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
from fastapi import APIRouter

# Database config - dynamically pull from environment
DB_URL = os.getenv("DATABASE_URL")

if not DB_URL:
    raise ValueError("DATABASE_URL environment variable is not set!")

engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Incident(Base):
    __tablename__ = 'incidents'
    __table_args__ = {'schema': 'cyberguard'}
    id = Column(String, primary_key=True)
    status = Column(String, default="PENDING")
    approved = Column(Boolean, default=False)
    # NEW: Store the Slack context so main.py can reply to the thread later
    slack_channel_id = Column(String, nullable=True)
    slack_thread_ts = Column(String, nullable=True)

    # Automatically logs the exact time the row is inserted
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Automatically updates the timestamp whenever the row is modified
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

Base.metadata.create_all(engine)


approval_router = APIRouter()

# This pulls the secret you just configured in Cloud Run
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
        httpx.post(url, headers=headers, json=payload)
    except Exception as e:
        print(f"Network error sending Slack thread reply: {e}")

async def verify_slack_signature(request: Request):
    """
    Validates that incoming requests genuinely originate from Slack.
    """
    if not SLACK_SIGNING_SECRET:
        raise HTTPException(status_code=500, detail="Slack signing secret not configured.")

    # 1. Extract the headers Slack sends
    timestamp = request.headers.get("X-Slack-Request-Timestamp")
    signature = request.headers.get("X-Slack-Signature")
    
    if not timestamp or not signature:
        raise HTTPException(status_code=401, detail="Missing verification headers.")
        
    # 2. Prevent replay attacks (reject requests older than 5 minutes)
    if abs(time.time() - int(timestamp)) > 300:
        raise HTTPException(status_code=401, detail="Request expired.")
        
    # 3. Recreate the signature hash basestring
    body = await request.body()
    sig_basestring = f"v0:{timestamp}:".encode() + body
    
    # 4. Generate our own local hash using your secret
    local_signature = "v0=" + hmac.new(
        bytes(SLACK_SIGNING_SECRET, "utf-8"),
        sig_basestring,
        hashlib.sha256
    ).hexdigest()
    
    # 5. Cryptographically compare them
    if not hmac.compare_digest(local_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid request signature.")

@approval_router.post("/slack/interactive")
async def handle_slack_interactive(request: Request):
    # 1. Run the signature verification manually to parse the body correctly
    await verify_slack_signature(request)
    
    # 2. Parse the form data sent by Slack
    form_data = await request.form()
    payload = json.loads(form_data["payload"])
    
    # 3. Extract the incident ID and the unique response URL
    action = payload["actions"][0]
    incident_id = action["value"]
    action_id = action["action_id"]
    response_url = payload["response_url"]  # <-- Slack's temporary webhook to edit this specific message
    
    # NEW: Extract Slack Thread Metadata so we can reply later
    channel_id = payload["channel"]["id"]
    message_ts = payload["message"]["ts"]
    
    # 4. Handle the database update based on which button was clicked
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    status_msg = "Action recorded."
    
    if incident:
        if action_id == "approve_incident_action":
            incident.status = "APPROVED"
            incident.approved = True
            
            # NEW: Save the thread coordinates for the execution phase follow-ups
            incident.slack_channel_id = channel_id
            incident.slack_thread_ts = message_ts
            
            status_msg = f"✅ *APPROVED* by SOC Analyst. Remediation proceeding for `{incident_id}`."
            
        elif action_id == "deny_incident_action":
            incident.status = "DENIED"
            incident.approved = False
            status_msg = f"🛑 *DENIED* by SOC Analyst. Remediation aborted for `{incident_id}`."
            
        db.commit()
    db.close()
    
    # 5. Send a request back to Slack to instantly replace the buttons with the text confirmation
    update_payload = {
        "replace_original": True,
        "text": status_msg
    }
    httpx.post(response_url, json=update_payload)
    
    # 6. Respond back to Slack instantly with a 200 OK acknowledgment
    return {"status": "success"}
