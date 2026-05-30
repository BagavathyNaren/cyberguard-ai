from fastapi import Request,FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
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

Base.metadata.create_all(engine)


approval_router = APIRouter()

# This pulls the secret you just configured in Cloud Run
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

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

@approval_router.post.post("/incident/{incident_id}/approve")
def approve_incident(incident_id: str):
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "APPROVED"
    incident.approved = True
    db.commit()
    db.close()
    return {"status": "success", "message": f"Incident {incident_id} approved"}

@approval_router.post.post("/slack/interactive")
async def handle_slack_interactive(request: Request):
    # 1. Run the signature verification manually to parse the body correctly
    await verify_slack_signature(request)
    
    # 2. Parse the form data sent by Slack
    form_data = await request.form()
    payload = json.loads(form_data["payload"])
    
    # 3. Extract the incident ID from the button's action value
    action = payload["actions"][0]
    incident_id = action["value"]
    action_id = action["action_id"]
    
    # 4. Handle the database update based on which button was clicked
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if incident:
        if action_id == "approve_incident_action":
            incident.status = "APPROVED"
            incident.approved = True
        elif action_id == "deny_incident_action":
            incident.status = "DENIED"
            incident.approved = False
            
        db.commit()
    db.close()
    
    # 5. Respond back to Slack instantly with a 200 OK acknowledgment
    return {"status": "success", "message": "Incident state updated successfully"}