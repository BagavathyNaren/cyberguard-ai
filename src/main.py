from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import asyncio
import uuid
import os
import logging
from dotenv import load_dotenv
from langsmith import Client
import json
import redis

from src.crew import run_security_crew
from src.logger import get_structured_logger
from src.main_polling import wait_for_soc_approval
# Import DB models and your new Slack reply tool
from src.approval_endpoint import approval_router, SessionLocal, Incident, send_slack_thread_reply
# Import the remediation function we drafted earlier
from src.remediation import execute_approved_remediation 

# Force the environment to use the specific project
os.environ["LANGCHAIN_PROJECT"] = "cyberguard-ai"
os.environ["LANGCHAIN_TRACING_V2"] = "true"
# Optional: Add a client ping to verify connectivity
client = Client()
print(f"DEBUG: LangSmith client initialized for project: {os.environ.get('LANGCHAIN_PROJECT')}")

# 1. Force Python to look in the parent directory for the .env file BEFORE doing anything else
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
logger = logging.getLogger("uvicorn")
logger.info(f"LangSmith Project: {os.getenv('LANGCHAIN_PROJECT')}")
logger.info(f"LangSmith Tracing Enabled: {os.getenv('LANGCHAIN_TRACING_V2')}")

# Initialize our new structured JSON logger
logger = get_structured_logger("cyberguard_api")

app = FastAPI(title="CyberGuard AI", version="1.0.0")
app.include_router(approval_router) # <--- This brings your Slack routes to life

class LogEvent(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    timestamp: str
    raw_log: str
    metadata: dict = {}

# Initialize Redis client (decode_responses=True ensures we get strings back, not bytes)
redis_url = os.getenv("REDIS_URL")
redis_client = redis.from_url(redis_url, decode_responses=True) if redis_url else None

@app.post("/analyze-interactive")
def trigger_security_analysis(log_data: LogEvent):
    # 1. Generate the ID upfront
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    
    # 2. Insert PENDING status into Database BEFORE the agent runs
    db = SessionLocal()
    try:
        new_incident = Incident(
            id=incident_id,
            status="PENDING",
            approved=False,
            attacker_ip=log_data.source_ip  # <--- STEP 2: DYNAMIC IP SAVED HERE
        )
        db.add(new_incident)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB Error: {e}")
        raise HTTPException(status_code=500, detail="Database instantiation failed")
    finally:
        db.close()

    # 3. Run the Crew (pass the ID we just generated)
    logger.info(f"🚀 Starting Crew analysis for {incident_id}")
    crew_result = run_security_crew(log_event=log_data.dict(), incident_id=incident_id)
    
    # 4. ENTER THE GATEKEEPER LOOP
    # The execution pauses here until the DB status changes to APPROVED or DENIED via Slack
    logger.info(f"⏳ Pausing execution. Waiting for SOC analyst approval in Slack for {incident_id}...")
    is_approved = wait_for_soc_approval(incident_id=incident_id, timeout_seconds=300, poll_interval=5)
    
    # 5. Final Action Plane
    if is_approved:
        logger.info(f"✅ APPROVED! Executing final remediation blocks for {incident_id}...")
        # (Future step: Trigger your actual firewall block script here)
        return {
            "incident_id": incident_id,
            "status": "APPROVED & Remediated",
            "crew_analysis": crew_result
        }
    else:
        logger.warning(f"🛑 DENIED or TIMED OUT. Aborting remediation for {incident_id}.")
        return {
            "incident_id": incident_id,
            "status": "DENIED / Aborted",
            "crew_analysis": crew_result
        }


@app.post("/analyze")
async def analyze(event: LogEvent, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())[:8]
    
    # Log the incoming request with structured context
    logger.info(f"Received new {event.event_type} event", extra={
        "custom_context": {"job_id": job_id, "source_ip": event.source_ip}
    })
    
    background_tasks.add_task(process_event, job_id, event.dict())
    return {"status": "queued", "job_id": job_id}


async def process_event(job_id: str, data: dict):
    # 1. Generate the expected INC- format from the job_id
    incident_id = f"INC-{job_id.upper()}"
    
    try:
        logger.info("Starting CrewAI execution", extra={"custom_context": {"job_id": job_id}})
        loop = asyncio.get_event_loop()
        
        # 2. Pass BOTH 'data' and 'incident_id' to run_security_crew
        result = await loop.run_in_executor(None, run_security_crew, data, incident_id)
        
        # Save success to Upstash Redis
        if redis_client:
            redis_client.set(job_id, json.dumps({"status": "complete", "result": result}), ex=86400)
            
        logger.info("CrewAI execution successful", extra={"custom_context": {"job_id": job_id}})
    except Exception as e:
        # Save error to Upstash Redis
        if redis_client:
            redis_client.set(job_id, json.dumps({"status": "error", "error": str(e)}), ex=86400)
            
        logger.error(f"CrewAI execution failed: {str(e)}", extra={
            "custom_context": {"job_id": job_id, "error_type": type(e).__name__}
        })

@app.get("/result/{job_id}")
def get_result(job_id: str):
    if redis_client:
        stored_result = redis_client.get(job_id)
        if stored_result:
            return json.loads(stored_result)
    
    return {"status": "processing"}

@app.get("/")
async def root():
    return {"message": "CyberGuard AI is running and ready for remediation tasks."}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "cyberguard-ai"}

@app.post("/test")
async def test_endpoint(background_tasks: BackgroundTasks):
    sample = {
        "source_ip": "185.234.219.12",
        "destination_ip": "10.0.1.50",
        "event_type": "port_scan",
        "timestamp": "2026-05-25T10:23:45Z",
        "raw_log": "SRC=185.234.219.12 DST=10.0.1.50 PROTO=TCP 240 unique ports 3s XMAS scan",
        "metadata": {"sensor": "pfsense-01", "interface": "wan"}
    }
    job_id = str(uuid.uuid4())[:8]
    
    logger.info("Fired test endpoint", extra={"custom_context": {"job_id": job_id}})
    
    background_tasks.add_task(process_event, job_id, sample)
    return {"status": "test_queued", "job_id": job_id, "sample": sample}

@app.get("/debug-env")
async def debug_env():
    import os
    api_key = os.environ.get("CREWAI_API_KEY")
    return {
        "tracing_enabled_var": os.environ.get("CREWAI_TRACING_ENABLED"),
        "api_key_found": bool(api_key),
        "api_key_starts_with": api_key[:5] if api_key else "MISSING",
        "api_key_length": len(api_key) if api_key else 0
    }

@app.post("/test-incident")
def trigger_security_analysis_test(background_tasks: BackgroundTasks):
    # 1. Generate a unique, trackable Incident ID before starting
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    
    # 2. Insert the initial PENDING record into your Postgres DB
    db = SessionLocal()
    try:
        new_incident = Incident(
            id=incident_id,
            status="PENDING",
            approved=False,
            attacker_ip="192.168.1.50"  # <--- STEP 2: DYNAMIC IP FOR MOCK TEST LOG
        )
        db.add(new_incident)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to initialize incident in DB: {e}")
        raise HTTPException(status_code=500, detail="Database instantiation failed")
    finally:
        db.close()

    # 3. Create a mock log event dictionary
    mock_log = {
           "raw_log": "SRC_IP: 192.168.1.50 -> DST_IP: 10.0.0.5 | Protocol: TCP | Flags: XMAS Scan detected on port 80, 443, 22"   
    }
    
    logger.info(f"🚀 Kickoff CrewAI for {incident_id}")
    
    # 4. Run the Crew with the updated function signature 
    # (The Crew will run, call your updated SlackAlertTool, post the buttons, and finish its analysis phase)
    crew_output = run_security_crew(log_event=mock_log, incident_id=incident_id)

    # 5. ENTER THE GATEKEEPER LOOP
    # This freezes the endpoint thread right here, waiting for the Postgres status to change
    is_approved = wait_for_soc_approval(incident_id=incident_id, timeout_seconds=300, poll_interval=5)
    
    # 6. Action Plane Enforcement
    if is_approved:
        logger.info(f"⚡ [EXECUTION PHASE] Proceeding with remediation for {incident_id}...")

        # 1. Open a fresh database session to grab the incident and its Slack thread coordinates
        db_session = SessionLocal()
        incident = db_session.query(Incident).filter(Incident.id == incident_id).first()

        if not incident:
            logger.error(f"Could not find incident {incident_id} in DB during execution phase.")
            db_session.close()
            raise HTTPException(status_code=500, detail="Incident lost during execution")

        slack_channel = incident.slack_channel_id
        slack_thread = incident.slack_thread_ts

        # 2. Run your actual remediation logic (Firewall / EDR)
        try:
            # We pass the crew_output dictionary here so the remediation function can extract IPs/ports
            remediation_summary = execute_approved_remediation(incident_id, crew_output)
            
            # 3. Check the status and format the Slack reply
            if remediation_summary.get("status") == "SUCCESS":
                reply_text = f"✅ *Remediation Successful*\nAll approved actions executed without error."
 
            else:
                # If a tool timed out or failed, alert the team immediately
                errors = "\n".join(remediation_summary.get("errors", ["Unknown error occurred"]))
                reply_text = (
                    f"🚨 *REMEDIATION FAILED*\n"
                    f"One or more tools encountered an error during execution:\n"
                    f"```\n{errors}\n```\n"
                    f"<@here> Manual intervention required!"
                )
        except Exception as e:
            logger.error(f"Remediation execution failed: {str(e)}", extra={
                "custom_context": {"incident_id": incident_id, "error_type": type(e).__name__}
            })
    
        