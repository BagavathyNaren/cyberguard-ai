from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import asyncio, uuid
from src.crew import run_security_crew
from src.logger import get_structured_logger
import os
from dotenv import load_dotenv

# 1. Force Python to look in the parent directory for the .env file BEFORE doing anything else
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Initialize our new structured JSON logger
logger = get_structured_logger("cyberguard_api")

app = FastAPI(title="CyberGuard AI", version="1.0.0")

class LogEvent(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    timestamp: str
    raw_log: str
    metadata: dict = {}

results_store: dict = {}  # In-memory store (we will upgrade this to Redis next!)

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
    try:
        logger.info("Starting CrewAI execution", extra={"custom_context": {"job_id": job_id}})
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_security_crew, data)
        results_store[job_id] = {"status": "complete", "result": result}
        logger.info("CrewAI execution successful", extra={"custom_context": {"job_id": job_id}})
    except Exception as e:
        results_store[job_id] = {"status": "error", "error": str(e)}
        # Log the exact error mapped to the specific job ID
        logger.error(f"CrewAI execution failed: {str(e)}", extra={
            "custom_context": {"job_id": job_id, "error_type": type(e).__name__}
        })

@app.get("/result/{job_id}")
def get_result(job_id: str):
    return results_store.get(job_id, {"status": "processing"})

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