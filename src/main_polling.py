import time
import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker
# Import your Incident model from your approval_endpoint file
from src.approval_endpoint import Incident 

logger = logging.getLogger("uvicorn")

def wait_for_soc_approval(incident_id: str, timeout_seconds: int = 300, poll_interval: int = 10) -> bool:
    """
    Pauses execution and polls the database until the SOC analyst approves the incident.
    """
    DB_URL = os.getenv("DATABASE_URL")
    engine = create_engine(DB_URL, poolclass=NullPool)
    SessionLocal = sessionmaker(bind=engine)
    
    start_time = time.time()
    logger.info(f"🔒 Incident {incident_id} placed in PENDING status. Waiting for SOC approval...")

    while time.time() - start_time < timeout_seconds:
        db = SessionLocal()
        try:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            
            if incident and incident.status == "APPROVED":
                logger.info(f"✅ SOC Approval received for incident {incident_id}!")
                db.close()
                return True
                
            if incident and incident.status == "DENIED":
                logger.warning(f"❌ SOC Analyst DENIED execution for incident {incident_id}.")
                db.close()
                return False
                
        except Exception as e:
            logger.error(f"Database connection error during polling: {e}")
        finally:
            db.close()
            
        # Wait before checking the database again
        time.sleep(poll_interval)

    logger.error(f"⏳ Timeout reached waiting for SOC approval on incident {incident_id}.")
    return False