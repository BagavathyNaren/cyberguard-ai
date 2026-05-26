import logging
import json
import sys
from datetime import datetime, timezone

class JsonFormatter(logging.Formatter):
    def format(self, record):
        # Base log structure that GCP Cloud Logging loves
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": record.levelname,
            "message": record.getMessage(),
            "module": record.module
        }
        
        # If we pass extra context (like incident_id), inject it into the JSON
        if hasattr(record, "custom_context"):
            log_record.update(record.custom_context)
            
        return json.dumps(log_record)

def get_structured_logger(name="cyberguard"):
    logger = logging.getLogger(name)
    
    # Prevent duplicate logs if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
    return logger