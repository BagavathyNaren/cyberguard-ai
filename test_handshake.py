import os
from crewai import Crew

# Set the key you just generated from the dashboard
os.environ["CREWAI_API_KEY"] = "pat_l3MJX_NE7kscfwlQgTGPzOm0NBfO73pynud3FoyBX-c" # Your actual key here
os.environ["CREWAI_TRACING_ENABLED"] = "true"

print("Starting Handshake Test...")
try:
    # This will attempt to authenticate with the CrewAI platform
    test_crew = Crew(agents=[], tasks=[], verbose=True)
    print("SUCCESS: The handshake is working!")
except Exception as e:
    print(f"FAILED: The handshake returned error: {e}")