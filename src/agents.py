import os
import shutil

# Force-clear the cached tracing preference before the SDK initializes
tracing_config_dir = "/root/.crewai"
if os.path.exists(tracing_config_dir):
    shutil.rmtree(tracing_config_dir)
    print("DEBUG: Cleared CrewAI tracing cache.")

# Re-enforce the environment variable
os.environ["CREWAI_TRACING_ENABLED"] = "true"
os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "https://api.crewai.com"

from crewai import Agent, LLM
from src.tools.firewall_tool import FirewallTool
from src.tools.edr_tool import EDRTool
from src.tools.alert_tool import SlackAlertTool
from src.tools.threat_intel_tool import ThreatIntelTool

print(f"DEBUG: CREWAI_TRACING_ENABLED is set to: {os.environ.get('CREWAI_TRACING_ENABLED')}")
print(f"DEBUG: OTEL_EXPORTER_OTLP_ENDPOINT is set to: {os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT')}")


# LLM 1 — Fast triage (cheap, high-volume)
triage_llm = LLM(
    model="anthropic/claude-haiku-4-5",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    temperature=0.1,
    max_tokens=500
)

# # LLM 2 — Deep analysis (best reasoning, costly)
# analyzer_llm = LLM(
#     model="anthropic/claude-opus-4-20250514",
#     api_key=os.getenv("ANTHROPIC_API_KEY"),
#     temperature=0.1,
#     max_tokens=2000
# )

# LLM 2 — Deep analysis (Frontier Reasoning)
analyzer_llm = LLM(
    model="anthropic/claude-sonnet-4-6",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    temperature=0.1,
    max_tokens=2000
)

# LLM 3 — Precise tool execution (structured output)
executor_llm = LLM(
    model="anthropic/claude-haiku-4-5",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    temperature=0,
    max_tokens=1000
)

triage_agent = Agent(
    role="Security Triage Analyst",
    goal="Rapidly classify security events. Return severity JSON.",
    backstory="""Fast-response triage. Scan logs, classify LOW/MEDIUM/HIGH,
    assign confidence 0-100. Err on escalation for ambiguous cases.
    Respond ONLY with the JSON structure requested.""",
    llm=triage_llm,
    max_iter=2,
    verbose=True
)

analyzer_agent = Agent(
    role="Senior Threat Intelligence Analyst",
    goal="Deep incident report: MITRE mapping, blast radius, remediation.",
    backstory="""Elite analyst, expert in MITRE ATT&CK. Correlate evidence,
    enrich via threat intel tools, assess blast radius, recommend precise
    actions. Always weigh false-positive risk before recommending isolation.
    Structured report output only.""",
    llm=analyzer_llm,
    tools=[ThreatIntelTool()],
    max_iter=3,
    verbose=True
)

executor_agent = Agent(
    role="Security Operations Executor",
    goal="Execute remediation. Alert SOC first. Document every action.",
    backstory="""SOC ops specialist. Strict rules:
    (1) soc_alert FIRST, always, before any remediation.
    (2) HIGH confirmed: alert with requires_approval=True, then STOP.
    (3) MEDIUM: alert + temp firewall block max 60min.
    (4) LOW: alert only, no blocking ever.
    Log every action with timestamp and result.""",
    llm=executor_llm,
    tools=[FirewallTool(), EDRTool(), SlackAlertTool()],
    max_iter=2,
    verbose=True
)