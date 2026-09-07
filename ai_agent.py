import json
import os
from anthropic import Anthropic
from pydantic import BaseModel
import config

class ThreatReport(BaseModel):
    flow: str
    threat_level: str
    confidence_score: int
    suspected_type: str
    reasoning: str

class AIAnalysis(BaseModel):
    analysis_summary: str
    threats_detected: list[ThreatReport]

class C2Agent:
    def __init__(self):
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is missing! Set it in your environment variables.")
        self.client = Anthropic(api_key=api_key)

    def analyze_flows(self, flow_profiles: list) -> str:
        if not isinstance(flow_profiles, list) or not flow_profiles:
            return json.dumps({"error": "No flow profiles provided"})

        # Keep prompts bounded and avoid sending unneeded packet-derived metadata.
        max_flows = getattr(config, 'MAX_AI_FLOWS', 100)
        def limited(value, limit=255):
            return str(value)[:limit]

        flow_profiles = [
            {
                "flow": limited(profile.get("flow", "")),
                "dst_ip": limited(profile.get("dst_ip", ""), 64),
                "connection_count": profile.get("connection_count", 0),
                "mean_interval_sec": profile.get("mean_interval_sec", 0),
                "std_dev_sec": profile.get("std_dev_sec", 0),
                "jitter_percentage": profile.get("jitter_percentage", 0),
                "ja3_fingerprints": [limited(item, 64) for item in profile.get("ja3_fingerprints", [])[:5]],
                "sni_hostname": [limited(item, 255) for item in profile.get("sni_hostname", [])[:5]],
                "threat_intel": profile.get("threat_intel", {}),
            }
            for profile in flow_profiles[:max_flows]
            if isinstance(profile, dict)
        ]
        if not flow_profiles:
            return json.dumps({"error": "No valid flow profiles provided"})

        system_prompt = """
        You are an elite DFIR Threat Hunter specializing in C2 Beaconing analysis.
        Analyze network flows using timing metrics, jitter %, TLS Fingerprints (JA3, SNI), and IP Threat Intel.
        Evaluation Rules:
        1. Low Jitter (< 15%) on web ports with short intervals indicates automated beaconing.
        2. Differentiate legitimate NTP/Telemetry from malicious implants.
        3. Keep reasoning concise (2-4 sentences max per threat).
        """

        # Using Anthropic's Structured Outputs (Beta) to guarantee JSON compliance
        response = self.client.beta.messages.parse(
            model=getattr(config, 'MODEL_NAME', 'claude-3-5-sonnet-latest'),
            max_tokens=getattr(config, 'MAX_TOKENS', 2000),
            betas=["structured-outputs-2024-08-05"],
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze these flow profiles:\n{json.dumps(flow_profiles, indent=2)}"
                }
            ],
            response_format=AIAnalysis
        )

        return json.dumps(response.parsed.model_dump())