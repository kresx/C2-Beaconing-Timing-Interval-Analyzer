import json
import os
import anthropic
import config

class C2Agent:
    def __init__(self):
        # Fallback check for API key in config or environment
        api_key = getattr(config, 'ANTHROPIC_API_KEY', '') or os.environ.get('ANTHROPIC_API_KEY', '')
        
        if not api_key or api_key == "YOUR_ACTUAL_ANTHROPIC_API_KEY_HERE":
            raise ValueError("ANTHROPIC_API_KEY is missing! Set your key in config.py or environment variables.")

        self.client = anthropic.Anthropic(api_key=api_key)

    def analyze_flows(self, flow_profiles: list) -> str:
        if not flow_profiles:
            return json.dumps({"error": "No flow profiles provided"})

        system_prompt = """
        You are an elite DFIR Threat Hunter specializing in C2 Beaconing analysis.
        Analyze network flows using timing metrics, jitter %, TLS Fingerprints (JA3, SNI), and IP Threat Intel scores.

        Evaluation Rules:
        1. Low Jitter (< 15%) on ports 80/443/8443 with short intervals indicates automated beaconing (Cobalt Strike, Sliver, Mythic).
        2. Leverage JA3 hashes and SNI hostnames to detect non-standard TLS clients or CDN domain fronting.
        3. Differentiate legitimate NTP/Telemetry from malicious implants.
        4. Keep reasoning concise (2-4 sentences max per threat).

        Output JSON format ONLY (No markdown fences):
        {
          "analysis_summary": "High level executive summary.",
          "threats_detected": [
            {
              "flow": "<src -> dst:port>",
              "threat_level": "CRITICAL / HIGH / MEDIUM / LOW / BENIGN",
              "confidence_score": 0-100,
              "suspected_type": "Classification type",
              "reasoning": "Forensic breakdown including timing, JA3, SNI, and Threat Intel."
            }
          ]
        }
        """

        response = self.client.messages.create(
            model=getattr(config, 'MODEL_NAME', 'claude-3-5-sonnet-20241022'),
            max_tokens=getattr(config, 'MAX_TOKENS', 2000),
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze these flow profiles:\n{json.dumps(flow_profiles, indent=2)}"
                }
            ]
        )

        text_outputs = []
        for block in response.content:
            if hasattr(block, 'text'):
                text_outputs.append(block.text)

        raw_json = "\n".join(text_outputs).strip()

        # Sanitize potential markdown code blocks (```json ... ```)
        if raw_json.startswith("```json"):
            raw_json = raw_json[7:]
        elif raw_json.startswith("```"):
            raw_json = raw_json[3:]
        if raw_json.endswith("```"):
            raw_json = raw_json[:-3]

        return raw_json.strip()