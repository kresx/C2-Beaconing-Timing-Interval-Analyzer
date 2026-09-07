# config.example.py
import os

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "YOUR_ANTHROPIC_API_KEY_HERE")
MODEL_NAME = "claude-opus-5"
MAX_TOKENS = 4000

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# At least four data-bearing packets provide three intervals for a meaningful jitter estimate.
MIN_CONNECTIONS_TO_ANALYZE = 4
DEFAULT_SNIFF_COUNT = 100