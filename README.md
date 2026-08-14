# AI-Augmented C2 Beaconing & Network Timing Analyzer

An advanced Threat Hunting & DFIR application built to detect covert Command and Control (C2) channels (e.g., Cobalt Strike, botnets) using statistical jitter metrics, TLS fingerprints (JA3/SNI), and automated reasoning powered by Anthropic's **Claude Opus 5**.

---

## Features
- **Statistical Jitter Engine**: Computes packet arrival intervals ($\Delta t$), mean deltas, standard deviation, and jitter percentages to flag metronomic beaconing.
- **TLS & Metadata Fingerprinting**: Extracts Server Name Indication (SNI) hostnames and generates JA3 hashes from Client Hello frames.
- **Threat Intel Enrichment**: Integrates AbuseIPDB reputation metrics.
- **Interactive Waterfall Visualizations**: Renders real-time packet arrival timelines using Chart.js.
- **Claude 3 Opus DFIR Agent**: Automated forensic reporting that evaluates burst-onset cadences and identifies protocol masquerading.

---

## Stack
- **Backend**: Python, Flask, Scapy, NumPy, Pandas
- **AI / LLM**: Anthropic API (`claude-opus-5`)
- **Frontend**: Bootstrap 5, Chart.js

---

## Quickstart

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/c2-beaconing-analyzer.git](https://github.com/YOUR_USERNAME/c2-beaconing-analyzer.git)
   cd c2-beaconing-analyzer