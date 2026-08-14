# main.py
import argparse
from analyzer import extract_flow_metrics, sniff_live_traffic
from ai_agent import C2Agent
from rich.console import Console
from rich.table import Table

console = Console()

def main():
    parser = argparse.ArgumentParser(description="C2 Beaconing Analyzer")
    parser.add_argument("pcap", nargs="?", default="sample.pcap", help="PCAP file path")
    parser.add_argument("--live", action="store_true", help="Enable live sniffing mode")
    args = parser.parse_args()

    if args.live:
        console.print("[bold yellow][*] Live Sniffing Mode Activated...[/bold yellow]")
        profiles = sniff_live_traffic(packet_count=100)
    else:
        console.print(f"[bold blue][*] Parsing PCAP: {args.pcap}[/bold blue]")
        profiles = extract_flow_metrics(args.pcap)

    if not profiles:
        console.print("[bold red][!] No flows extracted.[/bold red]")
        return

    agent = C2Agent()
    response = agent.analyze_flows(profiles)
    console.print("\n[bold green]=== Analysis Complete ===[/bold green]")
    console.print(response)

if __name__ == "__main__":
    main()