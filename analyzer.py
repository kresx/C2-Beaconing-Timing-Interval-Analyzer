import hashlib
from functools import lru_cache
from collections import defaultdict
import requests
import numpy as np

# Native Scapy imports
from scapy.all import rdpcap, sniff, IP, TCP, UDP, TCPSession, PcapReader
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName
import config


def _to_int(val) -> int | None:
    """Helper to convert Scapy cipher/group values into JA3-compliant integer format."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 0)
        except ValueError:
            pass
    if hasattr(val, "val"):  # Scapy EnumField representation
        return val.val
    return None


def compute_ja3(packet) -> str:
    """
    Extracts TLS Client Hello parameters and computes the MD5 JA3 hash.
    Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    try:
        if packet.haslayer(TLSClientHello):
            tls = packet[TLSClientHello]

            # 1. TLS Version
            version = str(getattr(tls, 'version', 771))

            # 2. Cipher Suites
            raw_ciphers = getattr(tls, 'ciphers', [])
            ciphers_list = []
            for c in raw_ciphers:
                c_val = _to_int(c)
                if c_val is not None:
                    ciphers_list.append(str(c_val))
            ciphers = "-".join(ciphers_list)

            # 3. Extensions, 4. Curves, 5. Point Formats
            ext_list = []
            curves_list = []
            point_formats_list = []

            if hasattr(tls, 'ext') and tls.ext:
                for ext in tls.ext:
                    # Get numerical Extension Type ID
                    ext_type_val = _to_int(getattr(ext, 'type', None))

                    if ext_type_val is not None:
                        ext_list.append(str(ext_type_val))

                        # Extension 10: Supported Groups / Elliptic Curves
                        if ext_type_val == 10:
                            groups = getattr(ext, 'groups', getattr(ext, 'named_group_list', []))
                            for g in groups:
                                g_val = _to_int(g)
                                if g_val is not None:
                                    curves_list.append(str(g_val))

                        # Extension 11: EC Point Formats
                        elif ext_type_val == 11:
                            ec_pf = getattr(ext, 'ecpl', getattr(ext, 'ec_point_formats', []))
                            for pf in ec_pf:
                                pf_val = _to_int(pf)
                                if pf_val is not None:
                                    point_formats_list.append(str(pf_val))

            extensions = "-".join(ext_list)
            curves = "-".join(curves_list)
            point_formats = "-".join(point_formats_list)

            ja3_str = f"{version},{ciphers},{extensions},{curves},{point_formats}"
            return hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
    except Exception:
        pass
    return "N/A"


def extract_sni(packet) -> str:
    """Extracts Server Name Indication (SNI) from TLS Client Hello extensions."""
    try:
        if packet.haslayer(TLSClientHello):
            tls = packet[TLSClientHello]
            if hasattr(tls, 'ext') and tls.ext:
                for ext in tls.ext:
                    ext_type = _to_int(getattr(ext, 'type', None))
                    # Check for Server Name extension (Type 0)
                    if isinstance(ext, TLS_Ext_ServerName) or ext_type == 0:
                        servernames = getattr(ext, 'servernames', [])
                        for sn in servernames:
                            servername = getattr(sn, 'servername', None)
                            if servername:
                                if isinstance(servername, bytes):
                                    return servername.decode('utf-8', errors='ignore')
                                return str(servername)
    except Exception:
        pass
    return "N/A"


@lru_cache(maxsize=1024)
def query_abuseipdb(ip_address: str) -> dict:
    """Queries AbuseIPDB API v2 for IP reputation score (cached)."""
    if not getattr(config, 'ABUSEIPDB_API_KEY', None) or ip_address.startswith(("10.", "172.16.", "192.168.", "127.")):
        return {"abuse_score": 0, "reports": 0, "is_whitelisted": True}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=3)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "domain": data.get("domain", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False)
            }
    except Exception:
        pass
    return {"abuse_score": 0, "reports": 0, "is_whitelisted": False}


def process_packets(packets) -> list:
    """Groups packets into flows and computes statistical metrics + Threat Intel."""
    flows = defaultdict(list)
    flow_meta = defaultdict(lambda: {"ja3": set(), "sni": set(), "dst_ip": ""})

    for pkt in packets:
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport

            flow_key = f"{src_ip} -> {dst_ip}:{dport} ({proto})"
            timestamp = float(pkt.time)
            flows[flow_key].append(timestamp)

            flow_meta[flow_key]["dst_ip"] = dst_ip

            # Extract TLS details
            ja3_hash = compute_ja3(pkt)
            if ja3_hash != "N/A":
                flow_meta[flow_key]["ja3"].add(ja3_hash)

            sni = extract_sni(pkt)
            if sni != "N/A":
                flow_meta[flow_key]["sni"].add(sni)

    flow_profiles = []
    min_connections = getattr(config, 'MIN_CONNECTIONS_TO_ANALYZE', 1)

    for flow_key, timestamps in flows.items():
        if len(timestamps) < min_connections:
            continue

        timestamps.sort()
        deltas = np.diff(timestamps)
        mean_interval = float(np.mean(deltas)) if len(deltas) > 0 else 0.0
        std_dev = float(np.std(deltas)) if len(deltas) > 0 else 0.0
        jitter_pct = float((std_dev / mean_interval) * 100) if mean_interval > 0 else 0.0

        dst_ip = flow_meta[flow_key]["dst_ip"]
        intel = query_abuseipdb(dst_ip)

        # Normalize timestamps relative to t0 for waterfall chart
        t0 = timestamps[0]
        relative_timestamps = [round(t - t0, 2) for t in timestamps]

        flow_profiles.append({
            "flow": flow_key,
            "dst_ip": dst_ip,
            "connection_count": len(timestamps),
            "mean_interval_sec": round(mean_interval, 2),
            "std_dev_sec": round(std_dev, 2),
            "jitter_percentage": round(jitter_pct, 2),
            "timestamps_relative": relative_timestamps,
            "ja3_fingerprints": list(flow_meta[flow_key]["ja3"]),
            "sni_hostname": list(flow_meta[flow_key]["sni"]),
            "threat_intel": intel
        })

    return flow_profiles


from scapy.all import PcapReader  # Ensure PcapReader is imported at top or here

def extract_flow_metrics(pcap_path: str, max_packets: int = 3000) -> list:
    """Streams PCAP packets iteratively to guarantee zero crashes and ultra-fast processing."""
    packets = []
    try:
        with PcapReader(pcap_path) as reader:
            for idx, pkt in enumerate(reader):
                packets.append(pkt)
                if idx >= max_packets:
                    break
    except Exception as e:
        print(f"[!] Warning reading PCAP: {e}")

    return process_packets(packets)


def sniff_live_traffic(interface=None, packet_count=100) -> list:
    """Sniffs live traffic with TCP Session reassembly."""
    print(f"[*] Sniffing {packet_count} packets live...")
    packets = sniff(iface=interface, count=packet_count, session=TCPSession)
    return process_packets(packets)