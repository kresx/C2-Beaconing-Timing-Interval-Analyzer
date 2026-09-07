import hashlib
import ipaddress
from functools import lru_cache
from collections import defaultdict
import requests
import numpy as np

from scapy.all import sniff, IP, TCP, UDP, TCPSession, PcapReader
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
import config

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

def _to_int(val) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 0)
        except ValueError:
            pass
    if hasattr(val, "val"):
        return val.val
    return None

def compute_ja3(packet) -> str:
    try:
        if packet.haslayer(TLSClientHello):
            tls = packet[TLSClientHello]
            version = str(getattr(tls, 'version', 771))
            
            ciphers = "-".join(str(c) for c in map(_to_int, getattr(tls, 'ciphers', [])) 
                               if c is not None and c not in GREASE_VALUES)
            
            ext_list, curves_list, pf_list = [], [], []
            if hasattr(tls, 'ext') and tls.ext:
                for ext in tls.ext:
                    ext_type = _to_int(getattr(ext, 'type', None))
                    if ext_type is not None and ext_type not in GREASE_VALUES:
                        ext_list.append(str(ext_type))
                        if ext_type == 10:
                            groups = getattr(ext, 'groups', getattr(ext, 'named_group_list', []))
                            curves_list.extend(str(g) for g in map(_to_int, groups) 
                                               if g is not None and g not in GREASE_VALUES)
                        elif ext_type == 11:
                            ec_pf = getattr(ext, 'ecpl', getattr(ext, 'ec_point_formats', []))
                            pf_list.extend(str(p) for p in map(_to_int, ec_pf) if p is not None)
                            
            ja3_str = f"{version},{ciphers},{'-'.join(ext_list)},{'-'.join(curves_list)},{'-'.join(pf_list)}"
            return hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
    except Exception:
        pass
    return "N/A"

def extract_sni(packet) -> str:
    try:
        if packet.haslayer(TLSClientHello):
            tls = packet[TLSClientHello]
            if hasattr(tls, 'ext') and tls.ext:
                for ext in tls.ext:
                    ext_type = _to_int(getattr(ext, 'type', None))
                    if isinstance(ext, TLS_Ext_ServerName) or ext_type == 0:
                        for sn in getattr(ext, 'servernames', []):
                            servername = getattr(sn, 'servername', None)
                            if servername:
                                return servername.decode('utf-8', errors='ignore') if isinstance(servername, bytes) else str(servername)
    except Exception:
        pass
    return "N/A"

@lru_cache(maxsize=1024)
def query_abuseipdb(ip_addr: str) -> dict:
    try:
        if ipaddress.ip_address(ip_addr).is_private or not getattr(config, 'ABUSEIPDB_API_KEY', None):
            return {"abuse_score": 0, "reports": 0, "is_whitelisted": True}
    except ValueError:
        return {"abuse_score": 0, "reports": 0, "is_whitelisted": False}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_addr, "maxAgeInDays": 90}
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

def process_packets(packet_iterator) -> list:
    flows = defaultdict(list)
    flow_meta = defaultdict(lambda: {"ja3": set(), "sni": set(), "dst_ip": "", "payload_bytes": []})
    
    for pkt in packet_iterator:
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            proto = "TCP" if pkt.haslayer(TCP) else "UDP"
            # ACK-only TCP packets reflect transport behavior, not beacon events.
            if pkt.haslayer(TCP) and len(pkt[TCP].payload) == 0:
                continue
            src, dst = pkt[IP].src, pkt[IP].dst
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
            flow_key = f"{src} -> {dst}:{dport} ({proto})"
            
            flows[flow_key].append(float(pkt.time))
            flow_meta[flow_key]["dst_ip"] = dst
            payload = pkt[TCP].payload if pkt.haslayer(TCP) else pkt[UDP].payload
            flow_meta[flow_key]["payload_bytes"].append(len(payload))
            
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
        std_dev = float(np.std(deltas, ddof=1)) if len(deltas) > 1 else 0.0
        jitter_pct = float((std_dev / mean_interval) * 100) if mean_interval > 0 else 0.0
        
        dst_ip = flow_meta[flow_key]["dst_ip"]
        intel = query_abuseipdb(dst_ip)
        relative_timestamps = [round(t - timestamps[0], 2) for t in timestamps]
        
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

def extract_flow_metrics(pcap_path: str, max_packets: int = 50000) -> list:
    try:
        def stream_pcap():
            with PcapReader(pcap_path) as reader:
                for idx, pkt in enumerate(reader):
                    if idx >= max_packets: break
                    yield pkt
        return process_packets(stream_pcap())
    except Exception as e:
        print(f"[!] PCAP Error: {e}")
        return []

def sniff_live_traffic(interface=None, packet_count=100, timeout=30) -> list:
    print(f"[*] Sniffing up to {packet_count} packets for {timeout} seconds...")
    packets = sniff(iface=interface, count=packet_count, timeout=timeout, session=TCPSession)
    return process_packets(packets)