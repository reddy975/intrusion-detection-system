

#!/usr/bin/env python3
"""
kali_realtime_sniffer.py

Run on Kali (VM). Requirements:
  sudo apt install python3-pip
  pip3 install scapy requests

Usage:
  sudo python3 kali_realtime_sniffer.py

What it does:
 - Sniffs packets and aggregates them into directional flows (src->dst).
 - When a flow is inactive for FLOW_TIMEOUT seconds, compute features for that flow.
 - Post JSON with the 38 features to the Flask endpoint at HOST:5000/api/flow.
 - If the Flask server responds with "Blocked", the script will add an iptables DROP rule
   for the source IP (avoids duplicate rules).
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
import json
import requests
import sys
import math
import subprocess

from scapy.all import sniff, IP, TCP, UDP

# ---------- CONFIG ----------
HOST = "http://192.168.0.103:5000"   # CHANGE to your Windows host IP
API = HOST + "/api/flow"

FLOW_TIMEOUT = 5        # seconds of inactivity to consider a flow finished
FLOW_MAX_AGE = 120      # maximum seconds before forcing evaluation
WINDOW_SECS = 60        # sliding window in seconds for aggregated global metrics
SNAP_COUNT = 0          # 0 = continuous
POST_TIMEOUT = 3        # requests timeout
RETRY_POST = 2          # retries on post failure
# ----------------------------

# Feature names (must match model / dashboard expectations)
FEATURE_NAMES = [
    "pkSeqID", "stime", "flgs", "flgs_number", "proto_number",
    "pkts", "bytes", "state_number", "ltime", "seq", "dur",
    "mean", "stddev", "sum", "min", "max", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "srate", "drate",
    "TnBPSrcIP", "TnBPDstIP", "TnP_PSrcIP", "TnP_PDstIP",
    "TnP_PerProto", "TnP_Per_Dport", "AR_P_Proto_P_SrcIP",
    "AR_P_Proto_P_DstIP", "N_IN_Conn_P_DstIP", "N_IN_Conn_P_SrcIP",
    "AR_P_Proto_P_Sport", "AR_P_Proto_P_Dport",
    "Pkts_P_State_P_Protocol_P_DestIP",
    "Pkts_P_State_P_Protocol_P_SrcIP"
]

# ---------- helpers & data structures ----------
# Flow key: (src, dst, sport, dport, proto)
class Flow:
    def __init__(self, key, ts):
        self.key = key
        self.start = ts
        self.last = ts
        self.pkt_count = 0
        self.byte_count = 0
        self.pkt_sizes = []
        # directional counts: source->dest (as seen)
        self.spkts = 0
        self.dpkts = 0
        self.sbytes = 0
        self.dbytes = 0
        # flags counts (only TCP flags considered)
        self.flag_counts = defaultdict(int)
        # store some example state metric (we'll keep 0/1 style)
        self.state_number = 0

    def update(self, pkt_len, src_is_srcside=True, flags=None, ts=None):
        self.pkt_count += 1
        self.byte_count += pkt_len
        self.pkt_sizes.append(pkt_len)
        if src_is_srcside:
            self.spkts += 1
            self.sbytes += pkt_len
        else:
            self.dpkts += 1
            self.dbytes += pkt_len
        if flags:
            for ch in flags:
                self.flag_counts[ch] += 1
        if ts:
            self.last = ts

    def duration(self):
        return max(1e-6, self.last - self.start)

# active flows store
flows = {}
flows_lock = threading.Lock()

# sliding window to compute global stats (timestamped events)
window_events = deque()  # each entry: (ts, src, dst, proto, bytes, sport, dport)
window_lock = threading.Lock()

seq_counter = 0  # to assign pkSeqID unique incremental number

# ---------- IP blocking helpers ----------
blocked_ips = set()  # keep track of already-blocked IPs (to avoid duplicate rules)

def block_ip(ip):
    """Block the given IP using iptables (only if not already blocked)."""
    if ip in blocked_ips:
        return
    try:
        # Add a DROP rule for the IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.add(ip)
        print(f"[BLOCK] {ip} blocked via iptables")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block {ip}: {e}")

def unblock_ip(ip):
    """Remove DROP rule for IP (best effort)."""
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        if ip in blocked_ips:
            blocked_ips.discard(ip)
        print(f"[UNBLOCK] {ip} unblocked (iptables rule removed)")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to unblock {ip}: {e}")

# ---------- feature computations ----------
def proto_to_number(proto_str):
    # TCP=6 UDP=17 ELSE 1
    if proto_str == "TCP":
        return 6
    if proto_str == "UDP":
        return 17
    return 1

def compute_flow_features(flow, key):
    """
    Compute the 38 features for a completed Flow object.
    Many metrics use sliding-window global stats to approximate dataset aggregates.
    """
    global seq_counter
    src, dst, sport, dport, proto = key
    seq_counter += 1

    # basic stats
    pkt_count = flow.pkt_count
    byte_count = flow.byte_count
    duration = flow.duration()
    mean_pkt = sum(flow.pkt_sizes) / pkt_count if pkt_count else 0.0
    stddev_pkt = (sum((x-mean_pkt)**2 for x in flow.pkt_sizes) / pkt_count)**0.5 if pkt_count else 0.0
    sbytes = flow.sbytes
    dbytes = flow.dbytes
    spkts = flow.spkts
    dpkts = flow.dpkts
    min_pkt = min(flow.pkt_sizes) if flow.pkt_sizes else 0.0
    max_pkt = max(flow.pkt_sizes) if flow.pkt_sizes else 0.0
    sum_pkt = sum(flow.pkt_sizes)

    # flags: percent of flagged packets and flgs_number count
    flag_total = sum(flow.flag_counts.values())
    flgs_number = len([k for k,v in flow.flag_counts.items() if v>0])
    flgs_percent = (flag_total / pkt_count * 100) if pkt_count else 0.0

    # proto number
    proto_number = proto_to_number(proto)

    # state_number placeholder
    state_number = 1 if ('F' in flow.flag_counts or 'R' in flow.flag_counts) else 0

    # rates
    rate = byte_count / duration if duration > 0 else 0.0
    srate = sbytes / duration if duration > 0 else 0.0
    drate = dbytes / duration if duration > 0 else 0.0

    # sliding-window global stats for this flow's src/dst
    now = time.time()
    with window_lock:
        cutoff = now - WINDOW_SECS
        while window_events and window_events[0][0] < cutoff:
            window_events.popleft()

        total_bytes_window = sum(evt[4] for evt in window_events)
        total_pkt_window = len(window_events)

        bytes_per_src = defaultdict(int)
        bytes_per_dst = defaultdict(int)
        pkts_per_src = defaultdict(int)
        pkts_per_dst = defaultdict(int)
        proto_counts = defaultdict(int)
        sport_counts = defaultdict(int)
        dport_counts = defaultdict(int)
        conn_in_dst = defaultdict(int)
        conn_in_src = defaultdict(int)
        seen_src_dst_pairs = set()
        for evt in window_events:
            t, e_src, e_dst, e_proto, e_bytes, e_sport, e_dport = evt
            bytes_per_src[e_src] += e_bytes
            bytes_per_dst[e_dst] += e_bytes
            pkts_per_src[e_src] += 1
            pkts_per_dst[e_dst] += 1
            proto_counts[e_proto] += 1
            sport_counts[e_sport] += 1
            dport_counts[e_dport] += 1
            if (e_src, e_dst) not in seen_src_dst_pairs:
                conn_in_dst[e_dst] += 1
                conn_in_src[e_src] += 1
                seen_src_dst_pairs.add((e_src, e_dst))

        TnBPSrcIP = (bytes_per_src.get(src, 0) / total_bytes_window * 100) if total_bytes_window > 0 else 0.0
        TnBPDstIP = (bytes_per_dst.get(dst, 0) / total_bytes_window * 100) if total_bytes_window > 0 else 0.0

        TnP_PSrcIP = (pkts_per_src.get(src, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0
        TnP_PDstIP = (pkts_per_dst.get(dst, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0

        TnP_PerProto = (proto_counts.get(proto, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0
        TnP_Per_Dport = (dport_counts.get(dport, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0

        AR_P_Proto_P_SrcIP = (proto_counts.get(proto, 0) / (pkts_per_src.get(src, 1)) * 100) if pkts_per_src.get(src,0) > 0 else 0.0
        AR_P_Proto_P_DstIP = (proto_counts.get(proto, 0) / (pkts_per_dst.get(dst, 1)) * 100) if pkts_per_dst.get(dst,0) > 0 else 0.0

        N_IN_Conn_P_DstIP = conn_in_dst.get(dst, 0)
        N_IN_Conn_P_SrcIP = conn_in_src.get(src, 0)

        AR_P_Proto_P_Sport = (proto_counts.get(proto, 0) / (sport_counts.get(sport, 1)) * 100) if sport_counts.get(sport,0) > 0 else 0.0
        AR_P_Proto_P_Dport = (proto_counts.get(proto, 0) / (dport_counts.get(dport, 1)) * 100) if dport_counts.get(dport,0) > 0 else 0.0

        Pkts_P_State_P_Protocol_P_DestIP = (pkts_per_dst.get(dst, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0
        Pkts_P_State_P_Protocol_P_SrcIP = (pkts_per_src.get(src, 0) / total_pkt_window * 100) if total_pkt_window > 0 else 0.0

    feat = {
        "pkSeqID": float(seq_counter),
        "stime": float(flow.start % 100000),
        "flgs": float(round(flgs_percent, 2)),
        "flgs_number": float(flgs_number),
        "proto_number": float(proto_number),
        "pkts": float(pkt_count),
        "bytes": float(byte_count),
        "state_number": float(state_number),
        "ltime": float(flow.last % 100000),
        "seq": float(seq_counter),
        "dur": float(round(duration, 4)),
        "mean": float(round(mean_pkt, 4)),
        "stddev": float(round(stddev_pkt, 4)),
        "sum": float(round(sum_pkt, 4)),
        "min": float(min_pkt),
        "max": float(max_pkt),
        "spkts": float(spkts),
        "dpkts": float(dpkts),
        "sbytes": float(sbytes),
        "dbytes": float(dbytes),
        "rate": float(round(rate, 4)),
        "srate": float(round(srate, 4)),
        "drate": float(round(drate, 4)),
        "TnBPSrcIP": float(round(TnBPSrcIP, 4)),
        "TnBPDstIP": float(round(TnBPDstIP, 4)),
        "TnP_PSrcIP": float(round(TnP_PSrcIP, 4)),
        "TnP_PDstIP": float(round(TnP_PDstIP, 4)),
        "TnP_PerProto": float(round(TnP_PerProto, 4)),
        "TnP_Per_Dport": float(round(TnP_Per_Dport, 4)),
        "AR_P_Proto_P_SrcIP": float(round(AR_P_Proto_P_SrcIP, 4)),
        "AR_P_Proto_P_DstIP": float(round(AR_P_Proto_P_DstIP, 4)),
        "N_IN_Conn_P_DstIP": float(N_IN_Conn_P_DstIP),
        "N_IN_Conn_P_SrcIP": float(N_IN_Conn_P_SrcIP),
        "AR_P_Proto_P_Sport": float(round(AR_P_Proto_P_Sport, 4)),
        "AR_P_Proto_P_Dport": float(round(AR_P_Proto_P_Dport, 4)),
        "Pkts_P_State_P_Protocol_P_DestIP": float(round(Pkts_P_State_P_Protocol_P_DestIP, 4)),
        "Pkts_P_State_P_Protocol_P_SrcIP": float(round(Pkts_P_State_P_Protocol_P_SrcIP, 4))
    }

    ordered = {name: feat.get(name, 0.0) for name in FEATURE_NAMES}
    return ordered

# ---------- event recorder for sliding window ----------
def add_window_event(ts, src, dst, proto, b, sport, dport):
    with window_lock:
        window_events.append((ts, src, dst, proto, b, sport, dport))

# ---------- flow sweeper ----------
def sweeper():
    while True:
        now = time.time()
        to_eval = []
        with flows_lock:
            for k, f in list(flows.items()):
                if (now - f.last) >= FLOW_TIMEOUT or (now - f.start) >= FLOW_MAX_AGE:
                    to_eval.append(k)
            for k in to_eval:
                flow = flows.pop(k, None)
                if flow:
                    feat = compute_flow_features(flow, k)
                    post_features(feat, k)
        time.sleep(1)

# ---------- post to Flask ----------
def post_features(feat_dict, key):
    src_ip = key[0]
    payload = feat_dict.copy()
    payload['src_ip'] = src_ip
    payload['dst_ip'] = key[1]
    for attempt in range(RETRY_POST):
        try:
            r = requests.post(API, json=payload, timeout=POST_TIMEOUT)
            if r.status_code == 200:
                print(f"[POST] Sent features for {src_ip} -> {key[1]} | status=200")
                # check server response for blocking instruction
                try:
                    resp = r.json()
                    # server may return "Blocked" or a structured response
                    server_pred = None
                    if isinstance(resp, dict):
                        # try common fields
                        server_pred = resp.get("prediction") or resp.get("alert") or resp.get("status")
                        # if server returns wrapped alert
                        if isinstance(server_pred, list) and server_pred:
                            server_pred = server_pred[0]
                    # normalize check
                    if server_pred and "block" in str(server_pred).lower() or server_pred == "Blocked" or server_pred == "Blocked (Real)" or server_pred == "Blocked (Simulated)":
                        block_ip(src_ip)
                except Exception:
                    pass
                return
            else:
                print(f"[POST] Received {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[ERROR] Post attempt {attempt+1}: {e}")
            time.sleep(0.5)
    print(f"[ERROR] Failed to POST features for {src_ip} after {RETRY_POST} attempts")

# ---------- packet callback ----------
def pkt_callback(pkt):
    try:
        if IP not in pkt:
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        sport = 0
        dport = 0
        proto = "OTHER"
        flags = None
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            proto = str(ip.proto)

        plen = len(pkt)
        ts = time.time()
        key = (src, dst, sport, dport, proto)

        add_window_event(ts, src, dst, proto, plen, sport, dport)

        with flows_lock:
            if key not in flows:
                flows[key] = Flow(key, ts)
            flows[key].update(pkt_len=plen, src_is_srcside=True, flags=flags, ts=ts)
    except Exception as e:
        print("[WARN] pkt_callback error:", e)

# ---------- main ----------
if __name__ == "__main__":
    print("[INFO] Starting flow sweeper background thread...")
    t = threading.Thread(target=sweeper, daemon=True)
    t.start()
    print("[INFO] Starting packet capture... (Ctrl-C to stop)")
    try:
        sniff(prn=pkt_callback, store=False, count=SNAP_COUNT)
    except KeyboardInterrupt:
        print("[INFO] Stopping sniffing, finalizing remaining flows...")
        with flows_lock:
            for k, f in list(flows.items()):
                feat = compute_flow_features(f, k)
                post_features(feat, k)
        print("[INFO] Done. Exiting.")
        sys.exit(0)
