"""
Recon Agent
Responsible for network and host discovery only.
Produces structured recon JSON artifact.
"""

from pathlib import Path
from datetime import datetime
import json
import uuid
import subprocess

from tools.nmap_discovery import (
    icmp_discovery,
    tcp_discovery,
    port_service_scan
)
# -----------------------------
# Load JSON template
# -----------------------------
def load_recon_template():
    template_path = Path("docs/recon_data_model.json")
    with open(template_path, "r") as f:
        return json.load(f)


# -----------------------------
# Initialize metadata
# -----------------------------
def initialize_metadata(recon_data, target):
    recon_data["scan_metadata"]["scan_id"] = str(uuid.uuid4())
    recon_data["scan_metadata"]["target"] = target
    recon_data["scan_metadata"]["timestamp"] = datetime.utcnow().isoformat() + "Z"
    recon_data["scan_metadata"]["initiated_by"] = "user"


# -----------------------------
# Detect network context
# -----------------------------
def get_network_context():
    context = {}

    ip_output = subprocess.run(
        ["ip", "-4", "addr", "show"],
        capture_output=True,
        text=True
    ).stdout

    context["scanner_ip"] = "unknown"
    context["interface"] = "unknown"
    context["network_type"] = "unknown"

    for line in ip_output.splitlines():
        if "inet " in line and "127.0.0.1" not in line:
            parts = line.strip().split()
            context["scanner_ip"] = parts[1].split("/")[0]

    return context


# -----------------------------
# Parse discovered hosts
# -----------------------------
def parse_nmap_hosts(nmap_output):
    hosts = []

    for line in nmap_output.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1]

            hosts.append({
                "ip": ip,
                "status": "up",
                "discovery_method": ["icmp_ping"],
                "open_ports": []
            })

    return hosts


# -----------------------------
# Detect ICMP blocking
# -----------------------------
def detect_icmp_blocking(hosts):
    return len(hosts) == 0


# -----------------------------
# Save artifact to disk
# -----------------------------
def save_recon_artifact(recon_data):
    output_dir = Path("data/raw_scans")
    output_dir.mkdir(parents=True, exist_ok=True)

    target = recon_data["scan_metadata"]["target"].replace("/", "_")
    filename = f"recon_{target}.json"

    with open(output_dir / filename, "w") as f:
        json.dump(recon_data, f, indent=2)


# -----------------------------
# Main Recon Flow
# -----------------------------
# -----------------------------
# Main Recon Flow
# -----------------------------
def run_recon(target):

    recon_data = load_recon_template()
    initialize_metadata(recon_data, target)

    # Network context
    recon_data["network_context"].update(get_network_context())

    # --------------------------
    # ICMP Discovery
    # --------------------------
    raw_output = icmp_discovery(target)
    hosts = parse_nmap_hosts(raw_output)

    icmp_blocked = detect_icmp_blocking(hosts)

    recon_data["scan_strategy"]["discovery_methods"].append("icmp_ping")
    recon_data["scan_limitations"]["icmp_blocked"] = icmp_blocked

    # --------------------------
    # TCP Fallback (If ICMP blocked)
    # --------------------------
    if icmp_blocked:
        tcp_output = tcp_discovery(target)
        tcp_hosts = parse_nmap_hosts(tcp_output)

        for host in tcp_hosts:
            host["discovery_method"] = ["tcp_syn"]

        hosts.extend(tcp_hosts)
        recon_data["scan_strategy"]["discovery_methods"].append("tcp_syn")

    # --------------------------
    # Remove Duplicate Hosts
    # --------------------------
    unique_hosts = {h["ip"]: h for h in hosts}.values()
    hosts = list(unique_hosts)

    recon_data["hosts"] = hosts
    recon_data["summary"]["total_hosts_discovered"] = len(hosts)

    # --------------------------
    # Confidence Scoring
    # --------------------------
    if icmp_blocked:
        recon_data["scan_limitations"]["confidence_level"] = "medium"
        recon_data["scan_limitations"]["notes"] = "ICMP blocked, TCP fallback used"
    else:
        recon_data["scan_limitations"]["confidence_level"] = "high"
        recon_data["scan_limitations"]["notes"] = "ICMP discovery successful"

    # --------------------------
    # Port & Service Detection
    # --------------------------
    service_output = port_service_scan(target)
    port_data = parse_ports_services(service_output)

    for host in hosts:
        ip = host["ip"]

        if ip in port_data:
            host["open_ports"] = port_data[ip]
        else:
            host["open_ports"] = []

    # --------------------------
    # Summary Metrics (IMPORTANT)
    # --------------------------
    hosts_with_ports = sum(
        1 for h in hosts if len(h.get("open_ports", [])) > 0
    )

    recon_data["summary"]["hosts_with_open_ports"] = hosts_with_ports

    # Optional: overall confidence mirror
    recon_data["summary"]["overall_recon_confidence"] = \
        recon_data["scan_limitations"]["confidence_level"]

    # --------------------------
    # Save Artifact
    # --------------------------
    save_recon_artifact(recon_data)

def parse_ports_services(nmap_output):
    host_data = {}

    current_ip = None

    for line in nmap_output.splitlines():

        if "Nmap scan report for" in line:
            current_ip = line.split()[-1]
            host_data[current_ip] = []

        if "/tcp" in line and "open" in line:
            parts = line.split()

            port = int(parts[0].split("/")[0])
            service = parts[2]

            version = "unknown"
            if len(parts) > 3:
                version = " ".join(parts[3:])

            host_data[current_ip].append({
                "port": port,
                "protocol": "tcp",
                "service": service,
                "version": version
            })

    return host_data