import threading
import json
import time
from scapy.all import sniff, IP, TCP, UDP, Ether
import sqlite3

# Configuration
FIREWALL_RULES = "firewall_rules.json"
CONNECTION_LOG_DB = "connection_log.db"

# Initialize SQLite database for connection log
def initialize_database():
    connection = sqlite3.connect(CONNECTION_LOG_DB)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS connection_log (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            mac_src TEXT,
            mac_dst TEXT,
            payload TEXT,
            firewall_action TEXT,
            honeypot_action TEXT,
            final_action TEXT
        )
        """
    )

    connection.commit()
    connection.close()

# Log actions to the database
def log_to_db(log_data):
    connection = sqlite3.connect(CONNECTION_LOG_DB)
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO connection_log (
            timestamp, src_ip, dst_ip, src_port, dst_port, protocol, mac_src, mac_dst,
            payload, firewall_action, honeypot_action, final_action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_data["timestamp"], log_data["src_ip"], log_data["dst_ip"],
            log_data["src_port"], log_data["dst_port"], log_data["protocol"],
            log_data["mac_src"], log_data["mac_dst"], log_data["payload"],
            log_data["firewall_action"], log_data["honeypot_action"], log_data["final_action"]
        ),
    )

    connection.commit()
    connection.close()

# Load firewall rules from a file
def load_firewall_rules():
    try:
        with open(FIREWALL_RULES, 'r') as f:
            rules = json.load(f)
        return rules
    except FileNotFoundError:
        return []

# Firewall logic
def firewall(packet_info):
    rules = load_firewall_rules()
    for rule in rules:
        if (
            packet_info["src_ip"] == rule["ip"]
            and packet_info["src_port"] == rule["port"]
            and packet_info["protocol"] == rule["protocol"]
        ):
            action = rule["action"]
            break
    else:
        action = "ALLOW"

    return action

# Honeypot logic
def honeypot(packet_info):
    if len(packet_info["payload"]) > 1000:
        action = "BLOCK"
    else:
        action = "ALLOW"

    return action

# Secondary firewall logic
def secondary_firewall(packet_info, firewall_action, honeypot_action):
    if firewall_action == "BLOCK" or honeypot_action == "BLOCK":
        action = "BLOCK"
    else:
        action = "ALLOW"

    return action

# Packet callback function for Scapy
def packet_callback(packet):
    packet_info = {
        "timestamp": time.time(),
        "src_ip": packet[IP].src if IP in packet else "N/A",
        "dst_ip": packet[IP].dst if IP in packet else "N/A",
        "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "N/A"),
        "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "N/A"),
        "protocol": "TCP" if TCP in packet else ("UDP" if UDP in packet else "N/A"),
        "mac_src": packet[Ether].src if Ether in packet else "N/A",
        "mac_dst": packet[Ether].dst if Ether in packet else "N/A",
        "payload": str(packet.payload)
    }

    # Run firewall and honeypot in parallel threads
    firewall_thread = threading.Thread(target=firewall, args=(packet_info,))
    honeypot_thread = threading.Thread(target=honeypot, args=(packet_info,))
    firewall_thread.start()
    honeypot_thread.start()
    firewall_thread.join()
    honeypot_thread.join()

    # Get results from firewall and honeypot
    firewall_action = firewall_thread.result if hasattr(firewall_thread, "result") else "ALLOW"
    honeypot_action = honeypot_thread.result if hasattr(honeypot_thread, "result") else "ALLOW"

    # Make the final decision with secondary firewall
    final_action = secondary_firewall(packet_info, firewall_action, honeypot_action)

    # Log all actions to the database
    log_data = {
        "timestamp": packet_info["timestamp"],
        "src_ip": packet_info["src_ip"],
        "dst_ip": packet_info["dst_ip"],
        "src_port": packet_info["src_port"],
        "dst_port": packet_info["dst_port"],
        "protocol": packet_info["protocol"],
        "mac_src": packet_info["mac_src"],
        "mac_dst": packet_info["mac_dst"],
        "payload": packet_info["payload"],
        "firewall_action": firewall_action,
        "honeypot_action": honeypot_action,
        "final_action": final_action,
    }
    log_to_db(log_data)

    print(f"Final Action for packet from {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}: {final_action}")
    print("-" * 50)

def start_packet_sniffer():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Initialize the database
    initialize_database()

    # Start listening for connections
    start_packet_sniffer()
