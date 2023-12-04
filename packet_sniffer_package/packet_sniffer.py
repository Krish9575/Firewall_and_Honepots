import threading
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, Ether
from  ..firewall_package.primary_firewall import Firewall
from  ..honeypot_package.honeypot import Honeypot
from  ..firewall_package.secondary_firewall import combined_analysis
from firewall_package import secondary_firewall

def packet_callback(packet,results_queue):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
        else:
            ip_src = ip_dst = "N/A"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "N/A"
            src_port = dst_port = "N/A"

        if Ether in packet:
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
        else:
            mac_src = mac_dst = "N/A"

        payload = packet.payload
        print(f"Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}, {protocol}, {mac_src} -> {mac_dst}")
        print("Payload:", payload)
        print("-" * 50)

        # Here you would add logic to send the packet information to the firewall and honeypot

        request={
             'source_ip':ip_src,
              'destination_ip':ip_dst,
              'source_port':src_port,
              'destination_port' :dst_port,
              'protocol':protocol
        }
        firewall_thread = threading.Thread(target=Firewall.Matches,
                                           args=(request,results_queue))
        honeypot_thread = threading.Thread(target=Honeypot.analyze_packet,
                                           args=(request,results_queue,packet))

        firewall_thread.start()
        honeypot_thread.start()

        firewall_thread.join()
        honeypot_thread.join()
        

        secondary_firewall.combined_analysis(packet,results_queue)

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_packet_sniffer():
    results_queue=Queue()
    try:
        print("Starting packet sniffer...")
        sniff(prn=lambda x: packet_callback(x, results_queue), store=0)
    except KeyboardInterrupt:
        print("Packet sniffer stopped by user.")

if __name__ == "__main__":
    results_queue = Queue()
    sniffer_thread = threading.Thread(target=start_packet_sniffer)
    sniffer_thread.start()
    sniffer_thread.join()  # Wait for the packet sniffer thread to finish before exiting
