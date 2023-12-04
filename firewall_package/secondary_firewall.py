from firewall_package.deep_packet_analysis import DeepPacketAnalysis

def combined_analysis(firewall_action, honeypot_value,packet_info):
    threshold=0.5
    """Determine the final action based on firewall and honeypot results."""
    if firewall_action == "ALLOW":
        if honeypot_value < threshold:
            return "ALLOW"
        elif honeypot_value == threshold:
            return DeepPacketAnalysis(packet_info)
        else:
            return DeepPacketAnalysis(packet_info)
    elif firewall_action == "DROP":
        if honeypot_value < threshold:
            return DeepPacketAnalysis(packet_info)
        elif honeypot_value == threshold:
            return "DENIED"
        else:
            return "DENIED"
    else:  # firewall_action is "DENIED"
        if honeypot_value < threshold:
            return DeepPacketAnalysis(packet_info)
        else:
            return "DENIED"