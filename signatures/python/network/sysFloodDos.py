# This script requires the Scapy library. Install it with: pip install scapy
from scapy.all import IP, TCP, sr1, conf
import logging

# Suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def check_tcp_stack_anomaly(target_ip, target_port):

    # Checks for a TCP stack anomaly by sending a SYN+FIN packet.
    # METADATA BLOCK
    signature_metadata = {
        'unique_identifier': 'NET-STACK-SYNFIN-ANOMALY-1.0',
        'targeting_criteria': 'Any network device or server running a TCP/IP stack.',
        'severity': 'MEDIUM' # This often indicates a fragile stack, not direct exploitation.
    }

    # Standardized output structure
    result = {
        'vulnerable': False,
        'evidence': '',
        'metadata': signature_metadata
    }

    # PHASE 1: PROBE (Pre-condition Check)

    # Before sending our malformed packet, we must confirm the target port is open.
    try:
        probe_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
        probe_response = sr1(probe_packet, timeout=3)
        # print("*** [Initial Probe] --> ", probe_response)

        if probe_response is None:
            result['evidence'] = "Probe failed. No response received for initial SYN packet. Port may be filtered."
            return result

        # The 'SA' flags (SYN-ACK) are the expected response from an open port.
        if not (probe_response.haslayer(TCP) and probe_response.getlayer(TCP).flags == 0x12): # 0x12 is SYN-ACK
            result['evidence'] = f"Probe failed. Port appears closed or is not responding as expected. Response flags: {probe_response.getlayer(TCP).flags}"
            return result
            
    except Exception as e:
        result['evidence'] = f"Probe failed due to an exception: {e}"
        return result


    # PHASE 2: TRIGGER (The Active Check)

    # Now that we know the port is open, we craft and send the malformed packet
    # with both the SYN and FIN flags set.
    try:
        # 'SF' sets the SYN (0x02) and FIN (0x01) flags.
        trigger_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='SF')
        trigger_response = sr1(trigger_packet, timeout=3)
    except Exception as e:
        result['evidence'] = f"Trigger failed due to an exception during packet sending: {e}"
        return result

    # PHASE 3: VERIFY (Post-condition Analysis)
    # A compliant stack on an open port should silently drop the SYN+FIN packet.
    # A vulnerable stack will often reply with a RST packet. Receiving this RST
    # is the definitive sign of the anomaly.
    if trigger_response is None:
        result['evidence'] = "Verification failed. No response to SYN+FIN packet. This indicates compliant (non-vulnerable) behavior."
        return result

    if trigger_response.haslayer(TCP) and trigger_response.getlayer(TCP).flags == 0x14: # 0x14 is RST-ACK
        result['vulnerable'] = True
        result['evidence'] = "Verification successful. Target responded with a RST-ACK packet to a SYN-FIN packet, which is anomalous for an open port."
    elif trigger_response.haslayer(TCP) and trigger_response.getlayer(TCP).flags == 0x04: # 0x04 is RST
        result['vulnerable'] = True
        result['evidence'] = "Verification successful. Target responded with a RST packet to a SYN-FIN packet, which is anomalous for an open port."
    else:
        flags = trigger_response.getlayer(TCP).flags if trigger_response.haslayer(TCP) else 'N/A'
        result['evidence'] = f"Verification failed. Target gave an unexpected response. Flags: {flags}"

    return result

if __name__ == '__main__':
    # Example usage: Replace with target IP and an open port (e.g., 80, 443, 22).
    target_ip = 'localhost'
    target_port = 65432
    print(f"[*] Checking TCP stack anomaly on {target_ip}:{target_port}")
    vulnerability_status = check_tcp_stack_anomaly(target_ip, target_port)
    print(f"[*] Result: {vulnerability_status}")
