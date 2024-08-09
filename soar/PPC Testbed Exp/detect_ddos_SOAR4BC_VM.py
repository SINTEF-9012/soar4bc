from scapy.all import rdpcap, IP, TCP

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)
    total_http_requests = 0
    total_http_404_errors = 0
    continuous_404_errors = 0
    potential_ddos = False

    for i, packet in enumerate(packets):
        try:
            # Check if the packet has the 'IP' and 'TCP' layers
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_layer = packet.getlayer(IP)
                tcp_layer = packet.getlayer(TCP)
                
                # Debugging output (optional)
                # print(f"Packet {i}:")
                # print("Packet Layers:", [layer.name for layer in packet.layers()])
                # print(f"Source IP: {ip_layer.src}")
                # print(f"Destination IP: {ip_layer.dst}")
                # print(f"Source Port: {tcp_layer.sport}")
                # print(f"Destination Port: {tcp_layer.dport}")
                
                # Check for raw payload (HTTP data)
                if packet.haslayer('Raw'):
                    raw_data = packet.getlayer('Raw').load
                    try:
                        decoded_data = raw_data.decode(errors='ignore')
                        if "404 Not Found" in decoded_data:
                            total_http_404_errors += 1
                            total_http_requests += 1
                            continuous_404_errors += 1
                            #print(f"Consecutive 404 errors: {continuous_404_errors}")  # Debugging output
                        else:
                            continuous_404_errors = 0  # Reset counter if not 404
                        
                        # Check for potential DDoS attack
                        if continuous_404_errors >= 3:
                            potential_ddos = True
                            print(f"Potential DDoS attack ongoing!")

                    except Exception as e:
                        print(f"Error decoding raw data: {e}")
        except Exception as e:
            print(f"Error processing packet {i}: {e}")

    # Final report
    print("Anomaly Detection Report:")
    print("========================")
    print(f"Total HTTP requests processed: {total_http_requests}")
    print(f"Total HTTP 404 errors: {total_http_404_errors}")
    if potential_ddos:
        print("A potential DDoS attack on CSMS is detected!")
    else:
        print("No DDoS attack detected based on HTTP 404 errors.")

if __name__ == '__main__':
    analyze_packets('/home/user/capture.pcap')
