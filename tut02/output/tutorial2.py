from scapy.all import *

# Function to capture the TCP 3-way handshake initiation
def first():
    a = sniff(count=250)
    for item in a:
        if item.haslayer(TCP) and item[TCP].flags == 2:
            packet = []
            packet.append(item)
            ip_src = item[TCP].sport
            ip_dst = item[TCP].dport
            for item2 in a:
                if item2.haslayer(TCP) and item2[TCP].flags == 18 and item2[TCP].sport == ip_dst and item2[TCP].dport == ip_src:
                    packet.append(item2)
                    for item3 in a:
                        if item3.haslayer(TCP) and item3[TCP].flags == 16 and item3[TCP].sport == ip_src and item3[TCP].dport == ip_dst:
                            packet.append(item3)
                            wrpcap("TCP_3_way_handshake_start_2101CS24.pcap", packet)
                            return
    first()

# Function to capture TCP connection close
def second():
    a = sniff(count=10, lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags == 17)
    for item in a:
        packet = []
        packet.append(item)
        port_src = item[TCP].sport
        port_dst = item[TCP].dport
        for item2 in a:
            if item2[TCP].sport == port_dst and item2[TCP].dport == port_src:
                packet.append(item2)
                wrpcap("TCP_handshake_close_2101CS24.pcap", packet)
                return
    second()

# Function to capture two TCP packets
def third():
    a = sniff(count=10, lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags == 16)
    for item in a:
        packet = []
        packet.append(item)
        port_src = item[TCP].sport
        port_dst = item[TCP].dport
        for item2 in a:
            if item2[TCP].sport == port_dst and item2[TCP].dport == port_src:
                packet.append(item2)
                wrpcap("TCP_Packets_2101CS24.pcap", packet)
                return
    third()

# Function to capture two UDP packets
def fourth():
    a = sniff(count=10, lfilter=lambda x: x.haslayer(UDP))
    for item in a:
        packet = []
        packet.append(item)
        port_src = item[UDP].sport
        port_dst = item[UDP].dport
        for item2 in a:
            if item2[UDP].sport == port_dst and item2[UDP].dport == port_src:
                packet.append(item2)
                wrpcap("UDP_Packets_2101CS24.pcap", packet)
                return
    fourth()

# Main packet capture
# Call the capture functions with the captured packets
first()
second()
third()
fourth()
