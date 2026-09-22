#required modules 
import os
import sys
import time 
from collections import defaultdict
from scapy.all import sniff, IP

#limit of compariong traffic
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / interval_time

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP : {ip}, packet rate: {packet_rate} ")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)