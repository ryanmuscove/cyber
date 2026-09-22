#required modules & libraries 
import os
import sys
import time 
from collections import defaultdict
from scapy.all import sniff, IP #helps analyze netwokr packets

#limit of comparing traffic
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")


def packet_callback(packet):#recieves argument packet 
    src_ip = packet[IP].src
    packet_count[src_ip] += 1
    current_time = time.time() #records time
    time_interval = current_time - start_time[0]

    if time_interval >= 1:  #evaultes if a DoS attack is happening at a frequency of once every second. 
        for ip, count in packet_count.items(): #if interval is = or larger than 1, the loop executes
            packet_rate = count / time_interval #calcualte packet rate

            if packet_rate > THRESHOLD and ip not in blocked_ips: #ensuring multiple ip tables aren't created
                print(f"Blocking IP : {ip}, packet rate: {packet_rate} ")
                print(f"Would block {ip}")
                blocked_ips.add(ip) #keeping track of blocked ip addresses

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__": #main function
    #if os.geteuid() != 0:
      #  print("This script requires administrator privilages.")
    #sys.ext()

    packet_count = defaultdict(int) #default data strucutre to assign default value
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)