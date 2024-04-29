from scapy.all import *
import pandas as pd
import pyshark as ps
import csv 

def get_sequence_number(option):
    if option == "-sT":
        return 0
    elif option == "-sS":
        return 0
    elif option == "-sN":
        return 1
    elif option == "-sF":
        return 1
    elif option == "-sX":
        return 1
    elif option == "-sA":
        return 1
    elif option=="-sM":
        return 1
    return 0

pcap_file = "More_normal_packetssc.pcapng"

pkts = rdpcap(pcap_file)

# pkts = ps.FileCapture
count  = 1 
for pkt in pkts:
    packet_features = []

    syn_flag = int(pkt[TCP].flags.S)
    ack_flag = int(pkt[TCP].flags.A)
    psh_flag = int(pkt[TCP].flags.P)
    urg_flag = int(pkt[TCP].flags.U)
    fin_flag = int(pkt[TCP].flags.F)

    packet_features.append(syn_flag)
    packet_features.append(ack_flag)
    packet_features.append(psh_flag)
    packet_features.append(urg_flag)
    packet_features.append(fin_flag)


    window_size = pkt[TCP].window
    mss = 0
    if pkt[TCP].options:
        if pkt[TCP].options[0][1]:
            mss = pkt[TCP].options[0][1]

    option = ""
    sequence_no = get_sequence_number(option)
    port_scan_pkt = "NO"

    packet_features.append(window_size)
    packet_features.append(mss)
    packet_features.append(sequence_no)
    packet_features.append(port_scan_pkt)


    with open("Nmap_detection.csv",'a',newline='') as file:
        writer = csv.writer(file)

        writer.writerow(packet_features)
        
        print(f"{count} packet has been extracted")
        
    count +=1 

    




