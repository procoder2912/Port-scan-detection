import csv



with open('Port_scan_detection.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    field = ["flags","window_size","tcp.mss","port_scan_packet"]
    
    
    writer.writerow(field)
