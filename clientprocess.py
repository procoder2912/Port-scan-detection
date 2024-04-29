import socket as s
import numpy as np


server_ip = "192.168.0.104"
server_port = 5443

client = s.socket(s.AF_INET,s.SOCK_STREAM)
client.connect((server_ip,server_port))


tuple = client.recv(1024)

for ele in tuple:
    print(ele)


client.close()
