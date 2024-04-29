from scapy.all import *
import subprocess as sp
import joblib as jl
import numpy as np
import warnings
#from tensorflow.keras.models import load_model 


scale = jl.load("Scaleobjdata.pkl")
voting = jl.load("VotingClassifier.pkl")

def predict_result(arr):
    #print(arr)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore",category=UserWarning)
        feature = scale.transform([arr])
        prediction = voting.predict(feature)
        return prediction



def get_sequence_no():
    result = sp.run([
    'tshark',
    '-r', 'output.pcapng',
    '-Y', 'tcp',
    '-T', 'fields', '-e', 'tcp.seq'
    ], capture_output=True, text=True)
    
    ls = []
    if result.returncode == 0:
        ls = [line for line in result.stdout.split('\n') if line]
    else:
        print("Error:",result.stderr)
        return -1

    return ls
 

def get_ack_number():
    result = sp.run([
    'tshark',
    '-r', 'output.pcapng',
    '-Y', 'tcp',
    '-T', 'fields', '-e', 'tcp.ack'
    ], capture_output=True, text=True)
    ls = []
    if result.returncode == 0:
        ls = [line for line in result.stdout.split('\n') if line]
    else:
        print("Error: ",result.stderr)
        
        return -1
    return ls






if __name__=="__main__":
    capture  = sp.run([
        'tshark',
        '-i', 'any',
        '-f', 'tcp',
        '-a', 'duration:10',
        '-w', 'output.pcapng'
    ],capture_output=True,text=True)

    pkts = rdpcap('output.pcapng')

    sequenceNum = get_sequence_no()
    ackNum = get_ack_number()
   # print(ackNum)
#    print(sequenceNum)
    dic = {}
    countNor = 0
    countMal = 0
    for pkt,seq_no,ack in zip_longest(pkts,sequenceNum,ackNum):
        if pkt[TCP].flags.R:
            continue
        feature = []
     #   print(type(int(seq_no)))
        feature.append(pkt[TCP].flags.S)
        feature.append(int(ack))
        feature.append(pkt[TCP].flags.P)
        feature.append(pkt[TCP].flags.U)
        feature.append(pkt[TCP].flags.F)      
        window_size = pkt[TCP].window
        mss = 0
        if pkt[TCP].options:
            if pkt[TCP].options[0][1]:
                mss = pkt[TCP].options[0][1]


        feature.append(window_size)
        feature.append(mss)
        feature.append(int(seq_no))

        if predict_result(feature):
            countMal = countMal + 1
            print("%d)Port scan detected from %s"%(countMal,pkt[IP].src))
            print(pkt[IP].show())
            dic[pkt[IP].src] = dic.setdefault(pkt[IP].src,0)+1
            
        else:
            countNor = countNor + 1
    

    max_ip = None
    max_connection = 0
    for ip,connection in dic.items():
        if connection>max_connection:
            max_connection = connection
            max_ip = ip


    
    print("No of Port scan packets detected %d"%countMal)
    print("No of Normal packets detected %d"%countNor)
    print("%s tried to make connection %d times"%(max_ip,max_connection))

        








