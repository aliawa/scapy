from scapy.all import *

if1='00:1b:17:00:01:10'
if2='00:1b:17:00:01:11'
pkts = rdpcap("/home/aawais/tmp/rx_filtered_2.pcap")
i=0
j=0
for pkt in pkts:
    if (Raw in pkt):
        print (pkt[Ether].dst)
        if pkt[Ether].dst == if1:
            filename="if1_{}.bin".format(i)
            i+=1
        else:
            filename="if2_{}.bin".format(j)
            j+=1
            
        f = open(filename, 'wb')
        f.write(pkt[Raw].load)

