 #!/usr/bin/python

#
# Don't throw warnings
#
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


#
# Imports 
#
import sys, getopt, random, os, logging, time
from scapy.all import *

#
# Constants
#
INFO = "INFO:"
ERROR = "ERROR:"


#
# Don't output Sending packet .. type of messages froms scapy
#
conf.verb = 0

#
# Usage
#
def usage():
        print "Script options"
        print "Where [required] and [[optional]] options are:"
        print "[[-h | --help]] for help message"
        print "[ -s | --src-ip] source IP"
        print "[ -d | --dest-ip] proxy IP"
        print "[[-r | --sport]] source port"
        print "[ -p | --dport] destination port"
        print "[[-1 | --src-mac]] source MAC Address"
        print "[[-2 | --dest-mac]] destination MAC Address"
        print "[[-t | --timeout]] timeout in seconds"
        print "[[-l | --ttl]] IP time-to-live value for packets"
        print "[[-q | --seqnum]] set sequence number of initial TCP packet"
        print "[[-v | --verbose]] show verbose output"
        print "[[-m | --timestring]] timestrings in log"
        print "[[-i | --setipt]] set iptables to reject RST packets from src host"

#
# Getopts
#
try:
        opts, args = getopt.getopt(sys.argv[1:], "hvmis:d:p:r:1:2:t:l:q:", 
                     ["help", "verbose", "timestring", "setipt=", 
                      "src-ip=", "dest-ip=", "sport=", "dport=", "src-mac=", "dest-mac=", 
                      "timeout=", "ttl=", "seqnum="])
except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(-1)

srcip = srcmac = destmac = ""
setipt = verbose = ts = destip = dport = None
seq_num = random.randint(1, 65534)
sport = random.randint(1024, 65534)

ttl = 64
tout = 0

for o, a in opts:
        if o in ("-h", "--help"):
                usage()
                sys.exit(0)
        elif o in ("-v", "--verbose"):
                verbose = 1
        elif o in ("-m", "--timestring"):
                ts = 1
        elif o in ("-i", "--setipt"):
                setipt = 1
        elif o in ("-s", "--src-ip"):
                srcip = a
        elif o in ("-d", "--dest-ip"):
                destip = a
        elif o in ("-r", "--sport"):
                sport = int(a)
        elif o in ("-p", "--dport"):
                dport = int(a)
        elif o in ("-1", "--src-mac"):
                srcmac = a
        elif o in ("-2", "--dest-mac"):
                destmac = a
        elif o in ("-t", "--timeout"):
                tout = int(a)
        elif o in ("-l", "--ttl"):
                ttl = int(a)
        elif o in ("-q", "--seqnum"):
                seqnum = a
        else:
                print "Unhandled Exception, see usage below\n"
                usage()
                sys.exit(-1)


def log(message, mt):
    if (verbose == 1):
        from time import gmtime, strftime
        tvalue = strftime("%a, %d %b %Y %H:%M:%S ", gmtime())

        if ts:
            print str(tvalue) + "%6s 5s" % mt, message
        else:
            print "%6s 5s" % mt, message

if not destip:
    log("Please enter Destination IP Address", ERROR)
    usage()
    sys.exit(-1)

if not srcip:
    log("Please enter Source IP Address", ERROR)
    usage()
    sys.exit(-1)

if not dport:
    log("Please enter destination port number", ERROR)
    usage()
    sys.exit(-1)

#
# Iptables configuration
#
if setipt:
    iptables_flush_cmd = 'iptables -F'
    #iptables_cmd = 'iptables -A OUTPUT -p tcp -d ' + destip + ' --tcp-flags RST, RST --destination-port ' + str(dport) + ' -j DROP'
    iptables_cmd = 'iptables -A OUTPUT -p tcp -d ' + destip + ' --tcp-flags RST  RST --destination-port ' + str(dport) + ' -j DROP'
    os.system(iptables_flush_cmd)
    os.system(iptables_cmd)

#
# TCP 3 way handshake
#
eth_layer = None
if srcmac and destmac:
    eth_layer = Ether(src = srcmac, dst = destmac)

ip_layer = IP(src = srcip, dst = destip, ttl = ttl)

tcp_layer  = TCP(sport = sport, dport = dport, flags = "S", seq = seq_num)
syn_pkt = tcp_layer

if eth_layer:
    init_pkt = eth_layer/ip_layer/tcp_layer
else:
    init_pkt = ip_layer/tcp_layer

synack_rec = sr1(init_pkt)
if (synack_rec):
    log("received synack from destination", INFO)
    ack_num = synack_rec.seq + 1
else:
    log("did not receive synack from destination", ERROR)
    sys.exit(1)

ack_pkt_tcp = TCP(sport = sport, dport = dport, flags = "A", seq = syn_pkt.seq + 1, 
    ack = ack_num)
ack_pkt = ip_layer/ack_pkt_tcp

log("sending ack to destination", INFO)
send(ack_pkt)

#
# Read request and send it to destination
#
sz=211
req_data = sys.stdin.read()
sq=syn_pkt.seq+1
st=0
ed=sz
mydata=req_data[st:ed]
pkts=[]
ip_id=1
while len(mydata) > 0:
  print mydata
  req_tcp_layer = TCP(sport = sport, dport = dport, flags = "PA", seq = sq,
    ack = ack_num)

  req_pkt = IP(src = srcip, dst = destip, ttl = ttl, id=ip_id)/req_tcp_layer/mydata

  pkts.append(req_pkt)

  sq=sq+len(mydata)
  st=st+sz
  ed=ed+sz
  mydata=req_data[st:ed]
  ip_id+=1

for x in [1,2,3,4,5,0,1,2,3,4,5]:
  print "sending pkt %d" % x
  send (pkts[x])


#resp = sr1(req_pkt, timeout = tout)

