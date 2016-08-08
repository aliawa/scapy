 #!/usr/bin/python

import sys, getopt, random, os, logging, time
from scapy.all import *

setipt  = None
verbose = None 
ts      = None

class Log:
    INFO  = "INFO:"
    ERROR = "ERROR:"


def log(message, mt):
    if (verbose == 1):
        if ts:
            from time import gmtime, strftime
            tvalue = strftime("%a, %d %b %Y %H:%M:%S ", gmtime())
            print str(tvalue) + "%6s %s" % (mt, message)
        else:
            print "%6s %s" % (mt, message)


class TCPFLAGS:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

# Usage
def usage():
    print "Send data over TCP"
    print "Required Parameters"
    print "    -s, --src-ip      source IP"
    print "    -d, --dest-ip     proxy IP"
    print "    -p, --dport       destination port"
    print 
    print "Optional Parameters"
    print "    -h, --help        Show help"
    print "    -r, --sport       source port"
    print "    -1, --src-mac     source MAC Address"
    print "    -2, --dest-mac    destination MAC Address"
    print "    -t, --timeout     timeout in seconds"
    print "    -l, --ttl         IP time-to-live value for packets"
    print "    -q, --seqnum      set sequence number of initial TCP packet"
    print "    -v, --verbose     show verbose output"
    print "    -m, --timestring  print timestamp in log messages"
    print "    -i, --setipt      set iptables to reject RST packets from src host"


# scapy configuration
def scapy_conf():
    # Don't throw warnings
    logging.getLogger("scapy.runtime").setLevel(logging.INFO)
    # Don't output Sending packet .. type of messages from scapy
    conf.verb = 0


class tcp_state:
    def __init__(self, params):
        if params.seqnum:
            self.seq_num = param.seqnum
        else:
            self.seq_num = random.randint(1, 65534)
        self.ip_id=1
        self.ack_num = 0

    def createPacket(self, params, flgs, data=None):
        eth_layer = None
        if params.srcmac and params.destmac:
            eth_layer = Ether(src = params.srcmac, dst = params.destmac)

        ip_layer = IP(src = params.srcip, dst = params.destip, ttl = params.ttl,
                id = self.ip_id)

        tcp_layer  = TCP(sport = params.sport, dport = params.dport, flags = flgs, 
                seq = self.seq_num, ack=self.ack_num)
        self.ip_id+=1
        if eth_layer:
            pkt = eth_layer/ip_layer/tcp_layer
        else:
            pkt = ip_layer/tcp_layer

        if data:
            self.seq_num+=len(data)
            return pkt/data
        elif flgs.find('S') != -1 or flgs.find('F') != -1: 
            self.seq_num+=1

        return pkt

    def onRcv(self, count):
        self.ack_num = count
        self.ack_num +=1




class tcp_param:
    def __init__(self):
        self.srcip = None
        self.destip = None
        self.ttl=0
        self.dport = 0
        self.sport = random.randint(1024, 65534)
        self.srcmac = None
        self.destmac = None
        self.ttl = 64
        self.seqnum = 0

    def verify(self):
        if not self.destip:
            log("Please enter Destination IP Address", Log.ERROR)
            return False

        if not self.srcip:
            log("Please enter Source IP Address", Log.ERROR)
            return False

        if not self.dport:
            log("Please enter destination port number", Log.ERROR)
            return False
        return True


    def readOpts(self):
        try:
            opts, args = getopt.getopt(sys.argv[1:], "hvmis:d:p:r:1:2:t:l:q:", 
                ["help", "verbose", "timestring", "setipt=", 
                 "src-ip=", "dest-ip=", "sport=", "dport=", "src-mac=", "dest-mac=", 
                 "timeout=", "ttl=", "seqnum="])
        except getopt.GetoptError, err:
            print str(err)
            usage()
            sys.exit(-1)

        for o, a in opts:
                if o in ("-h", "--help"):
                    usage()
                    sys.exit(0)
                elif o in ("-v", "--verbose"):
                    global verbose    
                    verbose = 1
                elif o in ("-m", "--timestring"):
                    global ts
                    ts = 1
                elif o in ("-i", "--setipt"):
                    global setipt
                    setipt = 1
                elif o in ("-s", "--src-ip"):
                    self.srcip = a
                elif o in ("-d", "--dest-ip"):
                    self.destip = a
                elif o in ("-r", "--sport"):
                    self.sport = int(a)
                elif o in ("-p", "--dport"):
                    self.dport = int(a)
                elif o in ("-1", "--src-mac"):
                    self.srcmac = a
                elif o in ("-2", "--dest-mac"):
                    self.destmac = a
                elif o in ("-l", "--ttl"):
                    self.ttl = int(a)
                elif o in ("-q", "--seqnum"):
                    self.seqnum = a
                else:
                    print "Unknown option, see usage below\n"
                    usage()
                    sys.exit(-1)

        if not self.verify():
            usage()
            sys.exit(-1)




# Iptables configuration (Drop outgoing RST)
def setIpTableRule():
    iptables_flush_cmd = 'iptables -F'
    iptables_cmd = 'iptables -A OUTPUT -p tcp -d ' + destip + ' --tcp-flags RST  RST --destination-port ' + str(dport) + ' -j DROP'
    os.system(iptables_flush_cmd)
    os.system(iptables_cmd)



# TCP 3 way handshake
def doHandShake(params, state):
    init_pkt = state.createPacket(params, "S")
    synack_rec = sr1(init_pkt)

    if (synack_rec):
        FL = synack_rec[TCP].flags 
        if FL & TCPFLAGS.SYN and FL & TCPFLAGS.ACK:
            log("received synack from destination", Log.INFO)
            state.onRcv(synack_rec.seq )
        elif FL & TCPFLAGS.RST:
            log("received RST from destination", Log.INFO)
            return False
    else:
        log("did not receive synack from destination", Log.ERROR)
        return False


    ack_pkt = state.createPacket(params, "A")
    log("sending ack to destination", Log.INFO)
    send(ack_pkt)
    return True



def sendFin(params, state):
    finack_rec = sr1(state.createPacket(params, "FA"))
    if (finack_rec):
        log("received finack from destination", Log.INFO)
        state.onRcv(finack_rec.seq )
    else:
        log("did not receive finack from destination", Log.ERROR)
        return False

    ack_pkt = state.createPacket(params, "A")
    log("sending ack to destination", Log.INFO)
    send(ack_pkt)
    return True


def sendData(params, state):
    pkts=[]
    for x in [1,2,3,4,5]:
        mydata = open("reg_part" + str(x) + ".bin", 'r').read()
        mydata = mydata.replace('[$src-ip]', params.srcip)
        mydata = mydata.replace('[$dst-ip]', params.destip)
        pkts.append(state.createPacket(params, "PA", mydata))


    for x in [1,4,5,2,3]:
      print "sending pkt:", x
      send (pkts[x-1])




def main():
    scapy_conf()

    params = tcp_param()
    params.readOpts()

    state = tcp_state(params)

    if setipt:
        setIpTableRule()

    if not doHandShake(params,state):
        log ("TCP Handshake failed", Log.ERROR)
        sys.exit(-1)

    sendData(params, state)
    sendFin(params, state)



if __name__ == "__main__":
    main()



