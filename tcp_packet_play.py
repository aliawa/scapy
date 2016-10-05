 #!/usr/bin/python

import sys, getopt, random, os, logging, time, argparse
from scapy.all import *

# ---------------------------------------------------------------------------
#                               Helpers
# ---------------------------------------------------------------------------

gLogger = None

class DataRceiver:
    def __init__(self, files):
    pkts = []
    for f in files:
        try:
            mydata = open(f, 'r').read()
            s = Template(mydata).substitute(state)
            pkts.append(s)
        except FileNotFoundError:
            log(logging.ERROR, "File %s not found", f)

    self.data = ''.join(pkts)

    def recive(data):
        if (self.data.startswith(data)):
            self.data = self.data[len(data):]
        if (len(self.data) == 0 ):
            return True
        return False

# ---------------------------------------------------------------------------
#                               TCP Protocol
# ---------------------------------------------------------------------------


class TCPFLAGS:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80



def initState(args, state):
    if args.seqnum:
        state['seq_num'] = args.seqnum
    else:
        state['seq_num'] = random.randint(1, 65534)
    state['ip_id']   = 1
    state['ack_num'] = 0
    state['srcmac']  = args.srcmac
    state['destmac'] = args.dstmac
    state['srcip']   = args.srcip
    state['dstip']   = args.dstip
    state['sport']   = args.sport
    state['dport']   = args.dport
    state['ttl']     = 100
    state['replace'] = args.replace


def createPacket(state, flgs, data=None):
    eth_layer = None
    if state['srcmac'] and state['destmac']:
        eth_layer = Ether(src = state['srcmac'], dst = state['destmac'])

    ip_layer = IP(src = state['srcip'], dst = state['dstip'], ttl = state['ttl'],
            id = state['ip_id'])

    tcp_layer  = TCP(sport = state['sport'], dport = state['dport'], flags = flgs, 
            seq = state['seq_num'], ack=state['ack_num'])
            
    state['ip_id']+=1
    if eth_layer:
        pkt = eth_layer/ip_layer/tcp_layer
    else:
        pkt = ip_layer/tcp_layer

    if data:
        state['seq_num']+=len(data)
        return pkt/data
    elif flgs.find('S') != -1 or flgs.find('F') != -1: 
        state['seq_num']+=1

    return pkt



def doHandshakeSrvr(state):
    fltr= "dst host {} and dst port {} and tcp[13]=2".format(
            state['sport'], state['srcip'])
    pkts = sniff(filter=fltr, count=1);
    state['ack_num'] = pkts[0].seq +1 

    synack = createPacket(state, "SA")
    ack = sr1(synack)
    if (ack):
        if ack[TCP].flags & TCPFLAGS_ACK:
            log(logging.INFO, "received ack from destination")
            state['ack_num'] = synack_req.seq +1 
        elif FL & TCPFLAGS.RST:
            log(logging.INFO, "received RST from destination")
            return False
    else:
        log(logging.INFO, "did not receive ack from destination")
        return False


def doHandshakeClnt(state):
    syn = createPacket(state, "S")
    synack = sr1(syn)

    if (synack):
        FL = synack[TCP].flags 
        if FL & TCPFLAGS.SYN and FL & TCPFLAGS.ACK:
            log(logging.INFO, "received synack from destination")
            state['ack_num'] = synack.seq +1 
        elif FL & TCPFLAGS.RST:
            log(logging.INFO, "received RST from destination")
            return False
    else:
        log(logging.ERROR, "did not receive synack from destination")
        return False


    ack = createPacket(state, "A")
    log(logging.INFO, "sending ack to destination")
    send(ack)
    return True



def sendFin(state):
    finack_rec = sr1(createPacket(params, "FA"))
    if (finack_rec):
        log(logging.INFO, "received finack from destination")
        state['ack_num'] = finack_req.seq +1 
    else:
        log(logging.INFO, "did not receive finack from destination")
        return False

    ack_pkt = createPacket(params, "A")
    log(logging.INFO, "sending ack to destination")
    send(ack_pkt)
    return True


def sip_preprocess(state, segs)
    # Assemble the message
    sipMsg = ''.join(segs)

    # Do replacements
    for (key, value in state['replace']):
        if (value[0] == '$'):
            value = state[value[1:]]
        sipMsg.replace(key, value)

    # Modify content-length header
    cstart = sipMsg.find('\r\n\r\n')
    len=0
    if (cstart != -1):
        len = len(sipMsg) - cstart - 4
    re.sub('(content-length *:) *(\d+)', r'\1 {}'.format(len), s, flags=re.IGNORECASE)

    # Create new segments
    i = 0
    pos = 0
    for s in segs:
        if (pos < len(sipMsg)): 
            segs[i] = (sipMsg[i:len(s)])
            pos+=len(s)
        else:
            del segs[i]
        i+=1
    if (pos < len(sipMsg)):
        segs.append(sipMsg[pos:])


def sendData(state, files, order):
    segs = []
    for f in files:
        try:
            mydata = open(f, 'r').read()
            segs.append(s)
        except FileNotFoundError:
            log(logging.ERROR, "File %s not found", f)

    sip_preprocess(segs, state.replacements)
    pkts = [createPacket(state, "PA", s) for s in segs]

    for x in order:
        i = int(x)
        if i <= len(pkts):
            print ("sending pkt:", i)
            send (pkts[i-1])
        else:
            print ("ignoring pkt:", i)



def recvData(state, files, order):
    fltr = "tcp and dst port {} and dst host {} and src host {}".format(
            state['sport'], state['srcip'], state['dstip'])
    rcvr = DataRceiver(files)
    sniff(store=0, stop_filter=rcvr.receive, timeout=60)
    if (not rcvr.isDone()):
        raise AssertionError("Data not received")




# ---------------------------------------------------------------------------
#                                  Framework
# ---------------------------------------------------------------------------

def log(*args):
    if (gLogger):
        gLogger.log(*args)


def run_scenrio(args, scenario):
    state = {}
    initState(args, state)

    if (scenario[0]['action']=='recv'):
        doHandshakeSrvr(state)
    elif(scenario[0]['action']=='send'):
        doHandshakeClnt(state)
    else:
        log(logging.ERROR, "Unknown action in scenario: %s, exiting", scenario[0]['action'])
        sys.exit()

    for act in scenario:
        if (act['action'] == 'send'):
            sendData(state, act['msg'], act['order'])
        elif (act['action'] == 'recv'):
            recvData(state, act['msg'], arc['order'])
        else:
            log(logging.ERROR, "Unknown action in scenario: %s", act['action'])

# Iptables configuration (Drop outgoing RST)
def setIpTableRule(params):
    iptables_flush_cmd = 'iptables -F'
    iptables_cmd = 'iptables -A OUTPUT -p tcp -d {} --tcp-flags RST  RST --destination-port {} -j DROP'.format(
            params.destip, params.dport)
    os.system(iptables_flush_cmd)
    os.system(iptables_cmd)



# ---------------------------------------------------------------------------
#                                   Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Send Receive Segmented TCP")
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument('-i', '--setipt', action='store_true', help='set iptables to reject RST packets from src host')
    parser.add_argument('-s', '--srcip', required=True, help='source ip address')
    parser.add_argument('-d', '--dstip', help='destination ip address')
    parser.add_argument('-r', '--sport' , type=int, required=True, help='source port') 
    parser.add_argument('-p', '--dport',  type=int, help='destination port')
    parser.add_argument('-1', '--srcmac', help='source mac address')
    parser.add_argument('-2', '--dstmac', help='destination mac address')
    parser.add_argument('--seqnum',       help='initial sequence number')
    parser.add_argument('-sn', '--scenario', required=True, help='scenario file')

    args=parser.parse_args()

    if (args.verbose):
        global gLogger
        gLogger = logging.getLogger('tcp_packet_sender')
        gLogger.setLevel(logging.DEBUG)
        gLogger.addHandler(logging.FileHandler('tcp_packet_sender.log', mode='w'))
    

    config = {}
    exec(open(args.scenario).read(), config)

    if ('seq' not in config):
        log(logging.ERROR, "Config file is empty, exiting")
        sys.exit()
    elif (len(config['seq']) == 0):
        log(logging.ERROR, "Scenario is missing in config file, exiting")
        sys.exit()


    run_scenrio(args, config['seq'])

if __name__ == "__main__":
    main()



