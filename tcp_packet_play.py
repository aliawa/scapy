 #!/usr/bin/python

import sys, getopt, random, os, logging, time, argparse
from scapy.all import *

gLogger = None


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
            log("received ack from destination", Log.INFO)
            state['ack_num'] = synack_req.seq +1 
        elif FL & TCPFLAGS.RST:
            log("received RST from destination", Log.INFO)
            return False
    else:
        log("did not receive ack from destination", Log.ERROR)
        return False



def doHandshakeClnt(state):
    syn = createPacket(state, "S")
    synack = sr1(syn)

    if (synack):
        FL = synack[TCP].flags 
        if FL & TCPFLAGS.SYN and FL & TCPFLAGS.ACK:
            log("received synack from destination", Log.INFO)
            state['ack_num'] = synack_req.seq +1 
        elif FL & TCPFLAGS.RST:
            log("received RST from destination", Log.INFO)
            return False
    else:
        log("did not receive synack from destination", Log.ERROR)
        return False


    ack = createPacket(state, "A")
    log("sending ack to destination", Log.INFO)
    send(ack)
    return True



def sendFin(state):
    finack_rec = sr1(createPacket(params, "FA"))
    if (finack_rec):
        log("received finack from destination", Log.INFO)
        state['ack_num'] = finack_req.seq +1 
    else:
        log("did not receive finack from destination", Log.ERROR)
        return False

    ack_pkt = createPacket(params, "A")
    log("sending ack to destination", Log.INFO)
    send(ack_pkt)
    return True


def sendData(state, order):
    pkts = []
    for f in files:
        mydata = open(f, 'r').read()
        s = Template(mydata).substitute(state)
        pkts.append(createPacket(state, "PA", mydata))

    for x in order:
        i = int(x)
        if i <= len(pkts):
            print ("sending pkt:", i)
            send (pkts[i-1])
        else:
            print ("ignoring pkt:", i)



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
            sendData(act['msg'], act['order'])
        elif (act['action'] == 'recv'):
            receive(act['msg'])
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

    if (not 'seq' in config):
        log(logging.ERROR, "Config file is empty, exiting")
        sys.exit()
    elif (len(config['seq']) == 0):
        log(logging.ERROR, "Scenario is missing in config file, exiting")
        sys.exit()


    run_scenrio(args, config['seq'])

if __name__ == "__main__":
    main()



