 #!/usr/bin/python
 

import sys, random, os, logging, time, argparse
import xml.etree.ElementTree as ET
from string import Template
from scapy.all import *
from random import randint
import string

# ---------------------------------------------------------------------------
#                               Helpers
# ---------------------------------------------------------------------------


class DataRceiver:
    # States:
    # 0: message not complete
    # 2: headers are complete. waiting for content
    def __init__(self, config, state):
        self.tcp_state = state
        self.sipMsg    = ''
        self.len       = 0
        self.regex     = re.compile('content-length *: *(\d+)', flags=re.IGNORECASE)
        self.cfg       = config
        self.sip_state = 0
        self.setState(0)

    def receive(self, pkt):
        if (Raw not in pkt):
            return False
        if (TCP in pkt and pkt[TCP].sport == self.tcp_state['dport']):
            self.tcp_state['ack_num'] = pkt.seq + len(pkt[Raw].load)
            send(createPacket(self.tcp_state, "A"))
        else:
            return False

        self.sipMsg = "{}{}".format(self.sipMsg, pkt[Raw].load)
        if (self.sip_state == 0):
            pos = self.sipMsg.find('\r\n\r\n')
            if (pos != -1):
                m = self.regex.search(self.sipMsg)
                if m:
                    self.len = pos + 4 + int(m.group(1))
                    if (len(self.sipMsg) >= self.len):
                        self.onComplete()
                        return True
                    else:
                        self.setState(2)
                else:
                    self.len = pos + 4
                    self.onComplete()
                    return True
        elif (self.sip_state == 2):
            if (len(self.sipMsg) > self.len):
                self.onComplete()
                return True
        return False

    def onComplete(self):
        msg = self.sipMsg[:self.len]
        log(logging.INFO, "received:\n-----------------\n%s", msg)

        if (not msg.startswith("SIP/2.0")):
            for l in msg.splitlines():
                updateConfig(self.cfg, l.partition(':'))

        self.sipMsg = self.sipMsg[self.len:]
        self.setState(3)
        self.len    = 0
    
    def isDone(self):
        return self.sip_state == 3

    def setState(self, st):
        log(logging.DEBUG, "receiver state: {}->{}". format(self.sip_state, st))
        self.sip_state = st


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


def initState(args):
    state = {}
    if args.seqnum:
        state['seq_num'] = args.seqnum
    else:
        state['seq_num'] = random.randint(1, 65534)

    state['srcmac']     = args.srcmac
    state['destmac']    = args.dstmac
    state['ip_id']      = 1
    state['ack_num']    = 0
    state['ttl']        = 100
    state['remote_seq'] = 0
    state['srcip']      = args.srcip
    state['dstip']      = args.dstip
    state['sport']      = args.sport
    state['dport']      = args.dport
    return state


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



def doHandshakeSrvr(config, state):
    fltr= "tcp[13] = 0x02 and dst host {} and tcp dst port {}".format(state['srcip'], state['sport'] )
    pkts = sniff(filter=fltr, count=1)
    state['dport'] = pkts[0][TCP].sport
    state['dstip'] = pkts[0][IP].src
    state['ack_num'] = pkts[0].seq +1
    synack = createPacket(state, "SA")
    ack = sr1(synack)
    if (ack):
        if ack[TCP].flags & TCPFLAGS.ACK:
            log(logging.INFO, "received ack from destination")
            return True
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
    finack_rec = sr1(createPacket(state, "FA"))
    if (finack_rec):
        log(logging.INFO, "received finack from destination")
        state['ack_num'] = finack_req.seq +1 
    else:
        log(logging.INFO, "did not receive finack from destination")
        return False

    ack_pkt = createPacket(state, "A")
    log(logging.INFO, "sending ack to destination")
    send(ack_pkt)
    return True


def sip_preprocess(config, msg):
    sipTemplate = Template(msg)
    sipMsg = sipTemplate.substitute(config).strip()
    lines = [ln.strip() for ln in sipMsg.splitlines()]
    sipMsg = "{}\r\n".format("\r\n".join(lines))

    # Modify content-length header
    cstart = sipMsg.find('\r\n\r\n')
    mlen=0
    if (cstart != -1):
        mlen = len(sipMsg) - cstart - 4
    sipMsg = sipMsg.replace("X#X#X", "{}".format(mlen))
    if not mlen:
        sipMsg = "{}\r\n".format(sipMsg)

    return sipMsg



def sendData(config, state, act):

    msg = sip_preprocess(config, act['msg'])

    # create segments
    pkts=[]

    # segmentation policy
    if 'segs' in act:
        pos=0
        for size in act['segs']:
            pkts.append(createPacket(state, "PA", msg[pos:pos+int(size)] ))
            pos += int(size)
        if (len (msg[pos:])):
            pkts.append(createPacket(state, "PA", msg[pos:] ))
    elif 'seg_size' in act:
        size = act['seg_size']
        for pos in range(0,len(msg),size):
            pkts.append(createPacket(state, "PA", msg[pos:pos+size] ))
    else:
        pkts.append(createPacket(state, "PA", msg ))

    # send segments
    for x in act['order']:
        i = int(x)
        if i <= len(pkts):
            print ("sending pkt:{}".format(i))
            send (pkts[i-1])
            pkts[i-1][IP].ttl = 0 #mark as sent
        else:
            print ("ignoring pkt:{}".format(i))

    # send remaining packets
    for  x in pkts:
        if x[IP].ttl:
            send (x)


def recvData(config, state, act):
    fltr = "tcp and dst port {} and dst host {} and src host {}".format(
            state['sport'], state['srcip'], state['dstip'])
    rcvr = DataRceiver(config, state)
    sniff(store=0, stop_filter=rcvr.receive, filter=fltr, timeout=60)
    if (not rcvr.isDone()):
        raise AssertionError("Data not received")




# ---------------------------------------------------------------------------
#                                  Framework
# ---------------------------------------------------------------------------

gLogger = None
def log(*args):
    if (gLogger):
        gLogger.log(*args)


def run_scenrio(config, state, scenario):
    if (scenario[0]['action']=='recv'):
        if doHandshakeSrvr(config, state):
            config['remote_port'] = state['dport']
            config['remote_ip']   = state['dstip']
        else:
            log(logging.ERROR, "Server Handshake failed")
            sys.exit()

    elif(scenario[0]['action']=='send'):
        if not doHandshakeClnt(state):
            log(logging.ERROR, "Client Handshake failed")
            sys.exit()
    else:
        log(logging.ERROR, "Unknown action in scenario: %s, exiting", scenario[0]['action'])
        sys.exit()
    
    print ("Handshake done: {}:{}".format(config['remote_ip'], config['remote_port']))

    for act in scenario:
        if (act['action'] == 'send'):
            print ("send action")
            sendData(config, state, act)
        elif (act['action'] == 'recv'):
            print ("receive action")
            recvData(config, state, act)
        else:
            log(logging.ERROR, "Unknown action in scenario: %s", act['action'])


# Iptables configuration (Drop outgoing RST)
def setIpTableRule(params):
    iptables_flush_cmd = 'iptables -F'
    iptables_cmd = 'iptables -A OUTPUT -p tcp -d {} --tcp-flags RST  RST --destination-port {} -j DROP'.format(
            params.dstip, params.dport)
    os.system(iptables_flush_cmd)
    os.system(iptables_cmd)


def updateConfig(config, hdr):
    hdrs = {
        'via'    : 'last_Via',
        'to'     : 'last_To',
        'from'   : 'last_From',
        'call-id': 'last_Call_ID',
        'contact': 'last_Contact',
        'cseq'   : 'last_CSeq'
        }
    if hdr[0].lower() in hdrs:
        config[hdrs[hdr[0].lower()]]= "{}:{}".format(hdr[0],hdr[2])


def initConfig(args):
    config = {}
    config['local_ip']    = args.srcip
    config['remote_ip']   = args.dstip
    config['local_port']  = args.sport
    config['remote_port'] = args.dport
    config['branch']      = "z9hG4bKbe".format(randint(1000,9999))
    config['transport']   = 'TCP'
    config['call_id']     = '5a2fb8b1-3c6d8673@{}'.format(randint(1111,7070707))
    config['media_ip']    = args.srcip
    config['media_port']  = randint(6000,65000)
    config['pid']         = os.getpid()
    config['len']         = 'X#X#X'
    return config


def initLogging(args):
    if (args.verbose):
        global gLogger
        gLogger = logging.getLogger('tcp_packet_sender')
        gLogger.setLevel(logging.DEBUG)
        gLogger.addHandler(logging.FileHandler('send.log', mode='w'))


def loadScenario(scen):
    root = ET.parse(scen).getroot()
    scenario = []
    for child in root:
        act={}
        act['action'] = child.tag
        act['msg'] = child.text
        if 'seg_size' in child.attrib:
            act['seg_size'] = int(child.attrib['seg_size'])
        elif 'segs' in child.attrib:
            act['segs'] = child.attrib['segs'].split(',')
        act['order'] = child.attrib.get('order', '1').split(',')
        scenario.append(act)
    return scenario
    
def scapy_conf():
    # Don't throw warnings
    logging.getLogger("scapy.runtime").setLevel(logging.INFO)
    # Don't output Sending packet .. type of messages from scapy
    conf.verb = 0

# ---------------------------------------------------------------------------
#                                   Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Send Receive Segmented TCP")
    parser.add_argument("-v", "--verbose", action='store_true')
    parser.add_argument('-i', '--setipt', action='store_true', help='set iptables to reject RST packets from src host')
    parser.add_argument('-s', '--srcip', required=True, help='source ip address')
    parser.add_argument('-d', '--dstip', help='destination ip address')
    parser.add_argument('-r', '--sport' , type=int, default=randint(1025,65500), help='source port') 
    parser.add_argument('-p', '--dport',  type=int, help='destination port')
    parser.add_argument('-1', '--srcmac', help='source mac address')
    parser.add_argument('-2', '--dstmac', help='destination mac address')
    parser.add_argument('--seqnum',       help='initial sequence number')
    parser.add_argument('-sn', '--scenario', required=True, help='scenario file')

    args=parser.parse_args()

    if args.setipt:
        setIpTableRule(args)
        return

    scapy_conf()
    initLogging(args)
    scenario = loadScenario(args.scenario)
    config   = initConfig(args)
    state    = initState(args)

    run_scenrio(config, state, scenario)

if __name__ == "__main__":
    main()



