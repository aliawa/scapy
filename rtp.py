#!/usr/bin/python

import threading
import optparse
import SocketServer
import socket
from scapy.all import *

def myprn(n):
    sys.stdout.write("\x1b7\x1b[10C%d\x1b8" % (n))
    sys.stdout.flush()


# -----------------------------------------------------------------------
#
#                                rtpListner
#
# -----------------------------------------------------------------------


class rtpListner(threading.Thread):
    def __init__(self, threadID, name, addr):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.addr = addr
        self.ctrlSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.count = 0

    def run(self):
        print "Starting " + self.name
        fltr = "udp and dst port {port}".format(ip=self.addr[0], port=self.addr[1])
        pkts = sniff(prn=self.onRTP, 
                stop_filter=lambda x:x.haslayer(UDP) and x[UDP].len==0, filter=fltr) 
        print "Exiting " + self.name

    def stop(self):
        print "Stopping rtp listner on {ip}:{port}".format(ip=self.addr[0], port=self.addr[1])
        self.ctrlSock.sendto("", (self.addr[0], int(self.addr[1])))

    def onRTP(self, pkt):
        if (UDP in pkt and pkt[UDP].len == 260):
            self.count+=1
            sys.stdout.write("Received: {}\r".format(self.count))
            sys.stdout.flush()


# -----------------------------------------------------------------------
#
#                                rtpSender
#
# -----------------------------------------------------------------------


class RtpSender (threading.Thread):
    def __init__(self, threadID, name, pcap, saddr, daddr):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.saddr = saddr
        self.daddr = daddr
        self.pcap  = pcap
        self.count = 0

    def run(self):
        print "Starting " + self.name
        pkts = rdpcap(self.pcap)
        for pkt in pkts:
            pkt[IP].src = self.saddr[0]
            pkt[IP].dst = self.daddr[0]
            pkt[UDP].sport = self.saddr[1]
            pkt[UDP].dport = self.daddr[1]
            del(pkt[Ether].src)
            del(pkt[Ether].dst)
            send(pkt, verbose=0, realtime=True)
        print "Exiting " + self.name

    def stop(self):
        pass


# -----------------------------------------------------------------------
#
#                               Controller
#
# -----------------------------------------------------------------------

class controllerThread (threading.Thread):
    def __init__(self, threadID, name, addr):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.server = ControlServer(addr)

    def run(self):
        print "Starting " + self.name
        self.server.listen()
        print "Exiting " + self.name

    def stop(self):
        self.server.shutdown()


class ControlServer:
    def __init__(self, addr):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(addr)
        self.rtpListner=None


    def listen(self):
        print 'Opening Control socket'
        self.s.listen(1)
        while 1:
            conn, addr = self.s.accept()
            print 'Connection address:', addr
            while 1:
                data = conn.recv(1024)
                print "received data:", data
                if data.find("start_listner") != -1:
                    # first stop the existing rtp listner
                    self.stopListner()
                    pos = data.find("start_listner")
                    self.startListner(data[pos+14:].split(" ",2))

                elif data.find("start_sender") != -1:
                    # first stop the existing rtp listner
                    self.stopSender()
                    pos = data.find("start_sender")
                    self.startSender(data[pos+13:].split(" ",4))

                elif data.find("stop_listner") != -1:
                    self.stopListner()

                elif data.find("stop_sender") != -1:
                    self.stopListner()

                else:
                    print 'Closing control connection'
                    conn.close()
                    break

    def startListner(self, addr):
        print "starting rtp-listner on {}:{}".format(addr[0], addr[1])
        self.rtpListner = rtpListner(1, "rtp-listner", (addr[0], int(addr[1])))
        self.rtpListner.start()

    def stopListner(self):
        if (self.rtpListner):
            print "stoping rtp-listner"
            self.rtpListner.stop()

    def startSender(self, adr):
        print "starting rtp-sender {}:{} -> {}:{}".format(adr[0], adr[1], adr[2], adr[3])
        self.rtpSender = RtpSender(2, "rtp-sender", "g711a.pcap",
                (adr[0], int(adr[1])), (adr[2], int(adr[3])))
        self.rtpSender.start()

    def stopSender(self):
        pass


# -----------------------------------------------------------------------
#
#                                  main
#
# -----------------------------------------------------------------------

if __name__ == "__main__":
    # Options parser
    usage = "usage: %prog [options] ip-address port"
    parser = optparse.OptionParser(usage=usage);
    options, args = parser.parse_args()

    if len(args) !=2:
        parser.error("Incorrect number of arguments");

    controlThrd = controllerThread(1, "control-listner", (args[0], int(args[1])) )
    controlThrd.start()

    print "Exiting Main Thread"
