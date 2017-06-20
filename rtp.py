#!/usr/bin/python

import threading
import argparse
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys
import os
import textwrap


class printScreen:
    def __init__(self):
        sz = os.get_terminal_size()
        self.lines = sz.lines
        sys.stdout.write("\x1b[s")  # save cursor location
        sys.stdout.write("\x1b[{};0H\x1b[K".format(self.lines-4))
        sys.stdout.write("\x1b[{};0H\x1b[K".format(self.lines-3))
        sys.stdout.write("\x1b[{};0H\x1b[K".format(self.lines-2))
        sys.stdout.write("\x1b[{};0H\x1b[K---------------------------------------".format(self.lines-1))
    def receiver(self, value):
        sys.stdout.write("\x1b[{};0H\x1b[KReceived: 00000  <---  {}".format(
            self.lines-3, value))
        sys.stdout.flush()
        pass
    def sender(self, value):
        sys.stdout.write("\x1b[{};0H\x1b[KSent:     00000  --->  {}".format(
            self.lines-2, value))
        sys.stdout.flush()
    def status(self, value):
        sys.stdout.write("\x1b[{};0H\x1b[K{}".format(
            self.lines, value))
        sys.stdout.flush()
        logging.info(value)
    def error(self, value):
        logging.error(value)
    def received(self, value):
        sys.stdout.write("\x1b[{};11H{:0>5}\x1b[u".format(
            self.lines-3, value))
        sys.stdout.flush()
    def sent(self, value):
        sys.stdout.write("\x1b[{};11H{:0>5}\x1b[u".format(
            self.lines-2, value))
        sys.stdout.flush()
    def restore(self):
        sys.stdout.write("\x1b[u")  # restore cursor position
        sys.stdout.flush()

PS = None


# -----------------------------------------------------------------------
#
#                                RtpListner
#
# -----------------------------------------------------------------------

class RtpListner(threading.Thread):
    def __init__(self, threadID, name, addr, srcip):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.addr = addr
        self.ctrlSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.count = 0
        self.saddr = srcip

    def run(self):
        PS.receiver("{}:{}".format(self.addr[0], self.addr[1]))
        fltr = "udp and dst port {dport} and ( src host {src} or src host 127.0.0.1)".format(
                src=self.saddr, 
                dport=self.addr[1])
        sniff(prn=self.onRTP, 
                stop_filter=lambda x:(UDP in x) and x[UDP].len<10, filter=fltr,
                store=0) 
        PS.status("Exiting " + self.name)

    def stop(self):
        self.ctrlSock.sendto(b"x", ("127.0.0.1", int(self.addr[1])))

    def onRTP(self, pkt):
        if (UDP in pkt and pkt[UDP].len == 260):
            self.count+=1
            PS.received(self.count)
        else:
            pass
            #print "Unknown RTP packet received:", pkt.summary()


# -----------------------------------------------------------------------
#
#                                RtpSender
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
        PS.sender("{}:{}".format(self.daddr[0], self.daddr[1]))
        pkts = rdpcap(self.pcap)
        n=0
        for pkt in pkts:
            send(IP(dst=self.daddr[0], src=self.saddr[0])/UDP(sport=
                self.saddr[1], dport=self.daddr[1])/pkt[Raw], verbose=0
                )
            n+=1
            PS.sent(n)
            time.sleep(0.03) # 30 ms
        PS.status("Exiting " + self.name)

    def stop(self):
        pass


# -----------------------------------------------------------------------
#
#                               Controller
#
# -----------------------------------------------------------------------

class ControllerThread (threading.Thread):
    def __init__(self, threadID, name, addr):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.server = ControlServer(addr)

    def run(self):
        self.server.listen()

    def stop(self):
        self.server.shutdown()


class ControlServer:
    def __init__(self, addr):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(addr)
        self.rtpListner=None


    def listen(self):
        self.s.listen(1)
        while 1:
            PS.status("Listning for Control connection ...")
            conn, addr = self.s.accept()
            PS.status("Accepted connection from {}".format(addr))
            while 1:
                byteData = conn.recv(1024)
                data = byteData.decode("utf-8")
                if data.find("start_listner") != -1:
                    PS.status("command: start_listner")
                    # first stop the existing rtp listner
                    self.stopListner()
                    pos = data.find("start_listner")
                    self.startListner(data[pos+14:].split(" ",3))

                elif data.find("start_sender") != -1:
                    PS.status("command: start_sender")
                    # first stop the existing rtp listner
                    self.stopSender()
                    pos = data.find("start_sender")
                    self.startSender(data[pos+13:].split(" ",4))

                elif data.find("stop_listner") != -1:
                    PS.status("command: stop_listner")
                    self.stopListner()

                elif data.find("stop_sender") != -1:
                    PS.status("command: stop_sender")
                    self.stopListner()

                else:
                    conn.close()
                    PS.status("Control connection closed");
                    break

    def startListner(self, args):
        if (len(args) < 3):
            PS.error("Bad start_listen command {}".format(args))
        else:
            PS.status("starting RTP Listner on {}:{} src: ".format(args[0], int(args[1]), args[2]))
            #PS.status("starting RTP Listner on {}:{} source {}".format(args[0], int(args[1]), args[2]))
            self.rtpListner = RtpListner(1, "rtp-listner", (args[0], int(args[1])), args[2])
            self.rtpListner.start()

    def stopListner(self):
        if (self.rtpListner):
            self.rtpListner.stop()
            self.rtpListner=None

    def startSender(self, args):
        if (len(args) < 3):
            PS.error("Bad start_sender command".format(args))
        else:
            PS.status("starting RTP sender {}:{} -> {}:{}".format (
                args[0], int(args[1]), args[2], int(args[3])))
            self.rtpSender = RtpSender(2, "rtp-sender", "g711a.pcap",
                    (args[0], int(args[1])), (args[2], int(args[3])))
            self.rtpSender.start()

    def stopSender(self):
        self.rtpSender=None
        pass


# -----------------------------------------------------------------------
#
#                                  main
#
# -----------------------------------------------------------------------

def main():
    # Options parser
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            usage="usage: %(prog)s <ip-address> <port>",
            description=textwrap.dedent('''\
                    This program listens for commands on the control socket.
                    example: rtp.py 127.0.0.1 9898
                    The commands are:
                    * start_listner <listen-ip> <listen-port> <remote-ip>
                    * stop_listenen
                    * start_sender <send-ip> <send-port> <remote-ip> <remote-port>
                    * stop_sender
                    In SIPP the commands can be sent as follows:
                    <exec command="echo start_listner [media_ip] 20000 [$ip] | nc localhost 9898"/>''')
            )

    parser.add_argument("ip", help="control socket ip address")
    parser.add_argument("port", type=int, help="control socket port")
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s:%(message)s',
        filemode='w',  
        filename="rtp.py.log",
        level=logging.DEBUG)

    global PS
    PS = printScreen()
    controlThrd = ControllerThread(1, "control-listner", (args.ip, args.port) )
    controlThrd.start()
    controlThrd.join()

    PS.restore()


if __name__ == "__main__":
    main()
