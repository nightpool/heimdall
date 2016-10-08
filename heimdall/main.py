from contextlib import contextmanager
from netfilterqueue import NetfilterQueue
from scapy.all import *
from queue import Capability, CapabilityQueue, queueHandler
import random
import sys
import os
import threading
import time

def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def print_and_accept(pkt):
    #print "-----------------------NEW PACKET----------------------------"

    new_packet = IP(pkt.get_payload())

    #print new_packet[IP].src
    #print new_packet[IP].dst
    
    #print "Received a packet destined for", new_packet[IP].dst

    #packet is arriving as a DNS lookup
    if new_packet[IP].dst == "10.4.2.3":
        # THIS SHOULD BE MOVED TO ANOTHER FUNCTION LATER
        #options = {'iptables': '/sbin/iptables', 'srcAddress': '10.4.2.6'}
        #print options
        #rule = '{iptables} -I INPUT -s {srcAddress} -j NFQUEUE --queue-num 1'.format(**options)
        #print rule
        #iptables = subprocess.call(rule, shell=True)
        # END OF WHAT SHOULD BE MOVED   

        pkt.accept()
        #print "Accepted the packet to 10.4.2.3, should be exiting"
        return



    clientIP = new_packet[IP].dst

    #granting a capability to a new client
    if(not(capabilityQueue.containsCapability(clientIP))):
        newCapability = Capability(clientIP, time.time() + 30)
        capabilityQueue.addCapability(newCapability)
        mappedIP = newCapability.mapped_ip_addr

    #this client already has a capability; retrieve its mapped ip address
    else:
        for cap in capabilityQueue.capabilities:
            if cap.client_ip_addr == clientIP:
                mappedIP = cap.mapped_ip_addr

    

    #otherwise, its an outgoing DNS Response packet.
    dns = new_packet['DNS']

    #set all of the dns answers to the given IP for the client
    for i in range(dns.ancount):
        dns.an[i].rdata = mappedIP #"10.4.2.4"

    #set all of the dns additional records to the given IP
    #(to ensure the server IP stays hidden)
    for i in range(dns.arcount):
        dns.ar[i].rdata = mappedIP #"10.4.2.4"

    # Scapy doesn't check the length and checksum by default when reforming
    # A packet.  Therefore, the length and checksum should be deleted and
    # recalcuated via the show 2 command.  Show 2 will always output to the
    # terminal, so disabling/enabling console writing before/after the show2
    # would be ideal.
    del new_packet[IP].len
    del new_packet[IP].chksum
    del new_packet[UDP].len
    del new_packet[UDP].chksum
#    with suppress_stdout():
    new_packet.show2()
    
    send(new_packet)
    

#---------#Main execution path--------------------
print "Starting the application..."

#setup packet interception from NFQ
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
print "Bound to queue, preparing to run..."
if not os.getuid() == 0:
    print "ERRROR: This program must be run as root user to work."
#iptables = subprocess.call('iptables -t nat -F', shell=True)
#iptables = subprocess.call('iptables -F', shell=True)
iptables = subprocess.call('iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1', shell=True)
iptables = subprocess.call('iptables -I OUTPUT -p udp -j NFQUEUE --queue-num 1', shell=True)
iptables = subprocess.call('iptables -t nat -A POSTROUTING -j MASQUERADE', shell=True)
#setup capability queue
capabilityQueue = CapabilityQueue()
queueThread = threading.Thread(target=queueHandler, args=(capabilityQueue,))
queueThread.start()

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')
iptables = subprocess.call('iptables -F', shell=True)
print "Done."
nfqueue.unbind()