from contextlib import contextmanager
from netfilterqueue import NetfilterQueue
from scapy.all import *
from queue import Capability, CapabilityQueue, queueHandler
import random
import sys
import os
import threading
import time

def print_and_accept(pkt):

    new_packet = IP(pkt.get_payload())

    #packet is arriving as a DNS lookup, dont modify
    if new_packet[IP].dst == "10.4.2.3":
        pkt.accept()
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
    # recalcuated
    del new_packet.len
    del new_packet.chksum
    del new_packet[IP].len
    del new_packet[IP].chksum
    del new_packet[UDP].len
    del new_packet[UDP].chksum

    new_packet = new_packet.__class__(str(new_packet))
    
    send(new_packet,verbose=0)

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