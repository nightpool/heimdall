from netfilterqueue import NetfilterQueue
from scapy.all import *
import sys
import os

def print_and_accept(pkt):
    print "-----------------------NEW PACKET----------------------------"

    new_packet = IP(pkt.get_payload())

    print new_packet[IP].src
    print new_packet[IP].dst
    
    if new_packet[IP].dst == "10.4.2.3":
        # THIS SHOULD BE MOVED TO ANOTHER FUNCTION LATER
        options = {'iptables': '/sbin/iptables', 'srcAddress': '10.4.2.6'}
        print options
        rule = '{iptables} -I INPUT -s {srcAddress} -j NFQUEUE --queue-num 1'.format(**options)
        print rule
        iptables = subprocess.call(rule, shell=True)
        # END OF WHAT SHOULD BE MOVED   

        pkt.accept()
        print "Accepted the packet to 10.4.2.3, should be exiting"
        return

    #print new_packet[0].show()
    
    dns = new_packet['DNS']

    #set all of the dns answers to the given IP for the client
    for i in range(dns.ancount):
        dns.an[i].rdata = "10.4.2.4"

    #set all of the dns additional records to the given IP
    #(to ensure the server IP stays hidden)
    for i in range(dns.arcount):
        dns.ar[i].rdata = "10.4.2.4"

    # Scapy doesn't check the length and checksum by default when reforming
    # A packet.  Therefore, the length and checksum should be deleted and
    # recalcuated via the show 2 command.  Show 2 will always output to the
    # terminal, so disabling/enabling console writing before/after the show2
    # would be ideal.
    del new_packet[IP].len
    del new_packet[IP].chksum
    del new_packet[UDP].len
    del new_packet[UDP].chksum
    new_packet.show2()
    
    send(new_packet)
    
print "Starting the application..."
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
print "Bound to queue, preparing to run..."
if not os.getuid() == 0:
    print "ERRROR: This program must be run as root user to work."
iptables = subprocess.call('iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1', shell=True)
iptables = subprocess.call('iptables -I OUTPUT -p udp -j NFQUEUE --queue-num 1', shell=True)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')
iptables = subprocess.call('iptables -F', shell=True)
print "Done."
nfqueue.unbind()