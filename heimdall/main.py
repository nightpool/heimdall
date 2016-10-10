import sys, random, os, threading, time

from netfilterqueue import NetfilterQueue
from scapy.all import *

from queue import Capability, CapabilityQueue, queueHandler
import policy

DENIED_CAP = "127.0.0.1"
def print_and_accept(pkt):
    new_packet = IP(pkt.get_payload())

    #packet is arriving as a DNS lookup, dont modify
    if new_packet[IP].dst == "10.4.2.3":
        pkt.accept()
        return

    try:
        dns = new_packet['DNS']
    except:
        pkt.accept()
        return

    if not dns.ancount:
        pkt.accept()
        return

    clientIP = new_packet[IP].dst
    serverName = dns.qd[0].qname
    serverName = serverName[0:len(serverName)-1]

    print "packet from {} for {}".format(clientIP, serverName)
    print "  an: {}, ar: {}".format(dns.ancount, dns.arcount)

    selected_policy = policy.matchPolicy(config, serverName, clientIP)

    grantCapability = True # TK rate limiter

    useStrict = selected_policy.get('strict', 'true') in ('1', 'true', 'True')
    override = selected_policy.get("always")

    if override == "deny":
        grantCapability = False
    if override == "allow":
        grantCapability = True

    print '  policy: {}'.format(selected_policy)

    #granting a capability to a new client
    if grantCapability:
        if not capabilityQueue.containsCapability(clientIP):
            newCapability = Capability(clientIP, useStrict, time.time() + int(selected_policy['TTL']) + 5)
            capabilityQueue.addCapability(newCapability)
            mappedIP = newCapability.mapped_ip_addr
        else:
            for cap in capabilityQueue.capabilities:
                if cap.client_ip_addr == clientIP:
                        mappedIP = cap.mapped_ip_addr
    else:
        mappedIP = DENIED_CAP

    #set all of the dns answers to the given IP for the client
    for i in range(dns.ancount):
        dns.an[i].rdata = mappedIP
        dns.an[i].ttl = int(selected_policy['TTL'])

    #set all of the dns additional records to the given IP
    #(to ensure the server IP stays hidden)
    for i in range(dns.arcount):
        dns.ar[i].rdata = mappedIP
        dns.ar[i].ttl = int(selected_policy['TTL'])

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

#setup some initial rules to interface with netfilter queue
subprocess.call('iptables -F', shell=True)
subprocess.call('iptables -t nat -F', shell=True)
subprocess.call('iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1', shell=True)
subprocess.call('iptables -I OUTPUT -p udp -j NFQUEUE --queue-num 1', shell=True)
subprocess.call('iptables -t nat -A POSTROUTING -j MASQUERADE', shell=True)

#setup capability queue
capabilityQueue = CapabilityQueue()
queueThread = threading.Thread(target=queueHandler, args=(capabilityQueue,))
queueThread.start()

config = policy.getPolicy("policy.toml")

## setup a policy reading thread
## to re-read the policy file every 60s
# def readPolicyThread(config):
#     while(True):
#         print "Reading Policy File"
#         config = policy.getPolicy("policy.toml")
#         time.sleep(60)
# policyThread = threading.Thread(target=readPolicyThread, args=(config,))
# policyThread.start()

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

subprocess.call('iptables -F', shell=True)
subprocess.call('iptables -t nat -F', shell=True)
print "Done."
nfqueue.unbind()
queueThread.join()
