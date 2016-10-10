import os
import random
import sys
import threading
import time
import subprocess

class Capability:
    def __init__(self, client_ip_addr, useStrict, expiration_time):
        self.client_ip_addr = client_ip_addr
        self.mapped_ip_addr = "127.0.0.1"
        self.exp_time = expiration_time
        self.useStrict = useStrict

    def setMappedIP(self, mappedIP):
        self.mapped_ip_addr = mappedIP

    def printCapability(self):
        print "Client IP:\t", self.client_ip_addr, "Mapped IP:\t", self.mapped_ip_addr, "TTL:\t", self.exp_time

class CapabilityQueue:
    def __init__(self):
        self.capabilities = []
        self.availableIPs = []
        self.inUseIPs = []
        self.activeClients = []
        self.active = True

        for x in range(128, 256):
            self.availableIPs.append("10.4.2." + str(x))

    def addCapability(self, capability):
        #add the capability to the queue
        self.capabilities.append(capability)
        self.capabilities.sort(key=lambda x: x.exp_time)

        #map the capability 
        mappedIP = random.choice(self.availableIPs)
        capability.setMappedIP(mappedIP)
        self.availableIPs.remove(mappedIP)
        self.inUseIPs.append(mappedIP)
        self.activeClients.append(capability.client_ip_addr)

        #add iptables rules for this capability
        options = {'iptables': '/sbin/iptables', 'clientAddress': capability.client_ip_addr, 'mappedAddress': capability.mapped_ip_addr}
        if(capability.useStrict):
            rule = "{iptables} -t nat -A PREROUTING -p tcp -s {clientAddress} -d {mappedAddress} --dport 80 -j DNAT --to-destination 10.4.2.4:80".format(**options)
        else:
            rule = "{iptables} -t nat -A PREROUTING -p tcp -d {mappedAddress} --dport 80 -j DNAT --to-destination 10.4.2.4:80".format(**options)
        iptables = subprocess.call(rule, shell=True)

        print "A capability for", capability.client_ip_addr, "has been granted on IP Address", capability.mapped_ip_addr, "at time", round(time.time(),2)

    def removeExpirations(self):
        current_time = time.time()
        for cap in self.capabilities:
            if cap.exp_time < current_time:
                #return the ip address back to the pool of available ones
                self.availableIPs.append(cap.mapped_ip_addr)
                self.inUseIPs.remove(cap.mapped_ip_addr)
                self.activeClients.remove(cap.client_ip_addr)

                #remove the iptables rules with this capability
                options = {'iptables': '/sbin/iptables', 'clientAddress': cap.client_ip_addr, 'mappedAddress': cap.mapped_ip_addr}
                if(cap.useStrict):
		    rule = "{iptables} -t nat -D PREROUTING -p tcp -s {clientAddress} -d {mappedAddress} --dport 80 -j DNAT --to-destination 10.4.2.4:80".format(**options)        
		else:
		    rule = "{iptables} -t nat -D PREROUTING -p tcp -d {mappedAddress} --dport 80 -j DNAT --to-destination 10.4.2.4:80".format(**options)        
                iptables = subprocess.call(rule, shell=True)
                #finally remove the capability from the list
                print "A capability for", cap.client_ip_addr, "has expired at time", round(time.time(),2)
                self.capabilities.remove(cap)
                
    def containsCapability(self, ip_addr):
        for cap in self.capabilities:
            if cap.client_ip_addr == ip_addr:
                return True
        return False

    def isActive(self):
        return self.active

    def disable(self):
        self.active = False

    def isEmpty(self):
        return len(self.capabilities) == 0

    def printQueue(self):
        print "-----------------------------------------"
        print "Current Time:", time.time()
        for cap in self.capabilities:
            print "IP Address:", cap.ip_addr, " Expiration Time:", cap.exp_time
        print "-----------------------------------------"

def queueHandler(queue):
    print "Queue Handler initialized successfully, running queue..."
    while queue.isActive():
        #if not queue.isEmpty():
        #    queue.printQueue()
        queue.removeExpirations()
        time.sleep(.5)
