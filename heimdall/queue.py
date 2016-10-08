import random
import threading
import time

class Capability:
    def __init__(self, client_ip_addr,  expiration_time):
        self.client_ip_addr = client_ip_addr
	self.mapped_ip_addr = "127.0.0.1"
        self.exp_time = expiration_time

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
	#rule = ___
	#iptables = subprocess.call(rule, shell=True)

	print "A capability for", capability.client_ip_addr, "has been granted."

    def removeExpirations(self):
        current_time = time.time()
        for cap in self.capabilities:
            if cap.exp_time < current_time:
		#return the ip address back to the pool of available ones
		self.availableIPs.append(cap.mapped_ip_addr)
		self.inUseIPs.remove(cap.mapped_ip_addr)
		self.activeClients.remove(cap.client_ip_addr)

		#remove the iptables rules with this capability
		

                #finally remove the capability from the list
		print "A capability for", cap.client_ip_addr, "has expired."
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
'''
try:
    capQueue = CapabilityQueue()
    queueThread = threading.Thread(target=queueHandler, args=(capQueue,))
    queueThread.start()

    capQueue.addCapability(Capability("10.0.0.1", time.time() + 20))
    capQueue.addCapability(Capability("10.0.0.2", time.time() + 15))
    capQueue.addCapability(Capability("10.0.0.3", time.time() + 30))
    capQueue.addCapability(Capability("10.0.0.4", time.time() + 30))
    capQueue.addCapability(Capability("10.0.0.5", time.time() + 25))
    capQueue.addCapability(Capability("10.0.0.6", time.time() + 10))
    capQueue.addCapability(Capability("10.0.0.7", time.time() + 2))
    capQueue.addCapability(Capability("10.0.0.8", time.time() + 60))
    capQueue.addCapability(Capability("10.0.0.9", time.time() + 50))

except KeyboardInterrupt:
    capQueue.disable()
    queueThread.join()
'''