import threading
import time

class Capability:
    def __init__(self, ip_addr, expiration_time):
        self.ip_addr = ip_addr
        self.exp_time = expiration_time

class CapabilityQueue:
    def __init__(self):
        self.capabilities = []
        self.active = True

    def addCapability(self, capability):
        self.capabilities.append(capability)
        self.capabilities.sort(key=lambda x: x.exp_time)

    def removeExpirations(self):
        current_time = time.time()
        for cap in self.capabilities:
            if cap.exp_time < current_time:
                self.capabilities.remove(cap)
                
    def containsCapability(self, ip_addr):
        for cap in self.capabilities:
            if cap.ip_addr == ip_addr:
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
    while queue.isActive():
        if not queue.isEmpty():
            queue.printQueue()
        queue.removeExpirations()
        time.sleep(.5)

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
