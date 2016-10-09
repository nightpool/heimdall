import time, socket, sys

timeDelay = 5
numQueries = 20

if(len(sys.argv) >= 3):
    timeDelay = int(sys.argv[1])
    numQueries = int(sys.argv[2])

serverIP = socket.gethostbyname("webserver.isp")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)


start_time = time.time()
for i in range(numQueries):
    try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
        sock.connect((serverIP, 80))
        print "Successful connection:", round(time.time() - start_time,2)
	sock.close()
    except socket.error as err:
	print "Connection failed:", round(time.time() - start_time,2)
    time.sleep(timeDelay)
