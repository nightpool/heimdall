import socket, sys, time

#default number of queries to make
numQueries = 20

#default time between queries
timeDelay = 5

#target web server
server_name = "webserver.isp"

#determine if a response was correct/incorrect
incorrect_response = "127.0.0.1"

if(len(sys.argv) >= 3):
    numQueries = int(sys.argv[1])
    timeDelay = int(sys.argv[2])

for i in range(numQueries):
    recv_addr = ""
    start_time = time.time()
    try:
	recv_addr = socket.gethostbyname(server_name)
	print "{},{},{}".format(str(i), round((time.time()-start_time)*1000, 2), recv_addr)
    except:
	print "{}, CRITCAL FAILURE".format(str(i))
    time.sleep(timeDelay)