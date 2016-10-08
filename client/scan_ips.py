import socket
import sys
from datetime import datetime

# This program conducts a scan on port 80 of all addresses in a specified range in 10.4.2.0/24.
# The range can be specified by including the last octet of the start and end address,
# or the default specified below will be used.

defaultStartAddress = 0
defaultEndAddress = 10

if len(sys.argv) == 1:
	rangeStart = defaultStartAddress
	rangeEnd = defaultEndAddress
elif len(sys.argv) == 3:
	rangeStart = int(sys.argv[1])
	rangeEnd = int(sys.argv[2])
else:
	print 'Invalid number of arguments specified, either specify none or include the start and end of the range to scan.'
	sys.exit()

ip_address_start = '10.4.2.'

#lists to store the results of the connection attempts
successful_connections = []
refused_connections = []
no_route_to_destination = []
other_errors = []

#Display the result as each attempt is made
verbose = False

print 'Conducting scan on addresses in range {} to {}'.format(ip_address_start + str(rangeStart), ip_address_start + str(rangeEnd))

start_time = datetime.now()
for address_end in range(rangeStart, rangeEnd + 1):
	try:
		#set up a socket for tcp connections, try to connect to the current address on port 80. 
		#If successful, no socket.error error will be raised, record this as a success.
		scanning_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if verbose:
			print 'Attempting scan on {}'.format(ip_address_start + str(address_end))
		result = scanning_socket.connect(('10.4.2.' + str(address_end),80))
		if verbose:
			print result
		successful_connections.append(address_end)
	except socket.error as err:
		#record socket.error errors as connection failures using the errno to determine the cause of failure.
		#Differentiates between refused connection and no route to hosts, any other errors will be grouped together but should not happen.
		if verbose:
			print 'Error on connecting: {}'.format(err)
		if err.errno == 111:
			refused_connections.append(address_end)
		elif err.errno == 113:
			no_route_to_destination.append(address_end)
		else:
			other_errors.append(address_end)
	except KeyboardInterrupt:
		print 'Program execution stopped by user.'
		sys.exit()

end_time = datetime.now()

#Display a summary of the results, total addresses and specific address numbers for each category.
print 'Successful connections (total {}): {}'.format(len(successful_connections), successful_connections)
print 'Refused connections (total {}): {}'.format(len(refused_connections), refused_connections)
print 'Unreachable hosts (total {}): {}'.format(len(no_route_to_destination), no_route_to_destination)
if len(other_errors) != 0:
	print 'Other errors took place in connecting to the following addresses (total {}): {}'.format(len(other_errors), other_errors)
print 'Total scan time: {}'.format(end_time - start_time)
