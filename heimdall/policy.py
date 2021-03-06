import toml
import ipaddress

debug = True

def getPolicy(config_filename):
    with open(config_filename) as conffile:
        config = toml.loads(conffile.read())
    return config

#needs config
#Evaluate a specific policy against the client request to see if it is a match.
def checkPolicy(policy, config, clientIP, serverName):
    if compareSelector(policy, config, clientIP, serverName) == True:
        return True
    else:
        return False

#needs config, clientIP, serverName
#Evaluate the Selector field of a policy to see if it is a match for the client IP and server name.
def compareSelector(policy, config, clientIP, serverName):
    if debug:
        print '    comparing selectors on policy {}'.format(policy)
    ipMatch = True
    serverMatch = True
    selectors = config[policy]['selector'].split(':')
    if debug:
        print '    selectors are {} and {} and client info is {} and {}.'.format(selectors[0], selectors[1], clientIP, serverName)
    if selectors[0] != '':
        if '/' in selectors[0]: #CIDR
            if ipaddress.ip_address(unicode(clientIP, "utf-8")) not in ipaddress.ip_network(selectors[0], strict=False):
                ipMatch = False
        else: #wildcard
            if len(clientIP) != len(selectors[0]):
                ipMatch = False
            else:
                for i,c in enumerate(selectors[0]):
                    if (c != '*') and (c != clientIP[i]):
                        ipMatch = False
    if selectors[1] != '':
        if serverName != selectors[1]:
            serverMatch = False
    if debug:
        print '    returning {} and {}'.format(ipMatch, serverMatch)
    return ipMatch and serverMatch

#needs config
#start with the config file, and iterate over each policy after the default one.
#If a policy matches, return that one. If you get through all the policies and none match, return the default one.
def matchPolicy(policies, serverName, clientIP):
    config = policies
    for policy in config:
        if policy != 'default':
            if checkPolicy(policy, config, clientIP, serverName):
                if debug:
                    print '  choosing policy {}'.format(policy)
                return config[policy]
            elif debug:
                print '  rejected policy {}'.format(policy)
    if debug:
        print 'Choosing the default policy.'
    return config['default']
