import datetime
import json
import re
import time
from collections import defaultdict

# the following regexes will assist in finding entries in the log file which indicate allowed and blocked traffic:
blockPattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+-\d{2}:\d{2}) pi kernel: \[UFW BLOCK\] IN=(\S+) OUT= MAC=([0-9a-fA-F:]+) SRC=(\d{1,3}(?:\.\d{1,3}){3})(?:.*PROTO=(\w+))?(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?'
allowPattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+-\d{2}:\d{2}) pi kernel: \[UFW ALLOW\] IN=\S* OUT=\S* SRC=(\d{1,3}(?:\.\d{1,3}){3}) DST=(\d{1,3}(?:\.\d{1,3}){3})(?:.*PROTO=(\w+))?(?:.*SPT=(\d+))?(?:.*DPT=(\d+))?'

# we will parse a firewall log that contains information about traffic going through it.
# @param: none
# @return: an array of dictionaries, each of which map parsed
#   information such as IP, date/time, destination, etc.
#   to its respective key.
def loghunt():
    output = []
    with open('ufw.log', 'r') as f:
        lines = f.readlines()
        for l in lines: # iterate over all the lines
            blockMatch = re.match(blockPattern, l) # try to find a match where an IP address was blocked
            if blockMatch:
                # extract some information from the match so we can put it in a dictionary
                timestamp = blockMatch.group(1)
                date = timestamp.split('T')[0]
                time = timestamp.split('T')[1][:8]
                interface = blockMatch.group(2)
                macAddress = blockMatch.group(3)
                source = blockMatch.group(4)
                sourcePort = blockMatch.group(6) if blockMatch.group(6) else None
                destinationPort = blockMatch.group(7) if blockMatch.group(7) else None
                event = {
                    "EventType": "BLOCK",
                    "Date": date,
                    "Time": time,
                    "Interface": interface,
                    "MacAddress": macAddress,
                    "Source": source,
                    "Source Port": sourcePort,
                    "Destination Port": destinationPort,
                    "Destination": None
                }
                output.append(event) # now add it to the array
            allowMatch = re.match(allowPattern, l) # try to find a match where an IP address was allowed in
            if allowMatch:
                # extract some information from the match so we can put it in a dictionary
                timestamp = allowMatch.group(1)
                date = timestamp.split('T')[0]
                time = timestamp.split('T')[1][:8]
                source = allowMatch.group(2)
                destination = allowMatch.group(3)
                sourcePort = allowMatch.group(5) if allowMatch.group(5) else None
                destinationPort = allowMatch.group(6) if allowMatch.group(6) else None
                event = {
                    "EventType": "ALLOW",
                    "Date": date,
                    "Time": time,
                    "Protocol": allowMatch.group(4),
                    "MacAddress": None,
                    "Source": source,
                    "Source Port": sourcePort,
                    "Destination": destination,
                    "Destination Port": destinationPort
                }
                output.append(event)  # now add it to the array
    return output
if __name__ == '__main__':
    interval = 300 # we will wait 5 minutes until parsing the firewall log again.
    while True:
        eventList = loghunt()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") # we will create individual snapshots
        jsonfile = f"results_{timestamp}.json"
        with open(jsonfile, "w") as f: json.dump(eventList, f, indent = 4)
        attempts = defaultdict(int) # make a dictionary for counting attempts per IP and associated actions like BLOCK
        eventtypes = defaultdict(list)
        for event in eventList:
            source = event["Source"] # search up the source IP and event type
            eventtype = event["EventType"]
            attempts[source] += 1 # increment the attempt
            eventtypes[source].append(eventtype)
        with open("results.rpt", "w") as f:
            for ip, count in attempts.items():
                f.write(f"**** BEGIN SUMMARY FOR {ip} ****\n")
                # below, count the number of times BLOCK or ALLOW appears in each tuple in the map
                f.write(f"SOURCE {ip} | COUNT {count} | [BLOCK]: {eventtypes[ip].count('BLOCK')} | [ALLOW]: {eventtypes[ip].count('ALLOW')}")
                f.write(f"\n**** END SUMMARY FOR {ip} ****\n\n")
        time.sleep(interval)