# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import json
import re
import time
from collections import defaultdict

# the following regex will assist in finding entries in the log file which indicate allowed and blocked traffic:
ufwPattern = r'\[(UFW BLOCK|UFW AUDIT)\].*IN=(\S+)\s+OUT=(\S*)\s+MAC=([0-9a-fA-F:]+).*SRC=([\d\.]+).*DST=([\d\.]+|[0-9a-fA-F:]+)'
# we will parse a firewall log that contains information about traffic going through it.
# @param: none
# @return: an array of dictionaries, each of which map parsed
#   information such as IP, date/time, destination, etc.
#   to its respective key.
def loghunt():
    print("::: Now parsing firewall log...")
    output = []
    with open('/var/log/ufw.log', 'r') as f:
        lines = f.readlines()
        for l in lines:
            match = re.search(ufwPattern, l)
            if match:
                event = {
                    "EventType": match.group(1),
                    "Interface": match.group(2),
                    "Out": match.group(3),
                    "MacAddress": match.group(4),
                    "Source": match.group(5),
                    "Destination": match.group(6)
                }
                output.append(event)
    print("::: Parsing complete.")
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
