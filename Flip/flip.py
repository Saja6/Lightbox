# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import ipaddress
import json
import os.path
import re
import subprocess
from collections import defaultdict
# we will parse a firewall log that contains information about traffic going through it.
# @param: none
# @return: an array of dictionaries, each of which map parsed
#   information such as IP, date/time, destination, etc.
#   to its respective key.
def loghunt(logLocation):
    output = []
    with open(logLocation, 'r') as f:
        for line in f:
            if "[UFW BLOCK]" in line: eventtype = "BLOCK"
            elif "[UFW ALLOW]" in line: eventtype = "ALLOW"
            else: continue
            # we will try to find a matching timestamp in the log
            timematch = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            timestamp = timematch.group(1) if timematch else ""
            # an entry might contain th T, so remove it and take first part of the split;
            if "T" in timestamp:
                date = timestamp.split("T")[0]
                timeString = timestamp.split("T")[1][:8]
            elif timestamp:
                parts = timestamp.rsplit(" ", 1)
                date = parts[0]
                timeString = parts[1] if len(parts) > 1 else None
            else:
                date = None
                timeString = None
            # make a dictionary and map all instances of constants or identifiers separated from their value by an '='
            keyvalues = dict(re.findall(r'(\b[A-Z_]+)=([^\s]*)', line))
            event = {
                "EventType": eventtype,
                "Date": date,
                "Time": timeString,
                "Interface": keyvalues.get("IN") or None,
                "MacAddress": keyvalues.get("MAC") or None,
                "Source": keyvalues.get("SRC") or None,
                "Source Port": keyvalues.get("SPT") or None,
                "Destination": keyvalues.get("DST") or None,
                "Destination Port": keyvalues.get("DPT") or None,
                "Protocol": keyvalues.get("PROTO") or None
            }
            output.append(event)
    return output

if __name__ == '__main__':
    # default configuration if none is found:
    config = {
        "log-location": "/var/log/ufw.log",
        "num-blocks-required": 30,
        "whitelist": []
    }
    try:
        with open("flip.conf", "r") as f:
            for line in f:
                line = line.strip() # remove whitespaces before and after line
                if not line or line.startswith("#"): continue # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1) # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError: print("⚠️ ::: flip.conf not found. Using default configurations...")
    # below configurations may end up as default if flip.conf was not found!
    logLocation = config.get("log-location", "ufw.log")
    numBlocks = int(config.get("num-blocks-required", 5))
    whitelist = [ip.strip() for ip in config.get("whitelist", "").split(",") if ip.strip()]
    print(
        "::: Welcome to FLIP, the Firewall Log Ingestion Program!\n----------------------------------------------------------------\n❗ "
        "Use this tool in order to efficiently parse firewall logs and generate useful,\n"
        "information pertaining to them. You can always configure FLIP by editing.\n"
        "its configuration file in \"flip.conf\"\n"
        "\n::: Your current configuration is:\n"
        f"\tLog to ingest: {os.path.abspath(logLocation)}\n"
        f"\tNumber of blocks needed for automatic IP blocking: {numBlocks}\n"
        f"\tWhitelist: {whitelist}\n")
    print(f"🔥::: Now parsing firewall log...")
    eventList = loghunt(logLocation)
    jsonfile = "results.json"
    with open(jsonfile, "w") as f: json.dump(eventList, f, indent = 4)
    attempts = defaultdict(int) # make a dictionary for counting attempts per IP and associated actions like BLOCK
    eventtypes = defaultdict(list)
    for event in eventList:
        source = event["Source"] # search up the source IP and event type
        eventtype = event["EventType"]
        attempts[source] += 1 # increment the attempt
        eventtypes[source].append(eventtype)
    print(f"✅ ::: Firewall log parse complete!")
    if numBlocks > 0:
        for ip, events in eventtypes.items():
            blockCount = events.count('BLOCK') # count number of times blocked
            if blockCount >= numBlocks:
                if ip not in whitelist:
                    print(f"🕧 ::: Enforcing network traffic block from {ip} (Blocked {blockCount} times)...")
                    try: ipaddress.ip_address(ip)
                    except ValueError:
                        print(f"🛑 ::: \"{ip}\" is not a valid IP address. Skipping block...")
                        continue
                    try: # automate our work by implementing the firewall rule!
                        subprocess.run(["sudo", "ufw", "deny", "from", ip], check = True, capture_output = True, text = True)
                        print(f"✅ ::: Blocked network traffic from {ip}!")
                    except subprocess.CalledProcessError as e:
                        print(f"🛑 ::: Failed to block traffic from {ip}: {e.stderr.strip()}")
