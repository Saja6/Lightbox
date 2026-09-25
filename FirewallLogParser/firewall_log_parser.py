# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import ipaddress
import json
import os.path
import re
import subprocess
import sys
import time
from collections import defaultdict
import smtplib
from email.message import EmailMessage
# the following regexes will assist in finding entries in the log file which indicate allowed and blocked traffic:
blockPattern = r'.*?\[UFW BLOCK\]\s+IN=(?P<in>\S*)\s+OUT=\S*\s+(?:MAC=(?P<mac>\S+)\s+)?SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3}).*?(?:PROTO=(?P<proto>\w+))?.*?(?:SPT=(?P<spt>\d+))?.*?(?:DPT=(?P<dpt>\d+))?'
allowPattern = r'.*?\[UFW ALLOW\]\s+IN=(?P<in>\S*)\s+OUT=\S*\s+SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3}).*?(?:PROTO=(?P<proto>\w+))?.*?(?:SPT=(?P<spt>\d+))?.*?(?:DPT=(?P<dpt>\d+))?'
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
            else:
                date = timematch
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
        "interval": 300,
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
    interval = int(config.get("interval", 60))
    whitelist = [ip.strip() for ip in config.get("whitelist", "").split(",") if ip.strip()]
    # MyEmail = "EMAIL" # change this to your gmail address!
    # MyAppPass = "AAAA BBBB CCCC DDDD" # change this to your google app password!
    print(
        "::: Welcome to FLIP, the Firewall Log Ingestion Program!\n----------------------------------------------------------------\n❗ "
        "Use this tool in order to efficiently parse firewall logs and generate useful,\n"
        "information pertaining to them. You can always configure FLIP by editing.\n"
        "its configuration file in \"flip.conf\"\n"
        "\n::: Your current configuration is:\n"
        f"\tLog to ingest: {os.path.abspath(logLocation)}\n"
        f"\tNumber of blocks needed for automatic IP blocking: {numBlocks}\n"
        f"\tInterval between parses: {interval} seconds\n"
        f"\tWhitelist: {whitelist}\n"
        "\nIf your configuration is complete, enter 'C' to continue.\nOtherwise, please press any other key to exit the program.\n")
    entry = input("Continue? [C/c]: ")
    if entry == "C" or entry == "c":
        while True:
            print(f"🔥::: Now parsing firewall log...")
            eventList = loghunt(logLocation)
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
                    f.write(f"🔎 SOURCE: {ip}:\n\t📝 ACTIONS COUNTED: {count}\n\t🛑 [BLOCK]: {eventtypes[ip].count('BLOCK')}\n\t🟢 [ALLOW]: {eventtypes[ip].count('ALLOW')}")
                    f.write(f"\n**** END SUMMARY FOR {ip} ****\n\n")
                f.write("❗::: The above results are meant for analytical purposes only. Please verify the type of device\n"
                    "by using a port scanner to identify a recognizable host name for each IP address logged in ufw.log.\n"
                    "NEVER assume that traffic from an IP address that has been continuously allowed is safe.\n"
                    "This could potentially point to unauthorized network access if you don't recognize\nthe host name identified by your port scanner. "
                    "Please utilize this information above to\nimplement additional security features as needed.")
            print("✅ ::: Report generated! Details: \n-------------------------------------------------------------")
            with open("results.rpt", "r") as f: print(f.read())
            print("-------------------------------------------------------------")
            # if you do not need emailing functions and features, uncomment lines 72, 73, as well as lines 93 to 100.
            # message = EmailMessage() # make a new email object and set its contents (below)
            # message["Subject"] = "Firewall Log Parser Results"
            # message["From"] = MyEmail
            # message["To"] = MyEmail
            # with open("results.rpt") as f: message.set_content(f.read())
            # with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s: # google's SMTP client operates on port #465.
            #    s.login(MyEmail, MyAppPass)
            #    s.send_message(message)
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
            if 0 < interval <= 60: # unusually short intervals may not be easy to work with, so check for it:
                print("\n❗::: WARNING: Your interval between parses is unusually low (< 60 seconds).\n"
                      "If you continue, you may end up with an undesirable, large amount of\n"
                      "results that may become difficult to manage. If you are okay with this,\n"
                      "Enter 'C' to continue, or any other key to exit the program and save results.\n")
                entry = input("Continue? [C/c]: ")
                if entry == "C" or entry == "c":
                    print("✅ ::: User confirmed continuation.")
                    print(f"🕧 ::: Waiting {interval} seconds before next parse...")
                    time.sleep(interval)
                else: sys.exit(1)
            else:
                print(f"🕧 ::: Waiting {interval} seconds before next parse...")
                time.sleep(interval)
            if interval == 0: sys.exit(0)
