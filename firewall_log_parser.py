# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import json
import re
import time
from collections import defaultdict
import smtplib
from email.message import EmailMessage
# the following regexes will assist in finding entries in the log file which indicate allowed and blocked traffic:
blockPattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+-\d{2}:\d{2})\s+\S+\s+\S+:\s+\[UFW BLOCK\]\s+IN=(\S+)\s+OUT=\s+MAC=([0-9a-fA-F:]+)\s+SRC=(\d{1,3}(?:\.\d{1,3}){3})(?:.*?PROTO=(\w+))?(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?'
allowPattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d+\.\d+-\d{2}:\d{2})\s+\S+\s+\S+:\s+\[UFW ALLOW\]\s+IN=\S*\s+OUT=\S*\s+SRC=(\d{1,3}(?:\.\d{1,3}){3})\s+DST=(\d{1,3}(?:\.\d{1,3}){3})(?:.*?PROTO=(\w+))?(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?'
# we will parse a firewall log that contains information about traffic going through it.
# @param: none
# @return: an array of dictionaries, each of which map parsed
#   information such as IP, date/time, destination, etc.
#   to its respective key.
def loghunt():
    output = []
    with open('/var/log/ufw.log', 'r') as f:
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
    # VARIABLES
    interval = 1800 # we will wait 30 minutes until parsing the firewall log again.
    MyEmail = "EMAIL" # change this to your gmail address!
    MyAppPass = "AAAA BBBB CCCC DDDD" # change this to your google app password!
    while True:
        print(f"🔥::: Now parsing firewall log...")
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
        # if you do not need emailing functions and features, comment out lines 72, 73, as well as lines 93 to 100.
        message = EmailMessage() # make a new email object and set its contents (below)
        message["Subject"] = "Firewall Log Parser Results"
        message["From"] = MyEmail
        message["To"] = MyEmail
        with open("results.rpt") as f: message.set_content(f.read())
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s: # google's SMTP client operates on port #465.
            s.login(MyEmail, MyAppPass)
            s.send_message(message)
        print(f"✅ ::: Firewall log parse complete!")
        time.sleep(interval)
