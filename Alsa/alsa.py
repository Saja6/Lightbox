# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import ipaddress
import json
import os
import subprocess
import sys
from collections import defaultdict
import re
timePatten = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{2}:\d{2}|Z)?)' # a regex for identifying the time of an attempted login
userPattern = r'Failed password for (?:invalid user )?(?P<user>\S+)' # a regex for identifying the user related to the login attempt
ipPattern = r'from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+)' # a regex for identifying an IP address pattern for IPv4 and v6 addresses
portPattern = r'port (?P<port>\d+)' # a regex for identifying the port associated with the attempted login
logEntryPattern = re.compile(rf'{timePatten}.*?{userPattern}\s+{ipPattern}\s+{portPattern}') # the regex combining all components to avoid strictness
# we will use the regex above and search /var/log/auth.log for failed login attempts.
# All IPs in the log are identified and processed in loghunt()
#   @param: none
#   @return: a list of suspicious IPs, which in turn contains the
#   list of data related to the supposed brute-force attack that
#   was captured using our regexes.
#
def loghunt(logPath):
    print("🕒 ::: Now parsing authentication log...")
    try:
        with open(logPath, 'r') as f:
            for line in f:
                if "Failed password" not in line: continue
                match = logEntryPattern.search(line) # search the line for a matching pattern
                if match:
                    data = match.groupdict() # retrieve the groups as a dictionary then populate it below.
                    timestring = data['timestamp']
                    try:
                        dateAndTime = datetime.datetime.fromisoformat(timestring)
                        timeString = dateAndTime.strftime("%I:%M:%S %p")
                        dateString = dateAndTime.strftime("%B %d, %Y")
                    except ValueError:
                        timeString, dateString = "Unknown Time", "Unknown Date"
                    yield (data['ip'], data['port'], data['user'], timeString, dateString)
    except FileNotFoundError:
        print(f"🛑 ::: File not found: {os.path.abspath(logPath)}, stopping...")
        sys.exit(1)
    except PermissionError:
        print(f"🛑 ::: Permission denied for accessing: {os.path.abspath(logPath)}, stopping...")
        sys.exit(1)

if __name__ == '__main__':
    attempts = defaultdict(int) # create an empty dictionary for our attempts
    alreadyBanned = set()
    if os.path.exists("banned.json"):
        try:
            with open("banned.json", "r") as f: alreadyBanned = set(json.load(f))
        except (json.JSONDecodeError, ValueError): print("⚠️ ::: banned.json was corrupted or empty. Initializing new set.")
    # default configuration if none is found:
    config = {
        "log-location": "/var/log/auth.log",
        "num-failed-attempts-required": 5,
        "target-jail": "sshd"
    }
    try:
        with open("alsa.conf", "r") as f:
            for line in f:
                line = line.strip()  # remove whitespaces before and after line
                if not line or line.startswith("#"): continue  # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1)  # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError:
        print("⚠️ ::: alsa.conf not found. Using default configurations...")
    # below configurations may end up as default if alsa.conf was not found!
    logLocation = config.get("log-location", "/var/log/auth.log")
    numBlocks = int(config.get("num-failed-attempts-required", 5))
    targetJail = config.get("target-jail", "sshd")
    print(
        "::: Welcome to ALSA, the Authentication Log Summarizer & Analyzer!\n----------------------------------------------------------------\n❗ "
        "Use this tool in order to efficiently parse authentication logs and generate useful,\n"
        "information pertaining to them. You can always configure ALSA by editing.\n"
        "its configuration file in \"alsa.conf\".\n"
        "\n::: Your current configuration is:\n"
        f"\tLog to ingest: {os.path.abspath(logLocation)}\n"
        f"\tNumber of blocks needed for automatic IP blocking: {numBlocks}\n")
    eventsByIP = defaultdict(list) # the events recorded by IP will be stored in this dictionary
    results = []
    for item in loghunt(logLocation):
        ip = item[0]
        eventsByIP[ip].append(item)
    for ip, items in eventsByIP.items():
        count = len(items)
        if count < 3: severity = "LOW"
        elif count <= 5: severity = "MODERATE"
        elif count <= 7: severity = "HIGH"
        else: severity = "VERY HIGH"
        entry = {
            "IP address": ip,
            "Count": count,
            "Severity": severity,
            "Actions": [f"{item[0]} on port {item[1]} attempted login on {item[2]} at {item[3]} on {item[4]}" for item in items]
        }
        results.append(entry)
    with open("results.json", 'w') as f: json.dump(results, f, indent = 4)
    if numBlocks > 0:
        for ip, items in eventsByIP.items():
            count = len(items)
            if count >= numBlocks:
                if ip in alreadyBanned:
                    print(f"✅ ::: IP \"{ip}\" is already banned, skipping.")
                    continue
                print(f"🕧 ::: Enforcing automatic fail2ban IP blocking for {ip} (Blocked {count} times)...")
                try: ipaddress.ip_address(ip)
                except ValueError:
                    print(f"🛑 ::: \"{ip}\" is not a valid IP address. Skipping block...")
                    continue
                try: # automate our work by implementing the fail2ban rule!
                    command = ["sudo", "fail2ban-client", "set", targetJail, "banip", ip]
                    subprocess.run(command, check = True, capture_output = True, text = True)
                    alreadyBanned.add(ip)
                    print(f"✅ ::: Successfully banned \"{ip}\" in jail {targetJail}!")
                except subprocess.CalledProcessError as e:
                    print(f"🛑 ::: Failed to block IP address \"{ip}\": {e.stderr.strip()}")
    with open("banned.json", "w") as f: json.dump(list(alreadyBanned), f, indent = 4)
    print("\n✅ ::: Report generated! \n-------------------------------------------------------------")
    print("How you should respond by severity:")
    print("🟢🟢⚫⚫⚫ LOW SEVERITY: No further action required. Run this tool as often as you normally would.\n"
                  "However, if you do not recognize the IP address associated with the login attempts, monitor it more closely.\n")
    print("🟡🟡🟡⚫⚫ MODERATE SEVERITY: Enhanced monitoring is encouraged. If entirely uncertain about the device\n"
                  "associated with the IP address trying to log in, consider blocking it. Run this tool more often.\n")
    print("🟠🟠🟠🟠⚫ HIGH SEVERITY: Block the IP address associated with the login attempts right away.\n"
                  "The person using the device associated with the logged IP address likely indicates an attempted brute-force attack.\n")
    print("🔴🔴🔴🔴🔴 VERY HIGH SEVERITY: Block the IP address associated with the login attempts immediately.\n"
                  "Do not assume that this behavior is ever safe. If required, create an additional report documenting the\n"
                  "suspicious activity from the device associated with this IP address.")
    print("-------------------------------------------------------------")
