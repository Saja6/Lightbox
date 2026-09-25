# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import ipaddress
import os
import subprocess
import sys
import time
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
    alreadyBanned = set()  # we will track which IPs we have banned already!
    # default configuration if none is found:
    config = {
        "log-location": "/var/log/auth.log",
        "num-failed-attempts-required": 5,
        "interval": 300,
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
    # below configurations may end up as default if flip.conf was not found!
    logLocation = config.get("log-location", "/var/log/auth.log")
    numBlocks = int(config.get("num-failed-attempts-required", 5))
    interval = int(config.get("interval", 60))
    targetJail = config.get("target-jail", "sshd")
    print(
        "::: Welcome to ALSA, the Authentication Log Summarizer & Analyzer!\n----------------------------------------------------------------\n❗ "
        "Use this tool in order to efficiently parse authentication logs and generate useful,\n"
        "information pertaining to them. You can always configure ALSA by editing.\n"
        "its configuration file in \"alsa.conf\"\n"
        "\n::: Your current configuration is:\n"
        f"\tLog to ingest: {os.path.abspath(logLocation)}\n"
        f"\tNumber of blocks needed for automatic IP blocking: {numBlocks}\n"
        f"\tInterval between parses: {interval} seconds\n"
        "\nIf your configuration is complete, enter 'C' to continue.\nOtherwise, please press any other key to exit the program.\n")
    entry = input("Continue? [C/c]: ")
    if entry == "C" or entry == "c":
        while True:
            eventsByIP = defaultdict(list) # the events recorded by IP will be stored in this dictionary
            for item in loghunt(logLocation):
                ip = item[0]
                eventsByIP[ip].append(item)
            with open("results.rpt", 'w') as f:
                for ip, items in eventsByIP.items():
                    count = len(items)
                    f.write(f"****** BEGIN SUMMARY: {ip} ******\n\n")
                    f.write(f"{ip} has {count} failed attempts\n\n")
                    for item in items:
                        if item[0] == ip: f.write(f"{item[0]} on port {item[1]} attempted login on {item[2]} at {item[3]} on {item[4]}\n")
                    # we will assign levels to suggested actions below and write them to the report.
                    if count < 3: f.write(f"Severity: 🟢🟢⚫⚫⚫ LOW -- {count} failed attempts. No further action needed.\n\n")
                    elif count <= 5: f.write(f"Severity: 🟡🟡🟡⚫⚫ MODERATE -- {count} failed attempts. Consider monitoring this IP.\n\n")
                    elif count <= 7: f.write(f"Severity: 🟠🟠🟠🟠⚫ HIGH -- {count} failed attempts. Consider blocking this IP.\n\n")
                    else: f.write(f"Severity: 🔴🔴🔴🔴🔴 VERY HIGH -- {count} failed attempts. TAKE IMMEDIATE ACTION!\n\n")
                    f.write(f"****** END SUMMARY: {ip} ******\n")
                f.write(
                    "\n❗::: The above results are meant for analytical purposes only. Please verify the type of device\n"
                    "by using a IP scanner to identify a recognizable host name for each IP address logged in auth.log.\n"
                    "NEVER assume that a high number login attempts from an IP address is safe.\n"
                    "This could potentially point to an attempted brute-force attack if you don't recognize\nthe host name identified by your IP scanner. "
                    "Please utilize this information above to\nimplement additional security features as needed.")
            if numBlocks > 0:
                for ip, items in eventsByIP.items():
                    count = len(items)
                    if count >= numBlocks:
                        if ip in alreadyBanned:
                            print(f"✅ ::: IP \"{ip}\" is already banned, skipping.\n")
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
            print("✅ ::: Report generated! Details: \n-------------------------------------------------------------")
            with open("results.rpt", 'r') as f: print(f.read())
            print("-------------------------------------------------------------")
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
            print(f"🕒 ::: Waiting designated interval of {interval} seconds before next parse...")
            if 0 < interval <= 60:  # unusually short intervals may not be easy to work with, so check for it:
                print("\n❗::: WARNING: Your interval between parses is unusually low (< 60 seconds).\n"
                      "If you continue, you may end up with an undesirable, large amount of\n"
                      "results that may become difficult to manage. If you are okay with this,\n"
                      "Enter 'C' to continue, or any other key to exit the program and save results.\n")
                entry = input("Continue? [C/c]: ")
                if entry == "C" or entry == "c":
                    print("✅ ::: User confirmed continuation.")
                    print(f"🕧 ::: Waiting {interval} seconds before next parse...")
                    time.sleep(interval)
                else:
                    sys.exit(1)
            else:
                print(f"🕧 ::: Waiting {interval} seconds before next parse...")
                time.sleep(interval)
            if interval == 0: sys.exit(0)
    else: sys.exit(1)
