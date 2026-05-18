# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import time
from collections import defaultdict
import re
ip_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}-\d{2}:\d{2})\s+\S+\s+sshd-session\[(\d+)\]: Failed password for (\S+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+) ssh\d+'
# we will use the regex above and search /var/log/auth.log for failed login attempts.
# All IPs in the log are identified and processed in loghunt()
#   @param: none
#   @return: a list containing tuples.
#       Each tuple includes the IP in question,
#       the port number it connected to, which user
#       it tried logging in to, the time of login attempt,
#       and the date of login attempt. If no matches are found,
#       loghunt() will return an empty list.
#
def loghunt():
    suspiciousIPs = []
    try: f = open('auth.log', 'r')
    except FileNotFoundError: f = open('/var/log/auth.log', 'r')
    with f:
        lines = f.readlines()
        for line in lines: # for each line, try finding a match with the provided regex.
            match = re.match(ip_pattern, line)
            if match: # if there is a match, we will find our associated groups to obtain useful information
                affectedUser = match.group(3)
                IP = match.group(4)
                portNum = match.group(5)
                timestring = match.group(1)
                dateAndTime = datetime.datetime.fromisoformat(timestring)
                time = dateAndTime.strftime("%I:%M:%S %p")
                date = dateAndTime.strftime("%B %d, %Y")
                suspiciousIPs.append((IP, portNum, affectedUser, time, date))
    return suspiciousIPs
if __name__ == '__main__':
    interval = 300 # 5 minutes between each parse
    attempts = defaultdict(int) # create an empty dictionary
    events = loghunt()
    for entry in events:
        ip = entry[0] # IP is always the first element in our tuple
        attempts[ip] += 1 # increment the attempts for that IP
    filename = f"results_{datetime.datetime.now().strftime('%m-%d-%Y_%I:%M:%S-%p')}.rpt"
    with open(filename, 'w') as f:
        while True:
            for ip, count in attempts.items():
                f.write(f"****** BEGIN SUMMARY: {ip} ******\n\n")
                f.write(f"{ip} has {count} failed attempts\n\n")
                for entry in events:
                    if entry[0] == ip: # the attempts made by an IP to SSH will be written to the file.
                        f.write(f"{entry[0]} on port {entry[1]} "f"attempted login on {entry[2]} at {entry[3]} on {entry[4]}\n")
                # depending on how many login attempts there have been, different kinds of info will be written to the report.
                if attempts[ip] < 3: f.write(f"Severity: LOW -- {attempts[ip]} failed attempts. No further action needed.\n\n")
                elif attempts[ip] <= 5 and attempts[ip] >= 3: f.write(f"Severity: MODERATE -- {attempts[ip]} failed attempts. Consider monitoring this IP.\n\n")
                elif attempts[ip] >= 5 and attempts[ip] <= 7: f.write(f"Severity: HIGH -- {attempts[ip]} failed attempts. Consider blocking this IP.\n\n")
                elif attempts[ip] > 7: f.write(f"Severity: VERY HIGH -- {attempts[ip]} failed attempts. TAKE IMMEDIATE ACTION!\n\n")
                f.write(f"****** END SUMMARY: {ip} ******\n")
            time.sleep(interval)
