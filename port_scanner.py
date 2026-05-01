import socket
import sys
import time
from collections import defaultdict
IPList = ['192.168.1.185'] # the list of IP addresses we will try to connect to
commonports = range(1, 1024) # a basic scan will scan ports on this range (up to 1024)
allports = range(1, 65535) # a full scan will scan ports on this range (up to 65535)

# we will perform a port scan on each IP in the IPList to see if they are open
# @param: a command line argument; either "basic_mode" or "full_mode".
#       The argument dictates which kind of scan takes place.
# @return: a dictionary containing each IP mapped to the port number and service
#       running on that port should it be reached.
def scanPorts(mode = "basic_mode"):
    scanRange = commonports if mode == "basic_mode" else allports
    results = defaultdict(list)
    print(f"\n[***] Starting port scan ({mode})...\n")
    startTime = time.time()
    for ip in IPList: # do the following for every IP in IPList
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            for port in scanRange: # now with every port in the port range:
                try:
                    result = s.connect_ex((ip, port)) # connect to the IP on the current port
                    if result == 0: # the connection returned code 0, so no problems. now try this:
                        try: service = socket.getservbyport(port) # see if the port has a service running on it
                        except OSError: service = "unknown"
                        print(f"[OPEN] {ip}:{port} ({service})") # no exception mean we got a service
                        results[ip].append((port, service)) # now add our important info to the dictionary
                except Exception as e:
                    print(f"[ERROR] {ip}:{port} -- {e}")
                    continue
    print(f"[INFO] Scan completed in {time.time() - startTime:.2f}s")
    return results

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "basic_mode"
    interval = 300 # 5 minutes between each scan
    with open('results.rpt', 'a') as f:
        while True:
            f.write(f"\n[INFO] Starting scan in {mode}\n")
            results = scanPorts(mode)
            f.write("\n========== SUMMARY ==========\n")
            for ip, services in results.items():
                f.write(f"\nTarget: {ip}\n")
                f.write(f"Open ports: {len(services)}\n")
                for port, service in services: f.write(f"  - {port}/{service}\n")
            f.write("[INFO] Scan complete. Sleeping...\n")
            f.flush()
            time.sleep(interval)



