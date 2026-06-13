import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.l2 import getmacbyip
import time
# we will scan a range of IP addresses over a subnet for MAC addresses reachable on our network.
# @param: the IP address to scan
# @return: a dictionary containing the IP address with its respective discovered MAC address.
def scanSubnets(ip):
    print(f"::: Scanning for MAC addresses over {ip}...")
    stringIP = str(ip)
    start = time.perf_counter() # performance counter to identify time
    macAddress = getmacbyip(stringIP) # pull the MAC address
    elapsed = time.perf_counter() - start
    if not macAddress: return None
    else: macAddressDisplay = macAddress
    print(f"::: Found MAC Address: {macAddress} - {stringIP} in {round(elapsed, 4)} seconds.")
    return {"IP Address": stringIP, "MAC Address": macAddressDisplay, "Elapsed Time": round(elapsed, 3)}

if __name__ == "__main__":
    # Use the following options as the argument:
    # '192.168.1.0/26'
    # '192.168.1.0/25'
    # '192.168.1.0/24'
    net = '192.168.1.0/25'
    net = ipaddress.ip_network(net)
    hosts = list(net.hosts())
    macDictionary = {} # we will use this to map MAC addresses to all IPs they correspond to.
    with ThreadPoolExecutor(max_workers = 30) as executor:
        results = executor.map(scanSubnets, hosts)
        for device in results:
            if device:
                mac = device["MAC Address"]
                IP = device["IP Address"]
                if mac not in macDictionary: macDictionary[mac] = [] # make an empty tuple to start
                macDictionary[mac].append(IP) # add a new IP into the list of IPs a MAC associates with/
    with open(f"mac_resolutions_{time.strftime("%Y%b%d-%I:%M%p")}.txt", "w") as f:
        for mac, IPList in macDictionary.items():
            f.write(f"**** BEGIN SUMMARY FOR MAC ADDRESS: {mac} ****\n")
            f.write(f"Total IPs bound to address: {len(IPList)}\n")
            f.write("Associated IPs: ")
            IPinRow = 0 # counter for number of IPs in a row on a line (7 at most allowed)
            for ip in IPList:
                IPinRow += 1
                if IPinRow == 7: # 7 is enough, so write new line and reset count.
                    f.write(f"{ip}\n")
                    IPinRow = 0
                else: f.write(f"{ip}, ")
            f.write(f"\n**** END SUMMARY FOR MAC ADDRESS: {mac} ****\n\n")

