import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.l2 import getmacbyip
import time
from mac_vendor_lookup import MacLookup
# we will scan a range of IP addresses over a subnet for MAC addresses reachable on our network.
# @param: the IP address to scan
# @return: a dictionary containing the IP address with its respective discovered MAC address.
def resolveMac(ip):
    print(f"🔎 ::: Scanning for MAC addresses over {ip}...")
    stringIP = str(ip)
    start = time.perf_counter()
    try: macAddress = getmacbyip(stringIP)
    except Exception as e: return {
        "IP Address": stringIP,
        "MAC Address": None,
        "Elapsed Time": time.perf_counter() - start,
        "Error": str(e)
    }
    elapsed = time.perf_counter() - start
    if not macAddress: return {
        "IP Address": stringIP,
        "MAC Address": None,
        "Elapsed Time": elapsed,
        "Error": None
    }
    macAddress = macAddress.upper()
    print(f"✅ ::: Found MAC Address: {macAddress} - "f"{stringIP} in {elapsed:.4f} seconds.")
    return {
        "IP Address": stringIP,
        "MAC Address": macAddress,
        "Elapsed Time": elapsed,
        "Error": None
    }

if __name__ == "__main__":
    print("::: Welcome to MAST, the MAC Address Scanning Tool!\n"
          "❗Note: this tool is suited for collecting hardware-related information\n"
          "in order to identify devices connected to a private LAN as well as MAC addresses assigned to each device.\n"
          "Please use this tool responsibly by using it on a network you have an authorized and stable connection to.\n"
          "Do not use this tool on any network that you do not have rightful access to for the purposes of\n"
          "identifying, geolocating, or developing plans to compromise any sort of computer hardware.\n"
          "Please enter 'C' to continue, otherwise enter any other key to exit.\n")
    entry = input("Continue? [C/c] ")
    if entry == "C" or entry == "c":
        # Use the following options as the argument depending on the range of IP addresses you want to handle:
        # '192.168.1.0/26'
        # '192.168.1.0/25'
        # '192.168.1.0/24'
        net = '192.168.1.0/25'
        net = ipaddress.ip_network(net)
        hosts = net.hosts()
        macDictionary = {} # we will use this to map MAC addresses to all IPs they correspond to.
        errors = []
        with ThreadPoolExecutor(max_workers = 30) as executor:
            results = executor.map(resolveMac, hosts)
            for device in results:
                if not device: continue
                if device["MAC Address"]:
                    mac = device["MAC Address"].upper()
                    ip = device["IP Address"]
                    if mac not in macDictionary: macDictionary[mac] = []
                    macDictionary[mac].append(ip)
                elif device["Error"]:
                    errors.append(f"IP {device['IP Address']}: {device['Error']}")
        with open("mac_resolutions_report.txt", "w") as f:
            for mac, IPList in macDictionary.items():
                try: vendor = MacLookup().lookup(mac)
                except Exception: vendor = "Unknown vendor"
                f.write(f"**** BEGIN SUMMARY FOR MAC ADDRESS: {mac} ****\n")
                f.write(f"⭐ Vendor: {vendor}\n")
                f.write(f"⭐ Total IPs bound to MAC address: {len(IPList)}\n")
                f.write("⭐ Associated IPs: ")
                for i in range(0, len(IPList), 7): f.write(", ".join(IPList[i:i + 7]) + "\n")
                f.write(f"**** END SUMMARY FOR MAC ADDRESS: {mac} ****\n\n")
            if errors:
                f.write("**** UNRESOLVED / ERRORS ****\n")
                for err in errors: f.write(f"❗{err}\n")
            print("✅ ::: MAC address resolving process completed! Details: \n")
        with open("mac_resolutions_report.txt", "r") as f: print(f.read())
    else: sys.exit(1)
