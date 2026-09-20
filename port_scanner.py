import concurrent.futures
import platform
import socket
import subprocess
import sys
import time

# we will scan ports over the designated range
# @param: the range of ports such as (1, 1024) to scan as well as the list of IPs to scan
# @return: the list of ports open on a device with an IP address, which may be empty. Elapsed time 
#   for the scan will also be returned.
def scanPorts(portRange, IPs):
    openPorts = []
    commandFlag = "-n" if platform.system() == "Windows" else "-c" # check to see the operating system, since this dictates the flag
    startTime = time.perf_counter()
    for ip in IPs:
        print(f"\n🕒 ::: Assessing availability of host \"{ip}\"...")
        try:
            subprocess.run(["ping", commandFlag, "1", ip], check = True, timeout = 2)
            print(f"🟢 ::: Host \"{ip}\" is reachable.")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
            print(f"🔴 ::: Host \"{ip}\" is unreachable or blocking ping.")
            openPorts.append({"IP": ip, "Ports": []})
            continue
        # we will check a single port to see if it is open.
        # @param: the port number being scanned.
        # @return: None if the port closed, the port if it is open.
        def checkPort(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                try:
                    if s.connect_ex((ip, port)) == 0:
                        print(f"🟢 ::: Found open port: Port #{port} is open on {ip}")
                        return port
                except OSError: pass
            return None
        print(f"🕒 ::: Scanning ports 1 through {max(portRange)} on {ip}...")
        openPortsOnIP = [] # list that will contain our open ports
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(checkPort, port) for port in portRange]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None: openPortsOnIP.append(result)
        openPortsOnIP.sort() # sort them from smallest to largest
        openPorts.append({"IP": ip, "Ports": openPortsOnIP})
        print(f"⛓️‍💥 ::: Connection to {ip} closed.")
    endTime = time.perf_counter()
    elapsedTime = endTime - startTime
    return openPorts, elapsedTime

if __name__ == "__main__":
    print(
        "::: Welcome to port scanner!\n--------------------------------\n❗Note: this tool is intended for use in a dedicated IT zone and should be used responsibly.\n"
        "Do not use this tool to scan for open ports across a network you do not have rightful access to.\n"
        "Additionally, do not utilize it to identify potentially vulnerable devices in an attempt to\n"
        "launch a cyberattack against an individual, group of people, or public/private enterprise.\n"
        "By continuing you acknowledge that this tool is to be used for identifying a network attack surface\n"
        "in order to plan and implement additional security features across your devices if need be.\n"
        "Please enter 'C' to continue with the port scan, otherwise enter any other key to exit:\n")
    entry = input("Continue? [C/c] ")
    if entry.lower() == "c":
        print("::: Enter the number of ports you would like to scan from 1 up to your maximum.\n")
        try: numberOfPorts = int(input("Enter the maximum port number to scan up to (such as 1024): "))
        except ValueError: sys.exit("🔴 Invalid port number entered.")
        IPs = input("::: Enter the IP addresses you would like to scan (separated by spaces): ")
        formattedIPs = IPs.split()
        openPorts, elapsedTime = scanPorts(range(1, numberOfPorts + 1), formattedIPs)
        print("\n--------------------------------\n✅ ::: Port scan complete! Results:")
        minutes, seconds = divmod(elapsedTime, 60)
        formattedTime = None
        if minutes > 0: formattedTime = f"{int(minutes)}m {seconds:.2f}s"
        else: formattedTime = f"{seconds:.2f}s"
        print(f"🕒 Elapsed Time: {formattedTime}")
        for result in openPorts:
            ip = result["IP"]
            ports = result["Ports"]
            print(f"   IP address: {ip}")
            if ports:
                for port in ports: print(f"    🟢 Port: {port}")
            print("\n❗Note: if no list of ports identified as open appear next to each IP address,\n"
                  "no open ports were detected on the device with the associated IP address.\n--------------------------------")
    else: sys.exit(1)
