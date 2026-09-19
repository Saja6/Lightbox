import platform
import socket
import subprocess
import sys

# we will scan ports over the designated range
# @param: the range of ports such as (1, 1024) to scan as well as the list of IPs to scan
# @return: the list of ports open on a device with an IP address, which may be empty
def scanPorts(portRange, IPs):
    openPorts = [] # a list containing dictionaries with each IP mapped to its open ports list
    commandFlag = "-n" if platform.system() == "Windows" else "-c"
    for ip in IPs:
        try:
            print(f"🕒 ::: Assessing availability of host \"{ip}\"...")
            result = subprocess.run(["ping", commandFlag, "2", ip], shell=False, check=True, timeout=5, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            print(f"🔴 ::: Ping timed out: \"{ip}\"")
            continue
        except subprocess.CalledProcessError:
            print(f"🔴 ::: No respone from host: \"{ip}\"")
            continue
        except OSError as e:
            print(f"🔴 ::: Failed to execute ping for \"{ip}\": {e}")
            continue
        openPortsOnIP = []  # a list of all open ports associated with an IP address
        print(f"🟢 ::: Host \"{ip}\" is reachable.")
        print(f"🕒 ::: Scanning ports on {ip}...")
        for port in portRange:
            print(f"🕒 ::: Scanning port #{port} on {ip}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) # wait for this long before timing out
                target = (ip, port)
                try:
                    result = s.connect_ex(target) # try to connect to the target
                    if result == 0:
                        print(f"🟢 ::: Found open port: Port #{port} is open on {ip}")
                        openPortsOnIP.append(port)
                except OSError as e:
                    print(f"🔴 ::: Error while scanning {ip}:{port}: {e}")
        result = {
            "IP": ip,
            "Ports": openPortsOnIP,
        }
        openPorts.append(result)
        print(f"⛓️‍💥 ::: Connection to {ip} closed.")
    return openPorts

if __name__ == "__main__":
    print("::: Welcome to port scanner!\n--------------------------------\n❗Note: this tool is intended for use in a dedicated IT zone and should be used responsibly.\n"
          "Do not use this tool to scan for open ports across a network you do not have rightful access to.\n"
          "Additionally, do not utilize it to identify potentially vulnerable devices in an attempt to\n"
          "launch a cyberattack against an individual, group of people, or public/private enterprise.\n"
          "By continuing you acknowledge that this tool is to be used for identifying a network attack surface\n"
          "in order to plan and implement additional security features across your devices if need be.\n"
          "Please enter 'C' to continue with the port scan, otherwise enter any other key to exit:\n")
    entry = input("Continue? [C/c] ")
    if entry == "C" or entry == "c":
        print("::: Enter the number of ports you would like to scan. This port scanner will\n\tscan the number of ports from 1 all the way to the port number\n\tthat you enter.\n")
        numberOfPorts = input("Enter the maximum port number to scan up to (such as 1024): ")
        IPs = input("::: Enter the IP addresses you would like to scan (separated by spaces): ")
        formattedIPs = IPs.split()
        openPorts = scanPorts(range(1, int(numberOfPorts) + 1), formattedIPs)
        print("--------------------------------\n✅ ::: Port scan complete! Results:")
        if openPorts != []:
            for result in openPorts:
                ip = result["IP"]
                ports = result["Ports"]
                print(f"   IP address: {ip}")
                for port in ports: print(f"    🟢 Port: {port}")
        print("\n❗Note: if no list of ports identified as open appear next to each IP address,\n"
              "no open ports were detected on the device with the associated IP address.\n--------------------------------")
    else: sys.exit(1)
