import socket
import sys

# we will scan ports over the designated range
# @param: the range of ports such as (1, 1024) to scan
# @return: the list of ports open on a device with an IP address, otherwise an empty list.
def scanPorts(portRange):
    IPs = ["192.168.1.1"] # add as many IPs whose ports will be scanned as need be.
    openPorts = [] # a list containing dictionaries with each IP mapped to its open ports list
    for ip in IPs:
        openPortsOnIP = []  # a list of all open ports associated with an IP address
        print(f"🕒 ::: Scanning ports on {ip}...")
        for port in portRange:
            print(f"🕒 ::: Scanning port #{port} on {ip}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.01) # wait for this long before timing out
                target = (ip, port)
                try:
                    result = s.connect_ex(target) # try to connect to the target
                    if result == 0:
                        print(f"🟢 ::: Found open port: Port #{port} is open on {ip}")
                        openPortsOnIP.append(port)
                except socket.gaierror:
                    print(f"::: Could not resolve hostname/IP: {ip}")
                    break
                except Exception as e: pass
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
        # pass a range or custom list of ports to scan
        openPorts = scanPorts(range(1,10))
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
