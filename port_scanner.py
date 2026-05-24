import socket
# we will scan ports over the designated range
# @param: the range of ports such as (1, 1024) to scan
# @return: nothing
def scanPorts(portRange):
    IPs = ["192.168.1.185"] # add as many IPs whose ports will be scanned as need be.
    for ip in IPs:
        print(f"Scanning ports on {ip}...")
        for port in portRange:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) # wait for this long before timing out
                target = (ip, port)
                try:
                    result = s.connect_ex(target) # try to connect to the target
                    if result == 0: print(f"Port #{port} is open on {ip}")
                except socket.gaierror:
                    print(f"Could not resolve hostname/IP: {ip}")
                    break
                except Exception as e: pass
        print(f"Connection to {ip} closed.")

if __name__ == "__main__":
    # pass a range or custom tuple of ports to scan
    scanPorts(range(1,1024))
    print("Port scan complete.")
