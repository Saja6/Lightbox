import json
import subprocess
import sys
# Access policy description (this is an example of a policy you may find in 'access-policy.json'):
# {
#    "administrators": {
#        "ips": ["192.168.1.161"],
#        "allowed_ports": [22, 53, 80, 81, 443, 3001, 443, 19999, 8811, 5335]
#    },
#    "it_workers": {
#        "ips": [],
#        "allowed_ports": [3001, 443, 19999]
#    }
# }
# Any IP addresses under the key "administrators" have administrator privileges and may 
# access any of the Docker applications that we have set up. They may also be allowed
# To access SSH, HTTP, HTTPS, and DNS.
#
# Any IP addresses under the key "it_workers" have lower-level privileges and may 
# access only the Netdata and Uptime Kuma Docker containers. Special access to 
# any other network port should not be delegated without administrative approval.
#
# As your IT infrastructure or team grows, you can expect to add more and more IP addresses
# under either key field to allow for delegated user power across more devices. It is
# highly suggested to use an IT asset management tool to understand the 
# scale of your infrastructure and what IP addresses belong to your organization.

# we will implement firewall rules using UFW in the Python script.
# @param: the IP permitted to reach the port, which is also a parameter.
# @return" True if the firewall rule implementation succeeded, False otherwise.
def implementAccessControl(IP, port):
    command = ["sudo", "ufw", "allow", "from", IP, "to", "any", "port", str(port), "proto", "tcp"] # our command to run
    try:
        result = subprocess.run(command, shell=False, check=True, capture_output=True, text=True)
        print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ ::: UFW error: {e.stderr.strip()}")
        return False

if __name__ == '__main__':
    try:
        with open('access-policy.json', 'r') as f: accessList = json.load(f) # open and load our access list
    except FileNotFoundError:
        print("⚠️ ::: access-policy.json not found. Creating empty policy list...")
        with open('access-policy.json', 'w') as f: json.dump({}, f, indent = 4)
        sys.exit(1)
    if not accessList:
        print("⚠️ ::: Access policy is empty.")
        sys.exit(1)
    for group, settings in accessList.items(): # iterate over the JSON file
        ips = settings.get("ips", [])
        allowed_ports = settings.get("allowed_ports", [])
        if not ips:
            print(f"⚠️ ::: No IP addresses available for {group}.")
            continue
        # now implement the firewall rules
        for ip in ips:
            for port in allowed_ports:
                success = implementAccessControl(ip, port)
                if success: print(f"✅ ::: Allowed {ip} -> port {port}")
                else: print(f"❌ ::: Failed to allow {ip} -> port {port}")
