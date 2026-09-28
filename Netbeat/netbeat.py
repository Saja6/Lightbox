# Copyright 2026 Saja6: https://github.com/Saja6
import datetime
import json
import os
import socket
import subprocess
import time
import speedtest
from dns import resolver
import requests
from ping3 import ping
# We will try to ping our router by passing its IP address as an argument.
# @param: the IP address of the router.
# @return: True if the ping succeeded, False otherwise.
def pingRouter(routerIP):
    print("🕒 ::: Starting router ping test...")
    result = subprocess.run(["ping", "-c", "5", routerIP], shell = False) # run a ping command to ping the IP 5 times.
    if result.returncode == 0: # return code 0 means success!
        print("\n✅ ::: Router ping successful.\n")
        return True
    else:
        print(f"\n🔴 ::: Router ping failed.\n")
        return False

# We will try to ping our DNS server by passing its IP address as an argument.
# @param: the IP address of the DNS server.
# @return: True if the DNS server ping succeeded; False otherwise.
def pingDNSServer(DNS_IP):
    print("🕒 ::: Starting DNS server ping test...")
    result = subprocess.run(["ping", "-c", "5", DNS_IP], shell = False) # run a ping command to ping the IP 5 times.
    if result.returncode == 0: # return code 0 means success!
        print("\n✅ ::: DNS Server ping successful.")
        return True
    else:
        print(f"\n🔴 ::: DNS Server ping failed.\n")
        return False

# We will try to perform a DNS server lookup by passing its IP address as an argument as well as a website.
# @param: the IP address of the DNS server.
# @return: The time it took for the DNS server to resolve if the DNS server ping succeeded; none otherwise.
def testDNSlookup(DNS_IP, website):
    try:
        r = resolver.Resolver() # create a DNS resolver object
        r.nameservers = [DNS_IP] # the nameservers associated with it include the IP passed
        start = time.perf_counter()
        answer = r.resolve(website, "A")
        elapsed = (time.perf_counter() - start) * 1000 # the time it took to resolve a request.
        print(f"\n✅ ::: DNS lookup time: {elapsed:.2f} ms")
        for ip in answer: print(ip) # we may have multiple returned answers, which are the IPs associated with a website.
        return elapsed
    except Exception as e:
        print(f"\n🔴 ::: DNS lookup failed: {e}\n")
        return None

# We will send an HTTPS request to a website and see if it succeeded and the configured timeout.
# @param: the website in the form of https://WEBSITE.com to use.
# @return: True if the request succeeded; False otherwise.
def testHTTPSrequest(website, Timeout):
    print("🕒 ::: Starting HTTPS request test...")
    try:
        result = requests.get(website, timeout = Timeout) # send an HTTPS request and wait at most 5 seconds.
        if result.ok: # is the result a good one? we did alright then.
            print(f"\n✅ ::: HTTPS request succeeded\n")
            return True
        else:
            print(f"\n🔴 ::: HTTPS request failed with status {result.status_code}\n")
            return False
    except Exception as e:
        print(f"\n🔴 ::: HTTP request failed: {e}\n")
        return False

# We will test the upload and download speeds in Mbps over our network.
# @param: nothing
# @return: the upload and download speeds recorded after the test; None for both if it failed.
def testDownloadAndUploadSpeeds():
    print("🕒 ::: Starting download/upload speed test...")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        st = speedtest.Speedtest() # create a speedtest object.
        download = st.download() / 1000000 # divide by 1 million to go from bits to megabits
        upload = st.upload() / 1000000
        print(f"✅ ::: Upload speed: {upload:.2f} Mbps")
        print(f"✅ ::: Download speed: {download:.2f} Mbps\n")
        return upload, download
    except Exception as e:
        print(f"🔴 ::: Speed test failed: {e}")
        return None, None

# We will test the general network latency.
# @param: the DNS server's IP address, the website to connect to, and configured timeout
# @return: 3 kinds of latencies: ping, HTTPS, and TCP (see comments below!)
def testLatency(DNS_IP, website, Timeout):
    try:
        print("🕒 ::: Starting latency tests...")
        pingLatency = ping(DNS_IP, unit = "ms") # how fast does it take to ping an address?
        HTTPSStartTime = time.perf_counter()
        result = requests.get(f"https://{website}")
        HTTPSLatency = (time.perf_counter() - HTTPSStartTime) * 1000 # how fast did a successful HTTPS request get processed?
        TCPStartTime = time.perf_counter()
        s = socket.create_connection((website, 443), timeout = Timeout) # 443 is the port number used by HTTPS
        TCPLatency = (time.perf_counter() - TCPStartTime) * 1000 # how fast was a TCP connection made?
        s.close()
        print("✅ ::: Latency tests complete.\n")
        return pingLatency, HTTPSLatency, TCPLatency
    except Exception as e:
        print(f"\n🔴 ::: One or more latency tests failed: {e}\n")
        print("✅ ::: Latency tests complete.\n")
        return None, None, None

if __name__ == "__main__":
    # default configuration if none is found:
    config = {
        "router-ip": "192.168.1.1",
        "dns-ip": "192.168.1.1",
        "test-website": "google.com",
        "log-name": "results",
        "timeout": 5
    }
    try:
        with open("netbeat.conf", "r") as f:
            for line in f:
                line = line.strip()  # remove whitespaces before and after line
                if not line or line.startswith("#"): continue  # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1)  # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError:
        print("⚠️ ::: netbeat.conf not found. Using default configurations...")
    # below configurations may end up as default if netbeat.conf was not found!
    RouterIP = config.get("router-ip", "192.168.1.1")
    DNSServerIP = config.get("dns-ip", "192.168.1.1")
    TestWebsite = config.get("test-website", "google.com")
    LogName = config.get("log-name", "results")
    Timeout = int(config.get("timeout", 5))
    print("✅ ::: Starting Netbeat tests...")
    # now time to fetch results below:
    routerResult = pingRouter(RouterIP)
    DNSServerResult = pingDNSServer(DNSServerIP)
    DNSLookupResult = None
    if DNSServerResult == True: DNSLookupResult = testDNSlookup(DNSServerIP, TestWebsite)
    else: print("\n🔴 ::: DNS server unreachable. Skipping DNS lookup test.\n")
    HTTPSresult = testHTTPSrequest(f"https://{TestWebsite}", Timeout)
    uploadSpeed, downloadSpeed = testDownloadAndUploadSpeeds()
    pingLatency, HTTPSLatency, TCPLatency = testLatency(DNSServerIP, TestWebsite, Timeout)
    DNSResults = {
        "DNS Ping Status": "PING SUCCESSFUL" if DNSServerResult == True else "PING FAILED",
        "DNS Lookup Speed": DNSLookupResult if DNSServerResult == True else "N/A"
    }
    HTTPSResults = {
        "HTTPS Status": "REQUEST SUCCESSFUL" if HTTPSresult == True else "REQUEST FAILED",
        "HTTPS Latency": HTTPSLatency if HTTPSLatency else "N/A"
    }
    TCPResults = {
        "TCP Status": "CONNECTION SUCCESSFUL" if TCPLatency else "CONNECTION FAILED",
        "TCP Latency": TCPLatency if TCPLatency else "N/A"
    }
    netspeedResults = {
        "Download Speed": f"{downloadSpeed} mbps" if downloadSpeed else "N/A",
        "Upload Speed": f"{uploadSpeed} mbps" if uploadSpeed else "N/A"
    }
    # we will generate a report with useful information below:
    print(f"🕒 ::: Generating network health report...\n")
    with open(f"{LogName}.json", "w") as f:
        results = {"Time": f"{datetime.datetime.now().strftime('%b %d, %Y at %I:%M %p')}",
                 "Router Ping Status": "PING SUCCESSFUL" if routerResult == True else "PING FAILED",
                 "DNS": DNSResults,
                 "HTTPS": HTTPSResults,
                 "TCP": TCPResults
        }
        json.dump(results, f, indent = 4)
    print(f"✅ ::: Network health tests completed. Results are stored in: {os.path.abspath(LogName)}\n")
