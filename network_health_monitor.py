import datetime
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
    print("::: Starting router ping test...")
    result = subprocess.run(["ping", "-c", "5", routerIP], shell = False) # run a ping command to ping the IP 5 times.
    if result.returncode == 0: # return code 0 means success!
        print("\n::: Router ping successful.\n")
        return True
    else:
        print(f"\n::: Router ping failed.\n")
        return False

# We will try to ping our DNS server by passing its IP address as an argument.
# @param: the IP address of the DNS server.
# @return: True if the DNS server ping succeeded; False otherwise.
def pingDNSServer(DNS_IP):
    print("::: Starting DNS server ping test...")
    result = subprocess.run(["ping", "-c", "5", DNS_IP], shell = False) # run a ping command to ping the IP 5 times.
    if result.returncode == 0: # return code 0 means success!
        print("\n::: DNS Server ping successful.")
        return True
    else:
        print(f"\n::: DNS Server ping failed.\n")
        return False

# We will try to perform a DNS server lookup by passing its IP address as an argument as well as a website.
# @param: the IP address of the DNS server.
# @return: The time it took for the DNS server to resolve if the DNS server ping succeeded; False otherwise.
def testDNSlookup(DNS_IP, website):
    try:
        r = resolver.Resolver() # create a DNS resolver object
        r.nameservers = [DNS_IP] # the nameservers associated with it include the IP passed
        start = time.perf_counter()
        answer = r.resolve(website, "A")
        elapsed = (time.perf_counter() - start) * 1000 # the time it took to resolve a request.
        print(f"\nDNS lookup time: {elapsed:.2f} ms")
        for ip in answer: print(ip) # we may have multiple returned answers, which are the IPs associated with a website.
        return elapsed
    except Exception as e:
        print(f"\n::: DNS lookup failed: {e}\n")
        return False

# We will send an HTTPS request to a website and see if it succeeded.
# @param: the website in the form of https://WEBSITE.com to use.
# @return: True if the request succeeded; False otherwise.
def testHTTPSrequest(website):
    print("::: Starting HTTPS request test...")
    try:
        result = requests.get(website, timeout = 5) # send an HTTPS request and wait at most 5 seconds.
        if result.ok: # is the result a good one? we did alright then.
            print(f"\n::: HTTPS request succeeded\n")
            return True
    except Exception as e:
        print(f"\n::: HTTP request failed: {e}\n")
        return False

# We will test the upload and download speeds in Mbps over our network.
# @param: nothing
# @return: the upload and download speeds recorded after the test; None for both if it failed.
def testDownloadAndUploadSpeeds():
    print("::: Starting download/upload speed test...")
    try:
        st = speedtest.Speedtest() # create a speedtest object.
        download = st.download() / 1000000 # divide by 1 million to go from bits to megabits
        upload = st.upload() / 1000000
        print(f"Upload speed: {upload:.2f} Mbps")
        print(f"Download speed: {download:.2f} Mbps\n")
        return upload, download
    except Exception as e:
        print(f"::: Speed test failed: {e}")
        return None, None

# We will test the general network latency.
# @param: nothing
# @return: 3 kinds of latencies: ping, HTTPS, and TCP (see comments below!)
def testLatency(DNS_IP, website):
    try:
        print("::: Starting latency tests...")
        pingLatency = ping(DNS_IP, unit = "ms") # how fast does it take to ping an address?
        HTTPSStartTime = time.perf_counter()
        result = requests.get(f"https://{website}")
        HTTPSLatency = (time.perf_counter() - HTTPSStartTime) * 1000 # how fast did a successful HTTPS request get processed?
        TCPStartTime = time.perf_counter()
        s = socket.create_connection((website, 443), timeout = 5) # 443 is the port number used by HTTPS
        TCPLatency = (time.perf_counter() - TCPStartTime) * 1000 # how fast was a TCP connection made?
        s.close()
        print("::: Latency tests complete.\n")
        return pingLatency, HTTPSLatency, TCPLatency
    except Exception as e:
        print(f"\n::: One or more latency tests failed: {e}\n")
        print("::: Latency tests complete.\n")

if __name__ == "__main__":
    # GLOBAL VARIABLES:
    DNSServerIP = "192.168.1.9" # change this to the IP address of your DNS server
    RouterIP = "192.168.1.1" # change this to the IP address of your router.
    TestWebsite = "www.google.com" # you may use a different website if you want.

    # now time to fetch results below:
    while True:
        routerResult = pingRouter(RouterIP)
        DNSServerResult = pingDNSServer(DNSServerIP)
        DNSLookupResult = None
        if DNSServerResult == True: DNSLookupResult = testDNSlookup(DNSServerIP, TestWebsite)
        else: print("\n::: DNS server unreachable. Skipping DNS lookup test.\n")
        HTTPSresult = testHTTPSrequest(f"https://{TestWebsite}")
        uploadSpeed, downloadSpeed = testDownloadAndUploadSpeeds()
        pingLatency, HTTPSLatency, TCPLatency = testLatency(DNSServerIP, TestWebsite)
        currentTime = datetime.datetime.now().strftime("%b-%d-%Y")
        filename = "NetworkHealthMonitor_" + currentTime + ".rpt"
        # we will generate a report with useful information below:
        print(f"::: Generating network health report...\n")
        with open(filename, "w") as f:
            f.write("**** BEGIN NETWORK HEALTH SUMMARY ****\n")
            f.write(f"Today's date: {datetime.datetime.now().strftime('%b %d, %Y at %I:%M %p')}\n\n")
            f.write("* AVAILABILITY TESTS:\n")
            routerText = "Router ping test: SUCCESSFUL" if routerResult == True else "Router ping test: FAILED"
            DNSServerText1 = "DNS server ping test: SUCCESSFUL" if DNSServerResult == True else "DNS server ping test: FAILED"
            DNSServerText2 = f"DNS lookup speed: {DNSLookupResult:.2f} ms" if DNSLookupResult else "DNS lookup speed: FAILED"
            HTTPStext = "HTTPS request test: SUCCESSFUL" if HTTPSresult == True else "HTTP request test: FAILED"
            f.write(routerText + "\n")
            f.write(DNSServerText1 + "\n")
            f.write(DNSServerText2 + "\n")
            f.write(HTTPStext + "\n\n")
            f.write("* TRANSMISSION SPEED TESTS:\n")
            f.write(f"Network upload speed: {uploadSpeed:.2f} Mb/s\n")
            f.write(f"Network download speed: {downloadSpeed:.2f} Mb/s\n\n")
            f.write("* LATENCY TESTS:\n")
            f.write(f"Ping latency: {pingLatency:.2f} ms\n")
            f.write(f"HTTP latency: {HTTPSLatency:.2f} ms\n")
            f.write(f"TCP latency: {TCPLatency:.2f} ms\n")
            f.write("**** END NETWORK HEALTH SUMMARY ****\n")
        print(f"::: Network health tests completed. Results are stored in: {os.path.abspath(filename)}\n")
        print("::: Please wait 30 minutes for the next network health test.\n")
        time.sleep(1800) # we will perform these tests every half hour.
