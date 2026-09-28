import json
import os
import subprocess
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed
import time
import platform
# we will ping a number of hosts to check if we can reach them.
# @param: the host in the form of an IP address or web address to ping.
# @return: a dictionary containing the host, status,
#           and elapsed time for each ping command.
#           if the ping throws an exception, it will include the error
#           in the dictionary as well.
def ping(host):
    print(f"🕒 ::: Pinging {host}...")
    start = time.perf_counter()
    commandFlag = "-n" if platform.system() == "Windows" else "-c"
    try:
        # NOTE: on Windows, replace "-c" with "-n"
        subprocess.run(["ping", commandFlag, "2", host], shell = False, check = True, timeout = 5,
        capture_output = True, text = True)
        elapsed = (time.perf_counter() - start)
        return {
            "Host": host,
            "Status": "UP",
            "Error": "No errors detected",
            "Time": round(elapsed, 2)
        }
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {
            "Host": host,
            "Status": "DOWN",
            "Error": str(e),
            "Time": round(elapsed, 2)
        }

if __name__ == "__main__":
    # default configuration if none is found:
    config = {
        "hosts": [],
        "threads": 6,
        "filename": "results"
    }
    try:
        with open("mapping.conf", "r") as f:
            for line in f:
                line = line.strip()  # remove whitespaces before and after line
                if not line or line.startswith("#"): continue  # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1)  # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError:
        print("⚠️ ::: mapping.conf not found. Using default configurations...")
    # below configurations may end up as default if mapping.conf was not found!
    hostList = [ip.strip() for ip in config.get("hosts", "").split(",") if ip.strip()]
    threads = int(config.get("threads", 6))
    filename = config.get("filename", "results")
    results = [] # store the raw results here
    futureResults = [] # store the future results here
    errorCount = 0
    # use a thread pool executor for improved performance
    with ThreadPoolExecutor(max_workers = threads) as executor:
        for host in hostList:
            result = executor.submit(ping, host) # submit our function to the pool
            results.append(result)
    with open(f"{filename}.json", "w") as f:
        for future in as_completed(results): # print out the results of each ping.
            futureMap = future.result()
            print(f"- Ping result for: {futureMap['Host']}:")
            print(f"\t🕒Elapsed time: {futureMap['Time']}\n\t❓Status: {futureMap['Status']}\n\t⚠️ Errors: {futureMap['Error']}\n")
            if(futureMap['Error'] != "No errors detected"): errorCount += 1
            futureResults.append(futureMap)
        json.dump(futureResults, f, indent = 4)
    if errorCount > 0: print("⚠️ ::: Warning: some hosts failed to be pinged. Please review results.")
    print(f"✅ ::: Done! Generated copy of results in {os.path.abspath(filename)}.")
