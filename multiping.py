import subprocess
from concurrent.futures.thread import ThreadPoolExecutor
from concurrent.futures import as_completed
import time
# we will ping a number of hosts to check if we can reach them.
# @param: the host in the form of an IP address or web address to ping.
# @return: a dictionary containing the host, status,
#           and elapsed time for each ping command.
#           if the ping throws an exception, it will include the error
#           in the dictionary as well.
def ping(host):
    print(f"::: Pinging {host}...")
    start = time.perf_counter()
    try:
        # NOTE: on Windows, replace "-c" with "-n"
        subprocess.run(["ping", "-c", "2", host], shell = False, check = True, timeout = 5,
        capture_output = True, text = True)
        elapsed = (time.perf_counter() - start)
        return {
            "host": host,
            "status": "UP",
            "time": round(elapsed, 2)
        }
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {
            "host": host,
            "status": "DOWN",
            "error": str(e),
            "time": round(elapsed, 2)
        }
    print("::: Ping complete.")

if __name__ == "__main__":
    hostList = ["wholefoods.com", "amazon.com", "google.com", "192.168.1.166", "172.16.17.32", "192.168.1.156", "192.168.1.1", "192.168.1.100"] # change these to your list of hosts!
    futures = []
    # use a thread pool executor for improved performance
    with ThreadPoolExecutor(max_workers = min(3, len(hostList))) as executor:
        for host in hostList:
            future = executor.submit(ping, host) # submit our function to the pool
            futures.append(future)
    with open(f"ping_report_{time.strftime("%Y%b%d-%I:%M%p")}.txt", "w") as f:
        f.write("**** BEGIN PING SESSION SUMMARY ****\n")
        for future in as_completed(futures): # print out the results of each ping.
            futureMap = future.result()
            f.write(f"{futureMap['host']}: {futureMap['status']} | ELAPSED TIME: ({futureMap['time']}s)\n")
        f.write("**** END PING SESSION SUMMARY ****")
