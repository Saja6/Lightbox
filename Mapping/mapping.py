# Copyright 2026 Saja6: https://github.com/Saja6
import json
import socket
import datetime
import sys
import threading

ReceiveSize = 4096 # total number of bytes we can receive per connection

# we will listen on any port and receive connections and log specific details about it
# @param: the port number  on which to listen for connections, the maxbytes to receive, and the name of the service to send over.
# @return: nothing
def createSocket(port, service, maxBytes):
        print(f"🪤 ::: Now activating honeypot and listening on {port}.")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', int(port)))
            s.listen()
            while True:
                conn, addr = s.accept()
                with conn:
                    print("🚨 ::: Connection made by:", addr)
                    conn.sendall(f"{service}\r\n".encode()) # send the service name over
                    totalBytes = 0
                    while totalBytes < maxBytes: # as long as the total bytes received did not exceed limit:
                        bytesRemaining = maxBytes - totalBytes # calculate total remaining and receive the smallest of them:
                        recieveSize = min(ReceiveSize, bytesRemaining)
                        data = conn.recv(recieveSize)
                        if not data: break
                        totalBytes += len(data)
                        timestamp = datetime.datetime.now().strftime("%B %d %Y at %I:%M %p")
                        result = {
                            "IP Address": addr[0],
                            "Source Port": addr[1],
                            "Time:": timestamp,
                            "Data Received:": str(data)
                        }
                        # use a lock to allow each thread to write to the same file without messing it up.
                        jsonLock = threading.Lock()
                        with jsonLock:
                            try:
                                with open("results.json", "r") as f: connections = json.load(f)
                            except (FileNotFoundError, json.JSONDecodeError): connections = []
                            connections.append(result)
                            with open("results.json", "w") as f: json.dump(connections, f, indent=4)
                    print(f"🪤 ::: Connection from {addr[0]}:{addr[1]} ended after total bytes: {totalBytes}")

if __name__ == '__main__':
    # default configuration if none is found:
    config = {
        "ports": "",
        "service": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "max-bytes": 65536
    }
    try:
        with open("microbait.conf", "r") as f:
            for line in f:
                line = line.strip()  # remove whitespaces before and after line
                if not line or line.startswith("#"): continue  # ignore comments or blank lines
                if "=" in line:
                    key, val = line.split("=", 1)  # separate the key from the value in flip.conf
                    config[key.strip()] = val.strip()
    except FileNotFoundError:
        print("⚠️ ::: microbait.conf not found. Using default configurations...")
    # below configurations may end up as default if microbait.conf was not found!
    ports = [port.strip() for port in config.get("ports", "").split(",") if port.strip()]
    maxbytes = int(config.get("max-bytes", 65536))
    services = [service.strip() for service in config.get("services", "").split(",") if service.strip()]
    if len(ports) != len(services):
        print(f"🔴 ::: ERROR: List size mismatch: Port list length {len(ports)} != service length {len(services)}. Please check your configuration.")
        sys.exit(1)
    print("::: Welcome to Microbait! A lightweight honeypot and IP logging service.")
    # we will allow multithreading to allow each honeypot connection to run in the background as a daemon
    threads = []
    for port, service in zip(ports, services):
        thread = threading.Thread(target = createSocket, args = (port, service, maxbytes), daemon = True)
        thread.start()
        threads.append(thread)
    for thread in threads: thread.join()
