# Copyright 2026 Saja6: https://github.com/Saja6
import socket
import datetime
# we will listen on any port and receive connections and log specific details about it
# @param: the port number on which to listen for connections
# @return: nothing
def startService(portNumber):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', portNumber))
        s.listen()
        print("Listening on port", portNumber)
        while True:
            conn, addr = s.accept()
            with conn:
                print("Connection made by:", addr)
                conn.sendall(b"Big Toe\n") # change this to send a different service name (highly suggested!)
                with open("results.rpt", "a") as f:
                    f.write(f"**** BEGIN SUMMARY: {addr} ****\n")
                    while True:
                        data = conn.recv(1024)
                        if not data: break
                        f.write(f"Data received: {data!r} at {datetime.now().strftime("%B %d %Y at %I:%M %p")}\n")
                    f.write(f"**** END SUMMARY: {addr} ****\n\n")

if __name__ == '__main__':
    startService(8888) # change this to be whatever port you want to listen on!
