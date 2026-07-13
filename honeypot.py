# Copyright 2026 Saja6: https://github.com/Saja6
import smtplib
import socket
import datetime
from email.message import EmailMessage


# we will listen on any port and receive connections and log specific details about it
# @param: the port number on which to listen for connections
# @return: nothing
def startService(portNumber):
    # VARIABLES:
    MyEmail = "stephjay442@gmail.com" # change this to your email!
    MyAppPass = "irmx sdjj czuc jlum" # change this to your google app password!
    print(f"::: Now activating honeypot on {portNumber}.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', portNumber))
        s.listen()
        print("Listening on port", portNumber)
        while True:
            conn, addr = s.accept()
            with conn:
                print("Connection made by:", addr)
                conn.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n") # send the service name over
                with open("results.rpt", "a") as f:
                    f.write(f"**** BEGIN SUMMARY: {addr} ****\n")
                    while True:
                        data = conn.recv(1024)
                        if not data: break
                        timestamp = datetime.datetime.now().strftime("%B %d %Y at %I:%M %p")
                        f.write(f"Data received: {data!r} at {timestamp}\n")
                    f.write(f"**** END SUMMARY: {addr} ****\n\n")
                # if you don't need emailing features, comment out lines 13, 14, and lines 34 to 41
                message = EmailMessage()
                message["Subject"] = "Honeypot Alert"
                message["From"] = MyEmail
                message["To"] = MyEmail
                with open("results.rpt") as f: message.set_content(f.read())
                with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s: # google's SMTP server operates on port 465
                    s.login(MyEmail, MyAppPass)
                    s.send_message(message)

if __name__ == '__main__':
    startService(2222) # change this to be whatever port you want to listen on!
