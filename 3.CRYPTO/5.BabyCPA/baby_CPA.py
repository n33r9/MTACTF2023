#!/usr/local/bin/python3.10 -u

import sys
import select
from Crypto.Util.number import *
import gmpy2
import json
import socketserver
import threading


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        f = open("flag.txt","rb")
        flag = f.read()

        self.request.settimeout(30)
        rsend = self.request.sendall
        rclose = self.request.close
        rrecv = self.request.recv

        e = 65537
        users = {b"admin"}
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        d = gmpy2.invert(e, (p - 1) * (q - 1))


        rsend(b"Welcome to Baby CPA Challenge! \n")
        rsend(b"N = " + str(n).encode())     
        
            
        while(True):
            try:
                rsend(b"\n1. New account\n2. Login. \n3. Exit\nPlease enter your choice (1,2 or 3):")
                x = rrecv(4096).decode().rstrip('\n').rstrip('\r')
                option = int(x)
            except:                
                rsend(b"Enter a valid option!\n")
            if option == 1:
                rsend(b"Create a new account. Please enter your username: ")
                account = rrecv(4096).decode().rstrip('\n').rstrip('\r').encode()
                    
                if account not in users:
                    users.add(account)
                    rsend(account + b"_" + str(pow(bytes_to_long(account), d, n)).encode())
            elif option == 2:
                rsend(b"Login! Please enter your username: ")
                username = rrecv(4096).decode().rstrip('\n').rstrip('\r').encode()

                rsend(b"Please enter your password: ")
                password = int(rrecv(4096).decode().rstrip('\n').rstrip('\r'))
                
                if username in users and bytes_to_long(username) == pow(password, e, n):
                    if username == b"admin":
                        rsend(b"Flag is " + flag)
                        exit(0)
                    else:
                        rsend(b"No admin, no flag!")
                else:
                    rsend(b"Username or password is not correct!")
            elif option == 3:
                exit(0)
            else:
                rsend(b"Enter a valid option!\n")
        rsend("Please submit the flag!")
        rclose()
        f.close()


HOST, PORT = '0.0.0.0', 1111
while True:
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:"), server_thread.name
    server_thread.join()

    
