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
    def encrypt(self, m, e, n):
        return pow(bytes_to_long(m), e, n)

    def decrypt(self, c, d, n):
        return pow(c, d, n)

    def handle(self):
        f = open("flag.txt","rb")
        flag = f.read()

        self.request.settimeout(300)
        rsend = self.request.sendall
        rclose = self.request.close
        rrecv = self.request.recv

        e = 65537
        users = {b"admin"}
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        d = gmpy2.invert(e, (p - 1) * (q - 1))


        rsend(b"Welcome to Baby CCA challenge!")
        rsend(b"\nN = " + str(n).encode())
        rsend(b"\ne = " + str(e).encode())
        rsend(b"\nHere is your encrypted flag: " + long_to_bytes(self.encrypt(flag, e, n)).hex().encode())          
        
            
        try:
            rsend(b"\nEnter encrypted message (in hex): ")
            x = rrecv(4096).decode().rstrip('\n').rstrip('\r')
            c = int(x, 16)
        except:                
            rsend(b"\nNOT hex!!!")
            exit(0)
        
        if long_to_bytes(self.decrypt(c, d, n)) != flag:
            rsend(b"\nDecrypted message (in hex): " + long_to_bytes(self.decrypt(c, d, n)).hex().encode())
            exit(0)
        else:
            rsend(b"\nNo encrypted flag")
        f.close()


HOST, PORT = '0.0.0.0', 1111
while True:
    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:"), server_thread.name
    server_thread.join()

    
