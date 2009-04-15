#!/usr/bin/env python
"""Simple command line interface to the command channel of the signer
engine"""

#
# simple python command line interface to the signer engine
#

import sys
import socket

def send_msg(msg, client_socket):
    """Send a message to the engine"""
    client_socket.send(msg)
    print "sent cmd: " + msg,
    msg = ''
    chunk = ''
    prevchunk = ''
    while not (chunk == '\n' and prevchunk == '\n'):
        prevchunk = chunk
        chunk = client_socket.recv(1)
        if chunk == '':
            raise RuntimeError, "socket connection broken"
        if chunk != '\n':
            msg = msg + chunk
        else:
            print msg
            msg = ""


def run():
    """Read commands from stdin, and send them to the engine. Responses
    are printed to stdout"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 47806))

    print "cmd> ",
    cmd = sys.stdin.readline()
    while cmd:
        if cmd[:4] == "quit" or cmd[:4] == "exit":
            sys.exit(0)
        send_msg(cmd, client_socket)
        print "cmd> ",
        cmd = sys.stdin.readline()

    client_socket.shutdown(0)

if __name__ == "__main__":
    run()
