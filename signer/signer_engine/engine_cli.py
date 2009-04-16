#!/usr/bin/env python
"""Simple command line interface to the command channel of the signer
engine"""

#
# simple python command line interface to the signer engine
#

import sys
import socket

def send_msg(msg, c_sock):
    """Send a message to the engine"""
    c_sock.send(msg)
    #print "sent cmd: " + msg,
    msg = ''
    chunk = ''
    prevchunk = ''
    while not (chunk == '\n' and prevchunk == '\n'):
        prevchunk = chunk
        chunk = c_sock.recv(1)
        if chunk == '':
            raise RuntimeError, "socket connection broken"
        if chunk != '\n':
            msg = msg + chunk
        else:
            print msg
            msg = ""


def run(c_sock):
    """Read commands from stdin, and send them to the engine. Responses
    are printed to stdout"""
    print "cmd> ",
    cmd = sys.stdin.readline()
    while cmd:
        if cmd[:4] == "quit" or cmd[:4] == "exit":
            sys.exit(0)
        send_msg(cmd, c_sock)
        print "cmd> ",
        cmd = sys.stdin.readline()

def engine_cli(args, host="localhost", port=47806):
    """Command interface to engine, args is a List of strings, if not
    None or empty, the list will be concatenated and sent to the engine
    at host:port"""
    cl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cl_sock.connect((host, port))
    if args and len(args) > 1:
        send_msg(" ".join(args[1:]) + "\n", cl_sock)
    else:
        run()
    cl_sock.shutdown(0)

if __name__ == "__main__":
    # if we have no arguments, go to interactive mode
    engine_cli(sys.argv)
