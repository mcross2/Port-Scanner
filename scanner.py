#!/usr/bin/python3

import socket
import argparse
import time
import os
import re
import struct
import subprocess
import sys
import Popen
import PIPE
from scapy.all import *


# following 4 functions pulled from phillipsme https://github.com/phillips321/python-portscanner/blob/master/nmap.py

def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "": b += dec2bin(int(q), 8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b


def dec2bin(n, d=None):
    s = ""
    while n > 0:
        if n & 1:
            s = "1" + s
        else:
            s = "0" + s
        n >>= 1
    if d is not None:
        while len(s) < d: s = "0" + s
    if s == "": s = "0"
    return s


def bin2ip(b):
    ip = ""
    for i in range(0, len(b), 8):
        ip += str(int(b[i:i + 8], 2)) + "."
    return ip[:-1]


def returnCIDR(c):
    parts = c.split("/")
    print(parts)
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips = []
    if subnet == 32:
        return bin2ip(baseIP)
    else:
        ipPrefix = baseIP[:-(32 - subnet)]
        print(ipPrefix)
        for i in range(2 ** (32 - subnet)): ips.append(bin2ip(ipPrefix + dec2bin(i, (32 - subnet))))
        return ips


# Following two functions came from timmoffett https://github.com/timmoffett/port-scanner with minor adjustments

def udp_scan(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        port = int(port)
        try:
            s.sendto('ping', (host, port))
            re, svr = s.recvfrom(255)
            print("{}/tcp is open".format(port))
        except Exception as e:
            try:
                errno, errtxt = e
            except ValueError:
                output.append('{}/tcp  open'.format(port))
                print('{}/tcp  open'.format(port))
        s.close()
    except:
        pass


def tcp_scan(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        try:
            s.connect((host, port))
            s.close()

            output.append('{}/tcp  open'.format(port))
            print('{}/tcp  open'.format(port))
        except Exception:
            pass
    except:
        pass


# ping function (help from stackoverflow)

def ping(address):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', address]
        response = subprocess.call(command) == 0

        # check the response
        if response == 0:
            output.append('response from', address)
            print('response from', address)
        else:
            output.append('no response from', address)
            print('no response from', address)
    except:
        pass


# traceroute function (help from stackoverflow)

def tr(address):
    try:
        tr = subprocess.Popen(['tracert', address])
        tr.wait()
        output.append(tr.poll())
        print(tr.poll())
    except:
        try:
            for i in range(1, 30):
                p = IP(dst=address, ttl=i) / UDP(dport=33434)
                reply = sr1(pkt, verbose=0)
                if reply is None:
                    break
                else:
                    output.append('hop {}: {}'.format(i, address))
                    print('hop {}: {}'.format(i, address))

                # found end of line
                if reply.type == 3:
                    break
        except:
            pass


def main():
    # loop through all hosts
    for host in hosts:
        # use TCP structure
        if tcp:
            # check for which ports
            if ports:
                # loop through all ports
                for port in ports:
                    tcp_scan(host, port)
            else:
                print('specifiy port or ports')

        # use UDP structure
        if udp:
            if ports:
                # loop through all ports
                for port in ports:
                    udp_scan(host, port)
            else:
                print('specify port or ports')

        # ping host
        if ping:
            ping(address)

        # run traceroute to host
        if traceroute:
            tr(address)



if __name__ == "__main__":

    # initialize variables used to hold user input
    hosts = []
    ports = []
    ping = False
    udp = False
    tcp = False
    tr = False
    timeout = 3
    output = ""

    # pull arguments from command line
    parser = argparse.ArgumentParser()

    parser.add_argument('-TH', '--target', nargs='+', help="Sets target host's IP. Can receive a single IP, multiple IP's separated by spaces, or range of IP addresses. -TH or -f needs to be set")
    parser.add_argument('-f', '--file', help="Reads target host's IPs from a file (one IP per line)")
    parser.add_argument('-p', '--ports', nargs='+', help="Sets what ports to scan. Can take individual port or range of ports. Syntax '-p 22' or '-p 1-1000'")
    parser.add_argument('-T', '--tcp', action='store_true', help="Port scan using TCP packets/ports. This is the default scan")
    parser.add_argument('-U', '--udp', action='store_true', help="Port scan using UDP packets/ports")
    parser.add_argument('-P', '--ping', action='store_true', help="Runs Ping sweep on target host")
    parser.add_argument('-tr', '--traceroute', action='store_true', help="Runs traceroute to target host")
    args = parser.parse_args()
    timeout = args.timeout

    # changes scan to UDP is specified
    udp = args.udp

    # set Host IP's
    try:
        if args.target:
            if '/' in args.target[0]:
                hosts = returnCIDR(args.target[0])
            elif len(args.target) == 1:
                hosts = args.target
            else:
                hosts += list(set(args.target))
        else:
            with open(args.file) as f:
                hosts = f.readlines()

        hosts = [x.strip() for x in hosts]
    except:
        print('must specify at least one target host')
        quit()

    # set ports
    ports = []
    if args.ports:
        if '-' in args.ports[0]:
            ps, pe = args.ports[0].split('-')
            ports = range(int(ps), int(pe) + 1)
        elif len(args.ports) > 1:
            ports += list(set(args.ports))
        elif len(args.ports) == 1:
            ports = list(set(args.ports))
        else:
            pass
    else:
        pass

    if args.udp or args.ping:
        ping = args.ping
        tcp = args.tcp
        tr = args.traceroute
    elif args.traceroute:
        tr = args.traceroute
        tcp = args.tcp
    else:
        tcp = True

    main()