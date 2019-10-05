

"# Port-Scanner"

This is a port scanner that can handle scanning multiple targets on multiple ports. It can scan both TCP and UDP, along
with doing a ping sweep and and traceroute.


Setup notes:

    use python 2.7
    pip install argparse

usage: scanner.py [-h] [-TH TARGET [TARGET ...]] [-f FILE] [-p PORTS [PORTS ...]] [-T] [-U] [-P] [-tr]

optional arguments:
-h, --help show this help message and exit
-TH TARGET [TARGET ...], Sets target host's IP. Can receive a single IP, multiple IP's separated by spaces,
    or range of IP addresses. -TH or -f needs to be set
-f, Reads target host's IPs from a file (one IP per line)
-p PORTS [PORTS ...], Sets what ports to scan. Can take individual port or range of ports. Syntax '-p 22' or '-p 1-1000'
-T, Port scan using TCP packets/ports. This is the default scan
-U, Port scan using UDP packets/ports
-P, Runs Ping sweep on target host
-tr, Runs traceroute to target host
