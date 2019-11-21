from scapy.all import sniff, RadioTap
import getopt, sys
import argparse
from probe_request import ProbeRequest
import json
import time

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='targeted mac address to track')
#TODO make this required
parser.add_argument('-i', '--iface', help='wireless interface to listen with')
args = parser.parse_args()

#TODO do some exception catching

def pkt_callback(pkt):
    # management frames
    # probe requests
    # if target is set, match the source address
    # else all source addresses
    if pkt.type == 0 and pkt.subtype == 4 and ((args.target is not None and pkt.addr2 == args.target) or args.target is None):
        probe_request = ProbeRequest(pkt.addr2, pkt.addr1, pkt.addr3, pkt.getlayer(RadioTap).dBm_AntSignal, time.time())
        print(json.dumps(probe_request.__dict__))

def main():
    sniff(iface=args.iface, prn=pkt_callback)
    
if __name__ == '__main__':
    main()