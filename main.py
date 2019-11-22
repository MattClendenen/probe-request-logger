from scapy.all import sniff, RadioTap
import getopt, sys
import argparse
from probe_request import ProbeRequest
import json
import time
import logging
import os

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='targeted mac address to track')
parser.add_argument('-i', '--iface', help='wireless interface to listen with')
args = parser.parse_args()


#TODO do some exception catching
if (args.iface is None):
    sys.exit('ERROR: You must provide an interface!')

def pkt_callback(pkt):
    # management frames
    # probe requests
    # if target is set, match the source address
    # else all source addresses
    if pkt.type == 0 and pkt.subtype == 4 and ((args.target is not None and pkt.addr2 == args.target) or args.target is None):
        probe_request = ProbeRequest(pkt.addr2, pkt.addr1, pkt.addr3, pkt.getlayer(RadioTap).dBm_AntSignal, time.time())
        logging.info(json.dumps(probe_request.__dict__))
        # print(probe_request)
        print(json.dumps(probe_request.__dict__))

def main():

    print("start the show")
    batch_path = 'log/' + str(time.time())
    os.mkdir(batch_path)
    curr_logfile_name = str(time.time()) + '.json'
    curr_logfile_path = batch_path + '/' + curr_logfile_name
    logging.basicConfig(format='%(message)s', filename=curr_logfile_path, level=logging.DEBUG)
    logging.info("start the show")
    sniff(iface=args.iface, prn=pkt_callback)
    print("hello moto")

if __name__ == "__main__":

    main()