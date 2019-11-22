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


def pkt_callback(pkt):
    # print(pkt[0].show())
    # radiotap = pkt.getlayer(RadioTap)
    # rssi = radiotap.dBm_AntSignal
    # print(rssi)
    # print("\n")
    # record = object()
    # print(record)
    # print(args.iface)
    if pkt.type == 0 and pkt.subtype == 4 and pkt.addr2 == args.target:
        # pkt_record = object()
        # pkt_record.src = pkt.addr2
        # pkt_record.rssi = pkt.getlayer(RadioTap).dBm_AntSignal
        # print(pkt_record)
        probe_request = ProbeRequest(pkt.addr2, pkt.addr1, pkt.addr3, pkt.getlayer(RadioTap).dBm_AntSignal, time.time())
        logging.info(json.dumps(probe_request.__dict__))
        # print(probe_request)
        print(json.dumps(probe_request.__dict__))
        # print("\n")
        # radiotap = pkt.getlayer(RadioTap)
        # rssi = radiotap.dBm_AntSignal
        # print(rssi)
        # print("\n")


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
