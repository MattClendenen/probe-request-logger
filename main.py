from scapy.all import sniff, RadioTap
import getopt, sys
import argparse
# from probe_request import ProbeRequest

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='targeted mac address to track')
parser.add_argument('-i', '--iface', help='wireless interface to listen with')
args = parser.parse_args()


def pkt_callback(pkt):
    # # print(type(pkt))
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
        print(pkt.addr2)
        print("\n")
        radiotap = pkt.getlayer(RadioTap)
        rssi = radiotap.dBm_AntSignal
        print(rssi)
        # print("\n")


def main():
    sniff(iface=args.iface, prn=pkt_callback)
    
if __name__ == '__main__':
    main()