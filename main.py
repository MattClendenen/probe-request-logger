from scapy.all import sniff
import getopt, sys
import argparse

# small comment to satisfy git?

# the harder manual way

# argsList = sys.argv[1:]
# unixOptions = "hi:v"
# gnuOptions = ["help", "isolate=", "verbose"]

# try:
#     arguments, values = getopt.getopt(argsList, unixOptions, gnuOptions)
# except getopt.error as err:
#     # output error, and return with an error code
#     print (str(err))
#     sys.exit(2)

# print(arguments)
# print(arguments[0])
# print(values)
# print(values[0])

# probably the better way
parser = argparse.ArgumentParser()
parser.add_argument('--isolate', help='isolated mac address to track')
args = parser.parse_args()


def pkt_callback(pkt):
    # print(type(pkt))
    if pkt.type == 0 and pkt.subtype == 4 and pkt.addr2 == args.isolate:
        print(pkt.addr2)
        print("\n")


def main():
    sniff(iface='wlan1mon', prn=pkt_callback)
    
if __name__ == '__main__':
    main()