import scapy.all as sp
import sys
from datetime import datetime

IFACE_NAME = "git"
TIMEOUT = 5
PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4


def run():
    data = {}

    def is_probe(pkt):
        return pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and (
                pkt.haslayer(sp.Dot11FCS) or pkt.haslayer(sp.Dot11))

    def packet_handler(pkt):
        if is_probe(pkt):
            data[pkt.addr2] = {
                "mac": pkt.addr2,
                "SSID": pkt.info.decode("utf-8"),
                "RSSI": pkt.getfieldval("dBm_AntSignal"),
                "last_seen": datetime.utcfromtimestamp(pkt.time).strftime('%H:%M:%S')
            }

    while True:
        try:
            sp.sniff(iface=IFACE_NAME, prn=packet_handler, timeout=TIMEOUT)

            for key in data:
                datum = data[key]
                print("MAC: {} | SSID: {} | RSSI: {} | seen: {}".format(datum["mac"],
                                                                        datum["SSID"],
                                                                        datum["RSSI"],
                                                                        datum["last_seen"]))
            print("------------------")
        except KeyboardInterrupt:
            sys.exit()


if __name__ == '__main__':
    run()
