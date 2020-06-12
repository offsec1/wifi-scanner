from scapy.all import *
from threading import Thread
import pandas
import time
import os

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Probe_Request"])
networks.set_index("BSSID", inplace=True)


def callback(p):
    # scan wifi AP's
    if p.haslayer(Dot11Beacon):
        bssid = p[Dot11].addr2
        ssid = p[Dot11Elt].info.decode()

        try:
            dbm_signal = p.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        channel = p[RadioTap].Channel
        crypto = p[RadioTap].Crypto
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, "N/A")

    # scan wifi clients via sniffing the probe requests
    if p.haslayer(Dot11ProbeReq):
        bssid = p[Dot11].addr2

        try:
            dbm_signal = p.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        channel = p[RadioTap].Channel
        ssid = p.info

        if ssid == "":
            ssid = "broadcast probe"

        networks.loc[bssid] = ("[CLIENT DEVICE]", dbm_signal, channel, "N/A", ssid)


def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(1)


def change_channels():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(1)


if __name__ == "__main__":
    interface = sys.argv[1]
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    channel_changer = Thread(target=change_channels)
    channel_changer.daemon = True
    channel_changer.start()

    sniff(prn=callback, iface=interface)
