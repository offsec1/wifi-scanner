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

        stats = p[Dot11Beacon].network_stats()
        crypto = stats.get("crypto")
        channel = get_channel_from_frequency(p[RadioTap].Channel)
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, "N/A")

    # scan wifi clients via sniffing the probe requests
    if p.haslayer(Dot11ProbeReq):
        bssid = p[Dot11].addr2

        try:
            dbm_signal = p.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        channel = get_channel_from_frequency(p[RadioTap].Channel)
        ssid = p.info.decode('UTF-8')

        if ssid == "":
            ssid = "[BROADCAST]"

        networks.loc[bssid] = ("[CLIENT DEVICE]", dbm_signal, channel, "N/A", ssid)


def get_channel_from_frequency(frequency):
    base = 2407              # 2.4Ghz
    if frequency//1000 == 5:
        base = 5000          # 5Ghz
    # 2.4 and 5Ghz channels increment by 5
    return (frequency-base)//5


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
