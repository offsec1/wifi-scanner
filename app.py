from scapy.all import *
from threading import Thread
import pandas
import time
import os

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)


def callback(packet):
    # scan wifi AP's
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

    # TODO: we need to figure out as many information as possible about the client devices
    if packet.haslayer(Dot11ProbeReq):
        mac = packet[Dot11].addr2

        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        something = packet.info
        networks.loc[mac] = ("CLIENT DEVICE", dbm_signal, something, "test")


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
