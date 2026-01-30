from scapy.all import *


def generate_and_send():
    packets = []
    for _ in range(1024):
        pkt = (
            IP(dst="172.16.0.254", src=RandIP())
            / UDP(sport=RandShort(), dport=RandShort())
            / Raw(load="ECMP Hash Testing for b4com" * 64)
        )
        packets.append(pkt)

    send(packets, inter=0.1, iface=None)


if __name__ == "__main__":
    generate_and_send()
